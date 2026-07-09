from __future__ import annotations

import csv
import io
import json
import re
import uuid
from datetime import datetime, timezone
from typing import Any

from .constants import DEFAULT_POSTGRES_SCHEMA, DEFAULT_POSTGRES_TABLE, MISSING_PSYCOPG_MESSAGE
from .models import ScanConfig

try:
    import psycopg
    from psycopg import sql
    from psycopg.types.json import Jsonb
except ImportError:
    psycopg = None
    sql = None
    Jsonb = None


CONTROL_CHARACTER_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")
SQL_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

NORMALIZED_TABLES = (
    "scan_runs",
    "repositories",
    "branch_inventory",
    "inventory_types",
    "inventory_categories",
    "branch_contributors",
    "store_listings",
)

EXPORT_COLUMNS = (
    "provider",
    "organization",
    "owner_user_id",
    "owner_user_login",
    "project",
    "repo_name",
    "branch_name",
    "branch_last_updated",
    "branch_age_bucket",
    "web_url",
    "source_url",
    "inventory_name",
    "inventory_version",
    "inventory_types",
    "primary_language",
    "scanner_target",
    "semgrep_target",
    "sonarqube_project_key",
    "sonarqube_project_name",
    "mobile_name",
    "mobile_version",
    "mobile_identifier",
    "mobile_identifier_source",
    "mobile_identifier_status",
    "branch_contributing_developers",
    "contributing_developers",
    "last_updated",
    "confidence",
    "score",
    "categories",
    "store_lookup_status",
    "store_validation_passed",
    "store_platforms",
    "apple_app_store_name",
    "apple_app_store_identifier",
    "apple_app_store_url",
    "apple_app_store_version",
    "apple_app_store_last_updated",
    "apple_app_store_validation_passed",
    "apple_app_store_lookup_status",
    "google_play_name",
    "google_play_identifier",
    "google_play_url",
    "google_play_version",
    "google_play_last_updated",
    "google_play_validation_passed",
    "google_play_lookup_status",
    "scan_started_at",
    "synced_at",
)


class PostgresInventoryWriter:
    def __init__(self, config: ScanConfig) -> None:
        self.dsn = config.postgres_dsn
        self.schema, self.table = schema_table_parts(config.postgres_schema, config.postgres_table or DEFAULT_POSTGRES_TABLE)
        self.provider = config.provider
        self.organization = config.org
        self.owner_user_id = config.owner_user_id or "anonymous"
        self.owner_user_login = config.owner_user_login or "anonymous"
        self.scan_started_at = datetime.now(timezone.utc)
        self.scan_id = uuid.uuid4().hex
        self.connection: Any = None

    def __enter__(self) -> PostgresInventoryWriter:
        if psycopg is None or sql is None or Jsonb is None:
            raise SystemExit(MISSING_PSYCOPG_MESSAGE)
        if not self.dsn:
            raise ValueError("PostgreSQL DSN is required when database sync is enabled.")
        self.connection = psycopg.connect(self.dsn, autocommit=True)
        self.create_schema()
        return self

    def __exit__(self, exc_type: object, exc_value: object, traceback: object) -> None:
        self.close()

    def close(self) -> None:
        if self.connection is not None:
            self.connection.close()
            self.connection = None

    def write_result(self, result: dict[str, Any]) -> None:
        if self.connection is None:
            raise RuntimeError("PostgresInventoryWriter must be opened before writing.")
        self.write_flat_result(result)
        self.write_normalized_result(result)

    def create_schema(self) -> None:
        if self.connection is None:
            raise RuntimeError("PostgresInventoryWriter must be opened before creating schema.")
        create_database_schema(self.connection, self.schema, self.table)

    def write_flat_result(self, result: dict[str, Any]) -> None:
        values = self.row_values(result)
        self.connection.execute(self.upsert_sql(), values)

    def write_normalized_result(self, result: dict[str, Any]) -> None:
        self.upsert_scan_run(result)
        repository_id = self.upsert_repository(result)
        branch_inventory_id = self.upsert_branch_inventory(repository_id, result)
        self.replace_value_set("inventory_types", "inventory_type", branch_inventory_id, semicolon_values(result.get("inventory_types")))
        self.replace_value_set("inventory_categories", "category", branch_inventory_id, semicolon_values(result.get("categories")))
        self.replace_value_set(
            "branch_contributors",
            "developer",
            branch_inventory_id,
            semicolon_values(result.get("branch_contributing_developers") or result.get("contributing_developers")),
        )
        self.replace_store_listings(branch_inventory_id, result)

    def upsert_scan_run(self, result: dict[str, Any]) -> None:
        self.connection.execute(
            sql.SQL(
                """
                INSERT INTO {table} (
                    scan_id,
                    provider,
                    organization,
                    owner_user_id,
                    owner_user_login,
                    started_at,
                    synced_at
                )
                VALUES (%s, %s, %s, %s, %s, %s, now())
                ON CONFLICT (scan_id)
                DO UPDATE SET
                    organization = EXCLUDED.organization,
                    owner_user_login = EXCLUDED.owner_user_login,
                    synced_at = now()
                """
            ).format(table=object_identifier(self.schema, "scan_runs")),
            (
                self.scan_id,
                self.provider,
                text_value(result.get("organization") or self.organization),
                self.owner_user_id,
                self.owner_user_login,
                self.scan_started_at,
            ),
        )

    def upsert_repository(self, result: dict[str, Any]) -> int:
        row = self.connection.execute(
            sql.SQL(
                """
                INSERT INTO {table} (
                    provider,
                    organization,
                    project,
                    repo_name,
                    web_url,
                    source_url,
                    synced_at
                )
                VALUES (%s, %s, %s, %s, %s, %s, now())
                ON CONFLICT (provider, organization, project, repo_name)
                DO UPDATE SET
                    web_url = EXCLUDED.web_url,
                    source_url = EXCLUDED.source_url,
                    synced_at = now()
                RETURNING repository_id
                """
            ).format(table=object_identifier(self.schema, "repositories")),
            (
                text_value(result.get("provider") or self.provider),
                text_value(result.get("organization") or self.organization),
                text_value(result.get("project")),
                text_value(result.get("repo_name")),
                text_value(result.get("web_url")),
                text_value(result.get("source_url")),
            ),
        ).fetchone()
        return int(row[0])

    def upsert_branch_inventory(self, repository_id: int, result: dict[str, Any]) -> int:
        cleaned_result = postgres_json_value(result)
        evidence = json_value(result.get("detection_evidence"))
        row = self.connection.execute(
            sql.SQL(
                """
                INSERT INTO {table} (
                    repository_id,
                    scan_id,
                    owner_user_id,
                    owner_user_login,
                    branch_name,
                    branch_last_updated,
                    branch_age_bucket,
                    inventory_name,
                    inventory_version,
                    primary_language,
                    scanner_target,
                    semgrep_target,
                    sonarqube_project_key,
                    sonarqube_project_name,
                    mobile_name,
                    mobile_version,
                    mobile_identifier,
                    mobile_identifier_source,
                    mobile_identifier_status,
                    last_updated,
                    confidence,
                    score,
                    store_lookup_status,
                    store_validation_passed,
                    store_platforms,
                    row_data,
                    detection_evidence,
                    scan_started_at,
                    synced_at
                )
                VALUES (
                    %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                    %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, now()
                )
                ON CONFLICT (repository_id, branch_name, owner_user_id)
                DO UPDATE SET
                    scan_id = EXCLUDED.scan_id,
                    owner_user_login = EXCLUDED.owner_user_login,
                    branch_last_updated = EXCLUDED.branch_last_updated,
                    branch_age_bucket = EXCLUDED.branch_age_bucket,
                    inventory_name = EXCLUDED.inventory_name,
                    inventory_version = EXCLUDED.inventory_version,
                    primary_language = EXCLUDED.primary_language,
                    scanner_target = EXCLUDED.scanner_target,
                    semgrep_target = EXCLUDED.semgrep_target,
                    sonarqube_project_key = EXCLUDED.sonarqube_project_key,
                    sonarqube_project_name = EXCLUDED.sonarqube_project_name,
                    mobile_name = EXCLUDED.mobile_name,
                    mobile_version = EXCLUDED.mobile_version,
                    mobile_identifier = EXCLUDED.mobile_identifier,
                    mobile_identifier_source = EXCLUDED.mobile_identifier_source,
                    mobile_identifier_status = EXCLUDED.mobile_identifier_status,
                    last_updated = EXCLUDED.last_updated,
                    confidence = EXCLUDED.confidence,
                    score = EXCLUDED.score,
                    store_lookup_status = EXCLUDED.store_lookup_status,
                    store_validation_passed = EXCLUDED.store_validation_passed,
                    store_platforms = EXCLUDED.store_platforms,
                    row_data = EXCLUDED.row_data,
                    detection_evidence = EXCLUDED.detection_evidence,
                    scan_started_at = EXCLUDED.scan_started_at,
                    synced_at = now()
                RETURNING branch_inventory_id
                """
            ).format(table=object_identifier(self.schema, "branch_inventory")),
            (
                repository_id,
                self.scan_id,
                self.owner_user_id,
                self.owner_user_login,
                text_value(result.get("branch_name")),
                timestamp_value(result.get("branch_last_updated")),
                text_value(result.get("branch_age_bucket")),
                text_value(result.get("inventory_name")),
                text_value(result.get("inventory_version")),
                text_value(result.get("primary_language")),
                text_value(result.get("scanner_target")),
                text_value(result.get("semgrep_target")),
                text_value(result.get("sonarqube_project_key")),
                text_value(result.get("sonarqube_project_name")),
                text_value(result.get("mobile_name")),
                text_value(result.get("mobile_version")),
                text_value(result.get("mobile_identifier")),
                text_value(result.get("mobile_identifier_source")),
                text_value(result.get("mobile_identifier_status")),
                timestamp_value(result.get("last_updated")),
                text_value(result.get("confidence")),
                int_value(result.get("score")),
                text_value(result.get("store_lookup_status")),
                bool_value(result.get("store_validation_passed")),
                text_value(result.get("store_platforms")),
                Jsonb(cleaned_result),
                Jsonb(evidence),
                self.scan_started_at,
            ),
        ).fetchone()
        return int(row[0])

    def replace_value_set(self, table_name: str, column_name: str, branch_inventory_id: int, values: list[str]) -> None:
        self.connection.execute(
            sql.SQL("DELETE FROM {table} WHERE branch_inventory_id = %s").format(table=object_identifier(self.schema, table_name)),
            (branch_inventory_id,),
        )
        for value in sorted(set(values)):
            self.connection.execute(
                sql.SQL("INSERT INTO {table} (branch_inventory_id, {column}) VALUES (%s, %s) ON CONFLICT DO NOTHING").format(
                    table=object_identifier(self.schema, table_name),
                    column=sql.Identifier(column_name),
                ),
                (branch_inventory_id, value),
            )

    def replace_store_listings(self, branch_inventory_id: int, result: dict[str, Any]) -> None:
        self.connection.execute(
            sql.SQL("DELETE FROM {table} WHERE branch_inventory_id = %s").format(table=object_identifier(self.schema, "store_listings")),
            (branch_inventory_id,),
        )
        for listing in store_listing_rows(result):
            self.connection.execute(
                sql.SQL(
                    """
                    INSERT INTO {table} (
                        branch_inventory_id,
                        platform,
                        lookup_status,
                        validation_passed,
                        app_name,
                        app_identifier,
                        app_url,
                        app_version,
                        last_updated
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (branch_inventory_id, platform)
                    DO UPDATE SET
                        lookup_status = EXCLUDED.lookup_status,
                        validation_passed = EXCLUDED.validation_passed,
                        app_name = EXCLUDED.app_name,
                        app_identifier = EXCLUDED.app_identifier,
                        app_url = EXCLUDED.app_url,
                        app_version = EXCLUDED.app_version,
                        last_updated = EXCLUDED.last_updated
                    """
                ).format(table=object_identifier(self.schema, "store_listings")),
                (
                    branch_inventory_id,
                    listing["platform"],
                    listing["lookup_status"],
                    listing["validation_passed"],
                    listing["app_name"],
                    listing["app_identifier"],
                    listing["app_url"],
                    listing["app_version"],
                    timestamp_value(listing["last_updated"]),
                ),
            )

    def upsert_sql(self) -> Any:
        table = object_identifier(self.schema, self.table)
        columns = POSTGRES_COLUMNS
        assignments = [
            sql.SQL("{column} = EXCLUDED.{column}").format(column=sql.Identifier(column))
            for column in columns
            if column not in PRIMARY_KEY_COLUMNS
        ]
        assignments.append(sql.SQL("synced_at = now()"))
        return sql.SQL(
            """
            INSERT INTO {table} ({columns})
            VALUES ({placeholders})
            ON CONFLICT (provider, organization, project, repo_name, branch_name)
            DO UPDATE SET {assignments}
            """
        ).format(
            table=table,
            columns=sql.SQL(", ").join(sql.Identifier(column) for column in columns),
            placeholders=sql.SQL(", ").join(sql.Placeholder() for _ in columns),
            assignments=sql.SQL(", ").join(assignments),
        )

    def row_values(self, result: dict[str, Any]) -> list[Any]:
        cleaned_result = postgres_json_value(result)
        evidence = json_value(result.get("detection_evidence"))
        values = {
            "provider": text_value(result.get("provider") or self.provider),
            "organization": text_value(result.get("organization") or self.organization),
            "owner_user_id": text_value(self.owner_user_id),
            "owner_user_login": text_value(self.owner_user_login),
            "project": text_value(result.get("project")),
            "repo_name": text_value(result.get("repo_name")),
            "branch_name": text_value(result.get("branch_name")),
            "branch_last_updated": timestamp_value(result.get("branch_last_updated")),
            "branch_age_bucket": text_value(result.get("branch_age_bucket")),
            "web_url": text_value(result.get("web_url")),
            "source_url": text_value(result.get("source_url")),
            "inventory_name": text_value(result.get("inventory_name")),
            "inventory_version": text_value(result.get("inventory_version")),
            "inventory_types": semicolon_values(result.get("inventory_types")),
            "primary_language": text_value(result.get("primary_language")),
            "scanner_target": text_value(result.get("scanner_target")),
            "semgrep_target": text_value(result.get("semgrep_target")),
            "sonarqube_project_key": text_value(result.get("sonarqube_project_key")),
            "sonarqube_project_name": text_value(result.get("sonarqube_project_name")),
            "mobile_name": text_value(result.get("mobile_name")),
            "mobile_version": text_value(result.get("mobile_version")),
            "mobile_identifier": text_value(result.get("mobile_identifier")),
            "mobile_identifier_source": text_value(result.get("mobile_identifier_source")),
            "mobile_identifier_status": text_value(result.get("mobile_identifier_status")),
            "branch_contributing_developers": text_value(
                result.get("branch_contributing_developers") or result.get("contributing_developers")
            ),
            "contributing_developers": text_value(result.get("contributing_developers")),
            "last_updated": timestamp_value(result.get("last_updated")),
            "confidence": text_value(result.get("confidence")),
            "score": int_value(result.get("score")),
            "categories": semicolon_values(result.get("categories")),
            "store_lookup_status": text_value(result.get("store_lookup_status")),
            "store_validation_passed": bool_value(result.get("store_validation_passed")),
            "store_platforms": text_value(result.get("store_platforms")),
            "apple_app_store_name": text_value(result.get("apple_app_store_name")),
            "apple_app_store_identifier": text_value(result.get("apple_app_store_identifier")),
            "apple_app_store_url": text_value(result.get("apple_app_store_url")),
            "apple_app_store_version": text_value(result.get("apple_app_store_version")),
            "apple_app_store_last_updated": timestamp_value(result.get("apple_app_store_last_updated")),
            "apple_app_store_validation_passed": bool_value(result.get("apple_app_store_validation_passed")),
            "apple_app_store_lookup_status": text_value(result.get("apple_app_store_lookup_status")),
            "google_play_name": text_value(result.get("google_play_name")),
            "google_play_identifier": text_value(result.get("google_play_identifier")),
            "google_play_url": text_value(result.get("google_play_url")),
            "google_play_version": text_value(result.get("google_play_version")),
            "google_play_last_updated": timestamp_value(result.get("google_play_last_updated")),
            "google_play_validation_passed": bool_value(result.get("google_play_validation_passed")),
            "google_play_lookup_status": text_value(result.get("google_play_lookup_status")),
            "row_data": Jsonb(cleaned_result),
            "detection_evidence": Jsonb(evidence),
            "scan_started_at": self.scan_started_at,
        }
        return [values[column] for column in POSTGRES_COLUMNS]


def create_database_schema(connection: Any, schema: str, flat_table: str) -> None:
    valid_schema = sql_name(schema or DEFAULT_POSTGRES_SCHEMA, "PostgreSQL schema")
    valid_table = sql_name(flat_table or DEFAULT_POSTGRES_TABLE, "PostgreSQL table")
    connection.execute(sql.SQL("CREATE SCHEMA IF NOT EXISTS {schema}").format(schema=sql.Identifier(valid_schema)))
    create_flat_table(connection, valid_schema, valid_table)
    create_normalized_tables(connection, valid_schema)
    create_export_view(connection, valid_schema)


def create_flat_table(connection: Any, schema: str, table: str) -> None:
    target = object_identifier(schema, table)
    index_prefix = index_name_prefix(f"{schema}_{table}")
    connection.execute(
        sql.SQL(
            """
            CREATE TABLE IF NOT EXISTS {table} (
                provider text NOT NULL,
                organization text NOT NULL,
                owner_user_id text NOT NULL DEFAULT 'anonymous',
                owner_user_login text NOT NULL DEFAULT 'anonymous',
                project text NOT NULL,
                repo_name text NOT NULL,
                branch_name text NOT NULL,
                branch_last_updated timestamptz,
                branch_age_bucket text,
                web_url text,
                source_url text,
                inventory_name text,
                inventory_version text,
                inventory_types text[] NOT NULL DEFAULT '{{}}',
                primary_language text,
                scanner_target text,
                semgrep_target text,
                sonarqube_project_key text,
                sonarqube_project_name text,
                mobile_name text,
                mobile_version text,
                mobile_identifier text,
                mobile_identifier_source text,
                mobile_identifier_status text,
                branch_contributing_developers text,
                contributing_developers text,
                last_updated timestamptz,
                confidence text,
                score integer,
                categories text[] NOT NULL DEFAULT '{{}}',
                store_lookup_status text,
                store_validation_passed boolean,
                store_platforms text,
                apple_app_store_name text,
                apple_app_store_identifier text,
                apple_app_store_url text,
                apple_app_store_version text,
                apple_app_store_last_updated timestamptz,
                apple_app_store_validation_passed boolean,
                apple_app_store_lookup_status text,
                google_play_name text,
                google_play_identifier text,
                google_play_url text,
                google_play_version text,
                google_play_last_updated timestamptz,
                google_play_validation_passed boolean,
                google_play_lookup_status text,
                row_data jsonb NOT NULL,
                detection_evidence jsonb,
                scan_started_at timestamptz NOT NULL,
                synced_at timestamptz NOT NULL DEFAULT now(),
                PRIMARY KEY (provider, organization, project, repo_name, branch_name)
            )
            """
        ).format(table=target)
    )
    for column, definition in FLAT_TABLE_MIGRATIONS:
        connection.execute(
            sql.SQL("ALTER TABLE {table} ADD COLUMN IF NOT EXISTS {column} {definition}").format(
                table=target,
                column=sql.Identifier(column),
                definition=sql.SQL(definition),
            )
        )
    connection.execute(
        sql.SQL("CREATE INDEX IF NOT EXISTS {index} ON {table} USING GIN (inventory_types)").format(
            index=sql.Identifier(f"{index_prefix}_inventory_types_idx"),
            table=target,
        )
    )
    connection.execute(
        sql.SQL("CREATE INDEX IF NOT EXISTS {index} ON {table} (owner_user_id)").format(
            index=sql.Identifier(f"{index_prefix}_owner_user_id_idx"),
            table=target,
        )
    )
    connection.execute(
        sql.SQL("CREATE INDEX IF NOT EXISTS {index} ON {table} USING GIN (categories)").format(
            index=sql.Identifier(f"{index_prefix}_categories_idx"),
            table=target,
        )
    )
    connection.execute(
        sql.SQL("CREATE INDEX IF NOT EXISTS {index} ON {table} (last_updated)").format(
            index=sql.Identifier(f"{index_prefix}_last_updated_idx"),
            table=target,
        )
    )


def create_normalized_tables(connection: Any, schema: str) -> None:
    connection.execute(
        sql.SQL(
            """
            CREATE TABLE IF NOT EXISTS {table} (
                scan_id text PRIMARY KEY,
                provider text NOT NULL,
                organization text NOT NULL,
                owner_user_id text NOT NULL,
                owner_user_login text NOT NULL,
                started_at timestamptz NOT NULL,
                synced_at timestamptz NOT NULL DEFAULT now()
            )
            """
        ).format(table=object_identifier(schema, "scan_runs"))
    )
    connection.execute(
        sql.SQL(
            """
            CREATE TABLE IF NOT EXISTS {table} (
                repository_id bigserial PRIMARY KEY,
                provider text NOT NULL,
                organization text NOT NULL,
                project text NOT NULL,
                repo_name text NOT NULL,
                web_url text,
                source_url text,
                synced_at timestamptz NOT NULL DEFAULT now(),
                UNIQUE (provider, organization, project, repo_name)
            )
            """
        ).format(table=object_identifier(schema, "repositories"))
    )
    connection.execute(
        sql.SQL(
            """
            CREATE TABLE IF NOT EXISTS {table} (
                branch_inventory_id bigserial PRIMARY KEY,
                repository_id bigint NOT NULL REFERENCES {repositories}(repository_id) ON DELETE CASCADE,
                scan_id text NOT NULL REFERENCES {scan_runs}(scan_id) ON DELETE CASCADE,
                owner_user_id text NOT NULL,
                owner_user_login text NOT NULL,
                branch_name text NOT NULL,
                branch_last_updated timestamptz,
                branch_age_bucket text,
                inventory_name text,
                inventory_version text,
                primary_language text,
                scanner_target text,
                semgrep_target text,
                sonarqube_project_key text,
                sonarqube_project_name text,
                mobile_name text,
                mobile_version text,
                mobile_identifier text,
                mobile_identifier_source text,
                mobile_identifier_status text,
                last_updated timestamptz,
                confidence text,
                score integer,
                store_lookup_status text,
                store_validation_passed boolean,
                store_platforms text,
                row_data jsonb NOT NULL,
                detection_evidence jsonb,
                scan_started_at timestamptz NOT NULL,
                synced_at timestamptz NOT NULL DEFAULT now(),
                UNIQUE (repository_id, branch_name, owner_user_id)
            )
            """
        ).format(
            table=object_identifier(schema, "branch_inventory"),
            repositories=object_identifier(schema, "repositories"),
            scan_runs=object_identifier(schema, "scan_runs"),
        )
    )
    connection.execute(
        sql.SQL(
            """
            CREATE TABLE IF NOT EXISTS {table} (
                branch_inventory_id bigint NOT NULL REFERENCES {branch_inventory}(branch_inventory_id) ON DELETE CASCADE,
                inventory_type text NOT NULL,
                PRIMARY KEY (branch_inventory_id, inventory_type)
            )
            """
        ).format(
            table=object_identifier(schema, "inventory_types"),
            branch_inventory=object_identifier(schema, "branch_inventory"),
        )
    )
    connection.execute(
        sql.SQL(
            """
            CREATE TABLE IF NOT EXISTS {table} (
                branch_inventory_id bigint NOT NULL REFERENCES {branch_inventory}(branch_inventory_id) ON DELETE CASCADE,
                category text NOT NULL,
                PRIMARY KEY (branch_inventory_id, category)
            )
            """
        ).format(
            table=object_identifier(schema, "inventory_categories"),
            branch_inventory=object_identifier(schema, "branch_inventory"),
        )
    )
    connection.execute(
        sql.SQL(
            """
            CREATE TABLE IF NOT EXISTS {table} (
                branch_inventory_id bigint NOT NULL REFERENCES {branch_inventory}(branch_inventory_id) ON DELETE CASCADE,
                developer text NOT NULL,
                PRIMARY KEY (branch_inventory_id, developer)
            )
            """
        ).format(
            table=object_identifier(schema, "branch_contributors"),
            branch_inventory=object_identifier(schema, "branch_inventory"),
        )
    )
    connection.execute(
        sql.SQL(
            """
            CREATE TABLE IF NOT EXISTS {table} (
                branch_inventory_id bigint NOT NULL REFERENCES {branch_inventory}(branch_inventory_id) ON DELETE CASCADE,
                platform text NOT NULL,
                lookup_status text,
                validation_passed boolean,
                app_name text,
                app_identifier text,
                app_url text,
                app_version text,
                last_updated timestamptz,
                PRIMARY KEY (branch_inventory_id, platform)
            )
            """
        ).format(
            table=object_identifier(schema, "store_listings"),
            branch_inventory=object_identifier(schema, "branch_inventory"),
        )
    )
    for table_name, column_name in (
        ("repositories", "provider"),
        ("repositories", "organization"),
        ("branch_inventory", "owner_user_id"),
        ("branch_inventory", "last_updated"),
    ):
        connection.execute(
            sql.SQL("CREATE INDEX IF NOT EXISTS {index} ON {table} ({column})").format(
                index=sql.Identifier(f"{schema}_{table_name}_{column_name}_idx"[:63]),
                table=object_identifier(schema, table_name),
                column=sql.Identifier(column_name),
            )
        )


def create_export_view(connection: Any, schema: str) -> None:
    connection.execute(
        sql.SQL(
            """
            CREATE OR REPLACE VIEW {view} AS
            SELECT
                r.provider,
                r.organization,
                b.owner_user_id,
                b.owner_user_login,
                r.project,
                r.repo_name,
                b.branch_name,
                b.branch_last_updated,
                b.branch_age_bucket,
                r.web_url,
                r.source_url,
                b.inventory_name,
                b.inventory_version,
                COALESCE(types.inventory_types, '') AS inventory_types,
                b.primary_language,
                b.scanner_target,
                b.semgrep_target,
                b.sonarqube_project_key,
                b.sonarqube_project_name,
                b.mobile_name,
                b.mobile_version,
                b.mobile_identifier,
                b.mobile_identifier_source,
                b.mobile_identifier_status,
                COALESCE(contributors.contributing_developers, '') AS branch_contributing_developers,
                COALESCE(contributors.contributing_developers, '') AS contributing_developers,
                b.last_updated,
                b.confidence,
                b.score,
                COALESCE(categories.categories, '') AS categories,
                b.store_lookup_status,
                b.store_validation_passed,
                b.store_platforms,
                apple.app_name AS apple_app_store_name,
                apple.app_identifier AS apple_app_store_identifier,
                apple.app_url AS apple_app_store_url,
                apple.app_version AS apple_app_store_version,
                apple.last_updated AS apple_app_store_last_updated,
                apple.validation_passed AS apple_app_store_validation_passed,
                apple.lookup_status AS apple_app_store_lookup_status,
                google.app_name AS google_play_name,
                google.app_identifier AS google_play_identifier,
                google.app_url AS google_play_url,
                google.app_version AS google_play_version,
                google.last_updated AS google_play_last_updated,
                google.validation_passed AS google_play_validation_passed,
                google.lookup_status AS google_play_lookup_status,
                b.scan_started_at,
                b.synced_at
            FROM {branch_inventory} b
            JOIN {repositories} r ON r.repository_id = b.repository_id
            LEFT JOIN (
                SELECT branch_inventory_id, string_agg(inventory_type, '; ' ORDER BY inventory_type) AS inventory_types
                FROM {inventory_types}
                GROUP BY branch_inventory_id
            ) types ON types.branch_inventory_id = b.branch_inventory_id
            LEFT JOIN (
                SELECT branch_inventory_id, string_agg(category, '; ' ORDER BY category) AS categories
                FROM {inventory_categories}
                GROUP BY branch_inventory_id
            ) categories ON categories.branch_inventory_id = b.branch_inventory_id
            LEFT JOIN (
                SELECT branch_inventory_id, string_agg(developer, '; ' ORDER BY developer) AS contributing_developers
                FROM {branch_contributors}
                GROUP BY branch_inventory_id
            ) contributors ON contributors.branch_inventory_id = b.branch_inventory_id
            LEFT JOIN {store_listings} apple ON apple.branch_inventory_id = b.branch_inventory_id AND apple.platform = 'apple_app_store'
            LEFT JOIN {store_listings} google ON google.branch_inventory_id = b.branch_inventory_id AND google.platform = 'google_play'
            """
        ).format(
            view=object_identifier(schema, "inventory_export"),
            branch_inventory=object_identifier(schema, "branch_inventory"),
            repositories=object_identifier(schema, "repositories"),
            inventory_types=object_identifier(schema, "inventory_types"),
            inventory_categories=object_identifier(schema, "inventory_categories"),
            branch_contributors=object_identifier(schema, "branch_contributors"),
            store_listings=object_identifier(schema, "store_listings"),
        )
    )


def database_status(dsn: str, schema: str = DEFAULT_POSTGRES_SCHEMA, table: str = DEFAULT_POSTGRES_TABLE, owner_user_id: str = "") -> dict[str, Any]:
    if psycopg is None:
        return {"connected": False, "status": "missing_dependency", "message": MISSING_PSYCOPG_MESSAGE}
    if not dsn:
        return {"connected": False, "status": "missing_dsn", "message": "PostgreSQL DSN is required."}
    try:
        resolved_schema, resolved_table = schema_table_parts(schema, table)
        with psycopg.connect(dsn, autocommit=True, connect_timeout=3) as connection:
            create_database_schema(connection, resolved_schema, resolved_table)
            database = connection.execute("SELECT current_database()").fetchone()[0]
            branch_count = normalized_row_count(connection, resolved_schema, owner_user_id)
            flat_count = flat_row_count(connection, resolved_schema, resolved_table, owner_user_id)
            return {
                "connected": True,
                "status": "connected",
                "message": "Connected",
                "database": database,
                "schema": resolved_schema,
                "flatTable": resolved_table,
                "normalizedTables": list(NORMALIZED_TABLES),
                "branchRows": branch_count,
                "flatRows": flat_count,
            }
    except Exception as exc:
        return {"connected": False, "status": "unavailable", "message": postgres_error_message(exc), "detail": str(exc)}


def export_inventory_rows(
    dsn: str,
    schema: str = DEFAULT_POSTGRES_SCHEMA,
    owner_user_id: str = "",
    limit: int = 50000,
) -> list[dict[str, Any]]:
    if psycopg is None:
        raise RuntimeError(MISSING_PSYCOPG_MESSAGE)
    resolved_schema = sql_name(schema or DEFAULT_POSTGRES_SCHEMA, "PostgreSQL schema")
    with psycopg.connect(dsn, autocommit=True, connect_timeout=5) as connection:
        rows = connection.execute(
            sql.SQL(
                """
                SELECT {columns}
                FROM {view}
                WHERE (%s = '' OR owner_user_id = %s)
                ORDER BY organization, project, repo_name, branch_name
                LIMIT %s
                """
            ).format(
                columns=sql.SQL(", ").join(sql.Identifier(column) for column in EXPORT_COLUMNS),
                view=object_identifier(resolved_schema, "inventory_export"),
            ),
            (owner_user_id, owner_user_id, limit),
        )
        columns = [column.name for column in rows.description]
        return [dict(zip(columns, row)) for row in rows.fetchall()]


def export_inventory_csv(
    dsn: str,
    schema: str = DEFAULT_POSTGRES_SCHEMA,
    owner_user_id: str = "",
    limit: int = 50000,
) -> bytes:
    rows = export_inventory_rows(dsn, schema=schema, owner_user_id=owner_user_id, limit=limit)
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=list(EXPORT_COLUMNS), extrasaction="ignore")
    writer.writeheader()
    for row in rows:
        writer.writerow({column: export_cell(row.get(column)) for column in EXPORT_COLUMNS})
    return buffer.getvalue().encode("utf-8")


def export_inventory_json(
    dsn: str,
    schema: str = DEFAULT_POSTGRES_SCHEMA,
    owner_user_id: str = "",
    limit: int = 50000,
) -> bytes:
    rows = export_inventory_rows(dsn, schema=schema, owner_user_id=owner_user_id, limit=limit)
    return json.dumps(rows, default=export_cell, indent=2).encode("utf-8")


def normalized_row_count(connection: Any, schema: str, owner_user_id: str) -> int:
    return int(
        connection.execute(
            sql.SQL("SELECT count(*) FROM {table} WHERE (%s = '' OR owner_user_id = %s)").format(
                table=object_identifier(schema, "branch_inventory")
            ),
            (owner_user_id, owner_user_id),
        ).fetchone()[0]
    )


def flat_row_count(connection: Any, schema: str, table: str, owner_user_id: str) -> int:
    return int(
        connection.execute(
            sql.SQL("SELECT count(*) FROM {table} WHERE (%s = '' OR owner_user_id = %s)").format(
                table=object_identifier(schema, table)
            ),
            (owner_user_id, owner_user_id),
        ).fetchone()[0]
    )


PRIMARY_KEY_COLUMNS = ("provider", "organization", "project", "repo_name", "branch_name")

POSTGRES_COLUMNS = (
    "provider",
    "organization",
    "owner_user_id",
    "owner_user_login",
    "project",
    "repo_name",
    "branch_name",
    "branch_last_updated",
    "branch_age_bucket",
    "web_url",
    "source_url",
    "inventory_name",
    "inventory_version",
    "inventory_types",
    "primary_language",
    "scanner_target",
    "semgrep_target",
    "sonarqube_project_key",
    "sonarqube_project_name",
    "mobile_name",
    "mobile_version",
    "mobile_identifier",
    "mobile_identifier_source",
    "mobile_identifier_status",
    "branch_contributing_developers",
    "contributing_developers",
    "last_updated",
    "confidence",
    "score",
    "categories",
    "store_lookup_status",
    "store_validation_passed",
    "store_platforms",
    "apple_app_store_name",
    "apple_app_store_identifier",
    "apple_app_store_url",
    "apple_app_store_version",
    "apple_app_store_last_updated",
    "apple_app_store_validation_passed",
    "apple_app_store_lookup_status",
    "google_play_name",
    "google_play_identifier",
    "google_play_url",
    "google_play_version",
    "google_play_last_updated",
    "google_play_validation_passed",
    "google_play_lookup_status",
    "row_data",
    "detection_evidence",
    "scan_started_at",
)

FLAT_TABLE_MIGRATIONS = (
    ("owner_user_id", "text NOT NULL DEFAULT 'anonymous'"),
    ("owner_user_login", "text NOT NULL DEFAULT 'anonymous'"),
    ("branch_contributing_developers", "text"),
    ("apple_app_store_name", "text"),
    ("apple_app_store_identifier", "text"),
    ("apple_app_store_url", "text"),
    ("apple_app_store_version", "text"),
    ("apple_app_store_last_updated", "timestamptz"),
    ("apple_app_store_validation_passed", "boolean"),
    ("apple_app_store_lookup_status", "text"),
    ("google_play_name", "text"),
    ("google_play_identifier", "text"),
    ("google_play_url", "text"),
    ("google_play_version", "text"),
    ("google_play_last_updated", "timestamptz"),
    ("google_play_validation_passed", "boolean"),
    ("google_play_lookup_status", "text"),
)


def store_listing_rows(result: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for platform in ("apple_app_store", "google_play"):
        lookup_status = text_value(result.get(f"{platform}_lookup_status"))
        app_name = text_value(result.get(f"{platform}_name"))
        app_identifier = text_value(result.get(f"{platform}_identifier"))
        app_url = text_value(result.get(f"{platform}_url"))
        app_version = text_value(result.get(f"{platform}_version"))
        last_updated = text_value(result.get(f"{platform}_last_updated"))
        validation_passed = bool_value(result.get(f"{platform}_validation_passed"))
        if not any((lookup_status, app_name, app_identifier, app_url, app_version, last_updated, validation_passed is not None)):
            continue
        rows.append(
            {
                "platform": platform,
                "lookup_status": lookup_status,
                "validation_passed": validation_passed,
                "app_name": app_name,
                "app_identifier": app_identifier,
                "app_url": app_url,
                "app_version": app_version,
                "last_updated": last_updated,
            }
        )
    return rows


def schema_table_parts(schema: str, table: str) -> tuple[str, str]:
    table_value = text_value(table) or DEFAULT_POSTGRES_TABLE
    parts = [part for part in table_value.split(".") if part]
    if len(parts) == 2:
        return sql_name(parts[0], "PostgreSQL schema"), sql_name(parts[1], "PostgreSQL table")
    if len(parts) != 1:
        raise ValueError("PostgreSQL table must be a valid table name or schema-qualified table name.")
    return sql_name(schema or DEFAULT_POSTGRES_SCHEMA, "PostgreSQL schema"), sql_name(parts[0], "PostgreSQL table")


def table_identifier(table: str, schema: str = DEFAULT_POSTGRES_SCHEMA) -> Any:
    resolved_schema, resolved_table = schema_table_parts(schema, table)
    return object_identifier(resolved_schema, resolved_table)


def object_identifier(schema: str, name: str) -> Any:
    if sql is None:
        raise SystemExit(MISSING_PSYCOPG_MESSAGE)
    return sql.Identifier(sql_name(schema, "PostgreSQL schema"), sql_name(name, "PostgreSQL object"))


def sql_name(value: str, label: str) -> str:
    text = text_value(value)
    if not text or not SQL_NAME_RE.match(text):
        raise ValueError(f"{label} must use letters, numbers, and underscores and cannot start with a number.")
    return text


def index_name_prefix(table: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_]+", "_", table).strip("_")
    return (cleaned or DEFAULT_POSTGRES_TABLE)[:40]


def text_value(value: Any) -> str:
    if value is None:
        return ""
    return CONTROL_CHARACTER_RE.sub("", str(value))


def semicolon_values(value: Any) -> list[str]:
    return [part.strip() for part in text_value(value).split(";") if part.strip()]


def timestamp_value(value: Any) -> str | None:
    text = text_value(value)
    return text or None


def int_value(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def bool_value(value: Any) -> bool | None:
    text = text_value(value).upper()
    if text == "TRUE":
        return True
    if text == "FALSE":
        return False
    return None


def json_value(value: Any) -> Any:
    if isinstance(value, str):
        try:
            return postgres_json_value(json.loads(value))
        except ValueError:
            return text_value(value)
    return postgres_json_value(value)


def postgres_json_value(value: Any) -> Any:
    if isinstance(value, dict):
        return {text_value(key): postgres_json_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [postgres_json_value(item) for item in value]
    if isinstance(value, str):
        return text_value(value)
    return value


def export_cell(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (datetime,)):
        return value.isoformat()
    if isinstance(value, bool):
        return "TRUE" if value else "FALSE"
    return text_value(value)


def postgres_error_message(error: Exception) -> str:
    detail = str(error).lower()
    if "connection refused" in detail or "could not connect" in detail or "connection failed" in detail:
        return "PostgreSQL is not running or is not reachable on the configured host and port."
    if "password authentication failed" in detail:
        return "PostgreSQL rejected the configured user or password."
    if "does not exist" in detail and "database" in detail:
        return "The configured PostgreSQL database does not exist."
    if "library not loaded" in detail or "dyld" in detail:
        return "The local PostgreSQL installation cannot start because a required library is missing."
    return text_value(error)
