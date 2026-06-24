from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from typing import Any, Iterable

from .constants import DEFAULT_POSTGRES_TABLE, MISSING_PSYCOPG_MESSAGE
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


class PostgresInventoryWriter:
    def __init__(self, config: ScanConfig) -> None:
        self.dsn = config.postgres_dsn
        self.table = config.postgres_table or DEFAULT_POSTGRES_TABLE
        self.provider = config.provider
        self.organization = config.org
        self.owner_user_id = config.owner_user_id or "anonymous"
        self.owner_user_login = config.owner_user_login or "anonymous"
        self.scan_started_at = datetime.now(timezone.utc)
        self.connection: Any = None

    def __enter__(self) -> "PostgresInventoryWriter":
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
        values = self.row_values(result)
        self.connection.execute(self.upsert_sql(), values)

    def create_schema(self) -> None:
        if self.connection is None:
            raise RuntimeError("PostgresInventoryWriter must be opened before creating schema.")
        table = table_identifier(self.table)
        index_prefix = index_name_prefix(self.table)
        self.connection.execute(
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
                    contributing_developers text,
                    last_updated timestamptz,
                    confidence text,
                    score integer,
                    categories text[] NOT NULL DEFAULT '{{}}',
                    store_lookup_status text,
                    store_validation_passed boolean,
                    store_platforms text,
                    row_data jsonb NOT NULL,
                    detection_evidence jsonb,
                    scan_started_at timestamptz NOT NULL,
                    synced_at timestamptz NOT NULL DEFAULT now(),
                    PRIMARY KEY (provider, organization, project, repo_name, branch_name)
                )
                """
            ).format(table=table)
        )
        self.connection.execute(
            sql.SQL("ALTER TABLE {table} ADD COLUMN IF NOT EXISTS owner_user_id text NOT NULL DEFAULT 'anonymous'").format(
                table=table,
            )
        )
        self.connection.execute(
            sql.SQL("ALTER TABLE {table} ADD COLUMN IF NOT EXISTS owner_user_login text NOT NULL DEFAULT 'anonymous'").format(
                table=table,
            )
        )
        self.connection.execute(
            sql.SQL("CREATE INDEX IF NOT EXISTS {index} ON {table} USING GIN (inventory_types)").format(
                index=sql.Identifier(f"{index_prefix}_inventory_types_idx"),
                table=table,
            )
        )
        self.connection.execute(
            sql.SQL("CREATE INDEX IF NOT EXISTS {index} ON {table} (owner_user_id)").format(
                index=sql.Identifier(f"{index_prefix}_owner_user_id_idx"),
                table=table,
            )
        )
        self.connection.execute(
            sql.SQL("CREATE INDEX IF NOT EXISTS {index} ON {table} USING GIN (categories)").format(
                index=sql.Identifier(f"{index_prefix}_categories_idx"),
                table=table,
            )
        )
        self.connection.execute(
            sql.SQL("CREATE INDEX IF NOT EXISTS {index} ON {table} (last_updated)").format(
                index=sql.Identifier(f"{index_prefix}_last_updated_idx"),
                table=table,
            )
        )

    def upsert_sql(self) -> Any:
        table = table_identifier(self.table)
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
            "provider": self.provider,
            "organization": self.organization,
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
            "contributing_developers": text_value(result.get("contributing_developers")),
            "last_updated": timestamp_value(result.get("last_updated")),
            "confidence": text_value(result.get("confidence")),
            "score": int_value(result.get("score")),
            "categories": semicolon_values(result.get("categories")),
            "store_lookup_status": text_value(result.get("store_lookup_status")),
            "store_validation_passed": bool_value(result.get("store_validation_passed")),
            "store_platforms": text_value(result.get("store_platforms")),
            "row_data": Jsonb(cleaned_result),
            "detection_evidence": Jsonb(evidence),
            "scan_started_at": self.scan_started_at,
        }
        return [values[column] for column in POSTGRES_COLUMNS]


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
    "contributing_developers",
    "last_updated",
    "confidence",
    "score",
    "categories",
    "store_lookup_status",
    "store_validation_passed",
    "store_platforms",
    "row_data",
    "detection_evidence",
    "scan_started_at",
)


def table_identifier(table: str) -> Any:
    if sql is None:
        raise SystemExit(MISSING_PSYCOPG_MESSAGE)
    parts = [part for part in table.split(".") if part]
    if not parts or len(parts) > 2 or any(not SQL_NAME_RE.match(part) for part in parts):
        raise ValueError("PostgreSQL table must be a valid table name or schema-qualified table name.")
    return sql.Identifier(*parts)


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
