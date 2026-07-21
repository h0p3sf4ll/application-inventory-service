from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import threading
import time
import uuid
from collections.abc import Callable, Iterable
from datetime import datetime, timezone
from typing import Any

from .aspm_postgres import create_aspm_schema
from .constants import (
    DEFAULT_POSTGRES_SCHEMA,
    DEFAULT_POSTGRES_TABLE,
    MISSING_PSYCOPG_MESSAGE,
    STORE_FIELDNAMES,
)
from .domains import normalize_web_endpoint, normalized_confidence
from .inventory_exports import json_cell, rows_to_csv, rows_to_json, rows_to_xlsx
from .inventory_query import InventorySearchCriteria, repository_browse_url
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
SCHEMA_READY_LOCK = threading.Lock()
SCHEMA_READY: set[tuple[str, str, str]] = set()
SCHEMA_VERSION = 4
SCHEMA_VERSION_COMPONENT = "inventory"
MOBILE_ROUTING_FIELDS = ("nowsecure_target", *STORE_FIELDNAMES)

NORMALIZED_TABLES = (
    "schema_versions",
    "scan_runs",
    "repositories",
    "branch_inventory",
    "inventory_types",
    "inventory_categories",
    "branch_contributors",
    "web_domains",
    "web_domain_sources",
    "store_listings",
    "observability_events",
    "aspm_tools",
    "aspm_imports",
    "asset_security_profiles",
    "aspm_findings",
    "aspm_finding_identifiers",
    "aspm_import_findings",
    "aspm_finding_events",
    "aspm_coverage",
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
    "primary_web_domain",
    "web_domains",
    "web_urls",
    "web_domain_status",
    "web_domain_sources",
    "web_domain_evidence",
    "inventory_name",
    "inventory_version",
    "primary_language",
    "scanner_target",
    "semgrep_target",
    "sonarqube_project_key",
    "sonarqube_project_name",
    "branch_contributing_developers",
    "contributing_developers",
    "last_updated",
    "confidence",
    "score",
    "scan_started_at",
    "synced_at",
    "inventory_types",
    "categories",
    "mobile_name",
    "mobile_version",
    "mobile_identifier",
    "mobile_identifier_source",
    "mobile_identifier_status",
    "nowsecure_target",
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
)

SEARCHABLE_EXPORT_COLUMNS = (
    "provider",
    "organization",
    "owner_user_login",
    "project",
    "repo_name",
    "branch_name",
    "inventory_name",
    "inventory_version",
    "inventory_types",
    "primary_language",
    "scanner_target",
    "primary_web_domain",
    "web_domains",
    "web_urls",
    "web_domain_status",
    "web_domain_sources",
    "branch_contributing_developers",
    "confidence",
    "categories",
    "mobile_name",
    "mobile_version",
    "mobile_identifier",
    "nowsecure_target",
    "store_platforms",
    "apple_app_store_name",
    "apple_app_store_identifier",
    "google_play_name",
    "google_play_identifier",
)


class PostgresLogHandler(logging.Handler):
    def __init__(
        self, dsn: str, schema: str = DEFAULT_POSTGRES_SCHEMA, source: str = "service"
    ) -> None:
        super().__init__()
        self.dsn = dsn
        self.schema = sql_name(schema or DEFAULT_POSTGRES_SCHEMA, "PostgreSQL schema")
        self.source = text_value(source) or "service"
        self.connection: Any = None
        self.lock = threading.RLock()
        self.retry_after = 0.0

    def emit(self, record: logging.LogRecord) -> None:
        if (
            psycopg is None
            or sql is None
            or Jsonb is None
            or time.monotonic() < self.retry_after
        ):
            return
        try:
            with self.lock:
                connection = self._open_connection()
                metadata = record.__dict__.get("metadata")
                metadata = metadata if isinstance(metadata, dict) else {}
                connection.execute(
                    sql.SQL(
                        """
                        INSERT INTO {table} (
                            level,
                            logger,
                            source,
                            event_type,
                            message,
                            scan_id,
                            owner_user_id,
                            owner_user_login,
                            provider,
                            organization,
                            duration_ms,
                            status,
                            metadata
                        )
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                        """
                    ).format(
                        table=object_identifier(self.schema, "observability_events")
                    ),
                    (
                        record.levelname,
                        record.name,
                        self.source,
                        text_value(record.__dict__.get("event_type")) or "log",
                        sanitize_observability_message(record.getMessage()),
                        text_value(record.__dict__.get("scan_id"))
                        or text_value(os.getenv("APPLICATION_INVENTORY_SCAN_ID")),
                        text_value(record.__dict__.get("owner_user_id"))
                        or text_value(os.getenv("APPLICATION_INVENTORY_OWNER_USER_ID")),
                        text_value(record.__dict__.get("owner_user_login"))
                        or text_value(
                            os.getenv("APPLICATION_INVENTORY_OWNER_USER_LOGIN")
                        ),
                        text_value(record.__dict__.get("provider"))
                        or text_value(os.getenv("APPLICATION_INVENTORY_PROVIDER")),
                        text_value(record.__dict__.get("organization")),
                        float(record.__dict__["duration_ms"])
                        if record.__dict__.get("duration_ms") is not None
                        else None,
                        text_value(record.__dict__.get("status")),
                        Jsonb(metadata),
                    ),
                )
        except Exception:
            self._close_connection()
            self.retry_after = time.monotonic() + 15

    def close(self) -> None:
        with self.lock:
            self._close_connection()
        super().close()

    def _open_connection(self) -> Any:
        if self.connection is None or self.connection.closed:
            self.connection = psycopg.connect(
                self.dsn, autocommit=True, connect_timeout=3
            )
            create_observability_table(self.connection, self.schema)
        return self.connection

    def _close_connection(self) -> None:
        if self.connection is not None:
            try:
                self.connection.close()
            except Exception:
                pass
            self.connection = None


def sanitize_observability_message(message: str) -> str:
    sanitized = re.sub(
        r"(?i)(postgresql://)[^\s]+", r"\1[redacted]", text_value(message)
    )
    sanitized = re.sub(r"(?i)(bearer\s+)[^\s]+", r"\1[redacted]", sanitized)
    sanitized = re.sub(
        r"(?i)(--(?:pat|ado-org-pat)\s+)[^\s]+", r"\1[redacted]", sanitized
    )
    sanitized = re.sub(r"(?i)(password\s*[=:]\s*)[^\s]+", r"\1[redacted]", sanitized)
    return sanitized[:8000]


class PostgresInventoryWriter:
    def __init__(self, config: ScanConfig) -> None:
        self.dsn = config.postgres_dsn
        self.schema, self.table = schema_table_parts(
            config.postgres_schema, config.postgres_table or DEFAULT_POSTGRES_TABLE
        )
        self.provider = config.provider
        self.organization = config.org
        self.owner_user_id = config.owner_user_id or "anonymous"
        self.owner_user_login = config.owner_user_login or "anonymous"
        self.scan_started_at = datetime.now(timezone.utc)
        self.scan_id = uuid.uuid4().hex
        self.connection: Any = None
        self.lock = threading.RLock()
        self.pending_rows = 0
        self.last_commit_at = time.monotonic()
        self.commit_rows = positive_int_env(
            "APPLICATION_INVENTORY_POSTGRES_COMMIT_ROWS", 50
        )
        self.commit_seconds = positive_float_env(
            "APPLICATION_INVENTORY_POSTGRES_COMMIT_SECONDS", 1.0
        )
        self.scan_run_written = False
        self.flush_error: Exception | None = None
        self.flush_stop = threading.Event()
        self.flush_thread: threading.Thread | None = None

    def __enter__(self) -> PostgresInventoryWriter:
        if psycopg is None or sql is None or Jsonb is None:
            raise SystemExit(MISSING_PSYCOPG_MESSAGE)
        if not self.dsn:
            raise ValueError(
                "PostgreSQL DSN is required when database sync is enabled."
            )
        self.connection = psycopg.connect(self.dsn, autocommit=False)
        self.create_schema()
        self.connection.commit()
        self.flush_thread = threading.Thread(
            target=self._flush_loop,
            name=f"postgres-flush-{self.scan_id[:8]}",
            daemon=True,
        )
        self.flush_thread.start()
        return self

    def __exit__(self, exc_type: object, exc_value: object, traceback: object) -> None:
        self.close(commit=exc_type is None)

    def close(self, commit: bool = True) -> None:
        self.flush_stop.set()
        if (
            self.flush_thread is not None
            and self.flush_thread is not threading.current_thread()
        ):
            self.flush_thread.join(timeout=max(2.0, self.commit_seconds * 2))
        with self.lock:
            if self.connection is not None:
                if commit and self.flush_error is None:
                    self.prune_unreferenced_scan_runs()
                    self.connection.commit()
                else:
                    self.connection.rollback()
                self.connection.close()
                self.connection = None
        if commit and self.flush_error is not None:
            raise RuntimeError(
                "PostgreSQL streaming commit failed."
            ) from self.flush_error

    def write_result(self, result: dict[str, Any]) -> None:
        with self.lock:
            if self.connection is None:
                raise RuntimeError(
                    "PostgresInventoryWriter must be opened before writing."
                )
            if self.flush_error is not None:
                raise RuntimeError(
                    "PostgreSQL streaming commit failed."
                ) from self.flush_error
            try:
                self.write_flat_result(result)
                self.write_normalized_result(result)
                self.pending_rows += 1
                now = time.monotonic()
                if (
                    self.pending_rows >= self.commit_rows
                    or now - self.last_commit_at >= self.commit_seconds
                ):
                    self._commit_pending()
            except Exception:
                self.connection.rollback()
                self.pending_rows = 0
                self.last_commit_at = time.monotonic()
                self.scan_run_written = False
                raise

    def _commit_pending(self) -> None:
        if self.connection is None or self.pending_rows <= 0:
            return
        self.connection.commit()
        self.pending_rows = 0
        self.last_commit_at = time.monotonic()

    def _flush_loop(self) -> None:
        while not self.flush_stop.wait(self.commit_seconds):
            with self.lock:
                if self.connection is None or self.pending_rows <= 0:
                    continue
                try:
                    self._commit_pending()
                except Exception as exc:
                    self.connection.rollback()
                    self.pending_rows = 0
                    self.flush_error = exc
                    self.flush_stop.set()
                    return

    def create_schema(self) -> None:
        if self.connection is None:
            raise RuntimeError(
                "PostgresInventoryWriter must be opened before creating schema."
            )
        ensure_database_schema(self.connection, self.dsn, self.schema, self.table)

    def write_flat_result(self, result: dict[str, Any]) -> None:
        values = self.row_values(result)
        self.connection.execute(self.upsert_sql(), values)

    def write_normalized_result(self, result: dict[str, Any]) -> None:
        if not self.scan_run_written:
            self.upsert_scan_run(result)
            self.scan_run_written = True
        repository_id = self.upsert_repository(result)
        branch_inventory_id = self.upsert_branch_inventory(repository_id, result)
        self.replace_value_set(
            "inventory_types",
            "inventory_type",
            branch_inventory_id,
            semicolon_values(result.get("inventory_types")),
        )
        self.replace_value_set(
            "inventory_categories",
            "category",
            branch_inventory_id,
            semicolon_values(result.get("categories")),
        )
        self.replace_value_set(
            "branch_contributors",
            "developer",
            branch_inventory_id,
            semicolon_values(
                result.get("branch_contributing_developers")
                or result.get("contributing_developers")
            ),
        )
        self.replace_web_domains(branch_inventory_id, result)
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
                    owner_user_id,
                    owner_user_login,
                    provider,
                    organization,
                    project,
                    repo_name,
                    web_url,
                    source_url,
                    synced_at
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, now())
                ON CONFLICT (owner_user_id, provider, organization, project, repo_name)
                DO UPDATE SET
                    owner_user_login = EXCLUDED.owner_user_login,
                    web_url = EXCLUDED.web_url,
                    source_url = EXCLUDED.source_url,
                    synced_at = now()
                RETURNING repository_id
                """
            ).format(table=object_identifier(self.schema, "repositories")),
            (
                self.owner_user_id,
                self.owner_user_login,
                text_value(result.get("provider") or self.provider),
                text_value(result.get("organization") or self.organization),
                text_value(result.get("project")),
                text_value(result.get("repo_name")),
                text_value(result.get("web_url")),
                text_value(result.get("source_url")),
            ),
        ).fetchone()
        return int(row[0])

    def upsert_branch_inventory(
        self, repository_id: int, result: dict[str, Any]
    ) -> int:
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
                    nowsecure_target,
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
                    search_document,
                    scan_started_at,
                    synced_at
                )
                VALUES (
                    %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                    %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, now()
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
                    nowsecure_target = EXCLUDED.nowsecure_target,
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
                    search_document = EXCLUDED.search_document,
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
                text_value(result.get("nowsecure_target")),
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
                inventory_search_document(result, self.owner_user_login),
                self.scan_started_at,
            ),
        ).fetchone()
        return int(row[0])

    def replace_value_set(
        self,
        table_name: str,
        column_name: str,
        branch_inventory_id: int,
        values: list[str],
    ) -> None:
        unique_values = sorted(set(values))
        self.connection.execute(
            sql.SQL(
                "DELETE FROM {table} WHERE branch_inventory_id = %s AND NOT ({column} = ANY(%s::text[]))"
            ).format(
                table=object_identifier(self.schema, table_name),
                column=sql.Identifier(column_name),
            ),
            (branch_inventory_id, unique_values),
        )
        if unique_values:
            self.connection.execute(
                sql.SQL(
                    "INSERT INTO {table} (branch_inventory_id, {column}) "
                    "SELECT %s, value FROM unnest(%s::text[]) AS value ON CONFLICT DO NOTHING"
                ).format(
                    table=object_identifier(self.schema, table_name),
                    column=sql.Identifier(column_name),
                ),
                (branch_inventory_id, unique_values),
            )

    def replace_store_listings(
        self, branch_inventory_id: int, result: dict[str, Any]
    ) -> None:
        listings = store_listing_rows(result)
        platforms = [listing["platform"] for listing in listings]
        self.connection.execute(
            sql.SQL(
                "DELETE FROM {table} WHERE branch_inventory_id = %s AND NOT (platform = ANY(%s::text[]))"
            ).format(table=object_identifier(self.schema, "store_listings")),
            (branch_inventory_id, platforms),
        )
        for listing in listings:
            self.connection.execute(
                sql.SQL(
                    """
                    INSERT INTO {table} AS current_listing (
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
                    WHERE (
                        current_listing.lookup_status,
                        current_listing.validation_passed,
                        current_listing.app_name,
                        current_listing.app_identifier,
                        current_listing.app_url,
                        current_listing.app_version,
                        current_listing.last_updated
                    ) IS DISTINCT FROM (
                        EXCLUDED.lookup_status,
                        EXCLUDED.validation_passed,
                        EXCLUDED.app_name,
                        EXCLUDED.app_identifier,
                        EXCLUDED.app_url,
                        EXCLUDED.app_version,
                        EXCLUDED.last_updated
                    )
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

    def replace_web_domains(
        self, branch_inventory_id: int, result: dict[str, Any]
    ) -> None:
        domains = web_domain_rows(result)
        domain_names = [domain["domain"] for domain in domains]
        existing = {
            row[1]: int(row[0])
            for row in self.connection.execute(
                sql.SQL(
                    "SELECT web_domain_id, domain FROM {table} WHERE branch_inventory_id = %s"
                ).format(table=object_identifier(self.schema, "web_domains")),
                (branch_inventory_id,),
            ).fetchall()
        }
        self.connection.execute(
            sql.SQL(
                "DELETE FROM {table} WHERE branch_inventory_id = %s AND NOT (domain = ANY(%s::text[]))"
            ).format(table=object_identifier(self.schema, "web_domains")),
            (branch_inventory_id, domain_names),
        )
        for domain in domains:
            web_domain_id = existing.get(domain["domain"])
            if web_domain_id is None:
                web_domain_id = int(
                    self.connection.execute(
                        sql.SQL(
                            """
                            INSERT INTO {table} (
                                branch_inventory_id,
                                domain,
                                url,
                                confidence,
                                environment,
                                is_primary
                            )
                            VALUES (%s, %s, %s, %s, %s, %s)
                            RETURNING web_domain_id
                            """
                        ).format(table=object_identifier(self.schema, "web_domains")),
                        (
                            branch_inventory_id,
                            domain["domain"],
                            domain["url"],
                            domain["confidence"],
                            domain["environment"],
                            domain["is_primary"],
                        ),
                    ).fetchone()[0]
                )
            else:
                self.connection.execute(
                    sql.SQL(
                        """
                        UPDATE {table}
                        SET url = %s,
                            confidence = %s,
                            environment = %s,
                            is_primary = %s
                        WHERE web_domain_id = %s
                          AND (url, confidence, environment, is_primary)
                              IS DISTINCT FROM (%s, %s, %s, %s)
                        """
                    ).format(table=object_identifier(self.schema, "web_domains")),
                    (
                        domain["url"],
                        domain["confidence"],
                        domain["environment"],
                        domain["is_primary"],
                        web_domain_id,
                        domain["url"],
                        domain["confidence"],
                        domain["environment"],
                        domain["is_primary"],
                    ),
                )
            self.replace_web_domain_sources(web_domain_id, domain["sources"])

    def replace_web_domain_sources(
        self, web_domain_id: int, sources: list[str]
    ) -> None:
        unique_sources = sorted(set(sources))
        self.connection.execute(
            sql.SQL(
                "DELETE FROM {table} WHERE web_domain_id = %s AND NOT (source = ANY(%s::text[]))"
            ).format(table=object_identifier(self.schema, "web_domain_sources")),
            (web_domain_id, unique_sources),
        )
        if unique_sources:
            self.connection.execute(
                sql.SQL(
                    "INSERT INTO {table} (web_domain_id, source) "
                    "SELECT %s, value FROM unnest(%s::text[]) AS value ON CONFLICT DO NOTHING"
                ).format(table=object_identifier(self.schema, "web_domain_sources")),
                (web_domain_id, unique_sources),
            )

    def prune_unreferenced_scan_runs(self) -> None:
        if self.connection is None:
            return
        self.connection.execute(
            sql.SQL(
                """
                DELETE FROM {scan_runs} scan_run
                WHERE scan_run.owner_user_id = %s
                  AND scan_run.provider = %s
                  AND NOT EXISTS (
                      SELECT 1
                      FROM {branch_inventory} branch
                      WHERE branch.scan_id = scan_run.scan_id
                  )
                """
            ).format(
                scan_runs=object_identifier(self.schema, "scan_runs"),
                branch_inventory=object_identifier(self.schema, "branch_inventory"),
            ),
            (self.owner_user_id, self.provider),
        )

    def upsert_sql(self) -> Any:
        table = object_identifier(self.schema, self.table)
        columns = POSTGRES_COLUMNS
        assignments = [
            sql.SQL("{column} = EXCLUDED.{column}").format(
                column=sql.Identifier(column)
            )
            for column in columns
            if column not in PRIMARY_KEY_COLUMNS
        ]
        assignments.append(sql.SQL("synced_at = now()"))
        return sql.SQL(
            """
            INSERT INTO {table} ({columns})
            VALUES ({placeholders})
            ON CONFLICT (owner_user_id, provider, organization, project, repo_name, branch_name)
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
            "primary_web_domain": text_value(result.get("primary_web_domain")),
            "web_domains": semicolon_values(result.get("web_domains")),
            "web_urls": semicolon_values(result.get("web_urls")),
            "web_domain_status": text_value(result.get("web_domain_status")),
            "web_domain_sources": text_value(result.get("web_domain_sources")),
            "web_domain_evidence": Jsonb(json_value(result.get("web_domain_evidence"))),
            "inventory_name": text_value(result.get("inventory_name")),
            "inventory_version": text_value(result.get("inventory_version")),
            "inventory_types": semicolon_values(result.get("inventory_types")),
            "primary_language": text_value(result.get("primary_language")),
            "scanner_target": text_value(result.get("scanner_target")),
            "semgrep_target": text_value(result.get("semgrep_target")),
            "sonarqube_project_key": text_value(result.get("sonarqube_project_key")),
            "sonarqube_project_name": text_value(result.get("sonarqube_project_name")),
            "nowsecure_target": text_value(result.get("nowsecure_target")),
            "mobile_name": text_value(result.get("mobile_name")),
            "mobile_version": text_value(result.get("mobile_version")),
            "mobile_identifier": text_value(result.get("mobile_identifier")),
            "mobile_identifier_source": text_value(
                result.get("mobile_identifier_source")
            ),
            "mobile_identifier_status": text_value(
                result.get("mobile_identifier_status")
            ),
            "branch_contributing_developers": text_value(
                result.get("branch_contributing_developers")
                or result.get("contributing_developers")
            ),
            "contributing_developers": text_value(
                result.get("contributing_developers")
            ),
            "last_updated": timestamp_value(result.get("last_updated")),
            "confidence": text_value(result.get("confidence")),
            "score": int_value(result.get("score")),
            "categories": semicolon_values(result.get("categories")),
            "store_lookup_status": text_value(result.get("store_lookup_status")),
            "store_validation_passed": bool_value(
                result.get("store_validation_passed")
            ),
            "store_platforms": text_value(result.get("store_platforms")),
            "apple_app_store_name": text_value(result.get("apple_app_store_name")),
            "apple_app_store_identifier": text_value(
                result.get("apple_app_store_identifier")
            ),
            "apple_app_store_url": text_value(result.get("apple_app_store_url")),
            "apple_app_store_version": text_value(
                result.get("apple_app_store_version")
            ),
            "apple_app_store_last_updated": timestamp_value(
                result.get("apple_app_store_last_updated")
            ),
            "apple_app_store_validation_passed": bool_value(
                result.get("apple_app_store_validation_passed")
            ),
            "apple_app_store_lookup_status": text_value(
                result.get("apple_app_store_lookup_status")
            ),
            "google_play_name": text_value(result.get("google_play_name")),
            "google_play_identifier": text_value(result.get("google_play_identifier")),
            "google_play_url": text_value(result.get("google_play_url")),
            "google_play_version": text_value(result.get("google_play_version")),
            "google_play_last_updated": timestamp_value(
                result.get("google_play_last_updated")
            ),
            "google_play_validation_passed": bool_value(
                result.get("google_play_validation_passed")
            ),
            "google_play_lookup_status": text_value(
                result.get("google_play_lookup_status")
            ),
            "row_data": Jsonb(cleaned_result),
            "detection_evidence": Jsonb(evidence),
            "scan_started_at": self.scan_started_at,
        }
        return [values[column] for column in POSTGRES_COLUMNS]


def create_database_schema(connection: Any, schema: str, flat_table: str) -> None:
    valid_schema = sql_name(schema or DEFAULT_POSTGRES_SCHEMA, "PostgreSQL schema")
    valid_table = sql_name(flat_table or DEFAULT_POSTGRES_TABLE, "PostgreSQL table")
    connection.execute(
        sql.SQL("CREATE SCHEMA IF NOT EXISTS {schema}").format(
            schema=sql.Identifier(valid_schema)
        )
    )
    component = f"{SCHEMA_VERSION_COMPONENT}:{valid_table}"
    lock_name = f"application-inventory:{valid_schema}:{valid_table}"
    connection.execute("SELECT pg_advisory_lock(hashtextextended(%s, 0))", (lock_name,))
    try:
        create_schema_version_table(connection, valid_schema)
        current_version = connection.execute(
            sql.SQL("SELECT version FROM {table} WHERE component = %s").format(
                table=object_identifier(valid_schema, "schema_versions")
            ),
            (component,),
        ).fetchone()
        if current_version and int(current_version[0]) >= SCHEMA_VERSION:
            return
        create_flat_table(connection, valid_schema, valid_table)
        create_normalized_tables(connection, valid_schema)
        create_observability_table(connection, valid_schema)
        create_export_view(connection, valid_schema)
        create_aspm_schema(connection, valid_schema)
        connection.execute(
            sql.SQL(
                """
                INSERT INTO {table} (component, version, updated_at)
                VALUES (%s, %s, now())
                ON CONFLICT (component)
                DO UPDATE SET version = EXCLUDED.version, updated_at = now()
                """
            ).format(table=object_identifier(valid_schema, "schema_versions")),
            (component, SCHEMA_VERSION),
        )
    except Exception:
        if not connection.autocommit:
            connection.rollback()
        raise
    finally:
        connection.execute(
            "SELECT pg_advisory_unlock(hashtextextended(%s, 0))", (lock_name,)
        )


def create_schema_version_table(connection: Any, schema: str) -> None:
    connection.execute(
        sql.SQL(
            """
            CREATE TABLE IF NOT EXISTS {table} (
                component text PRIMARY KEY,
                version integer NOT NULL,
                updated_at timestamptz NOT NULL DEFAULT now()
            )
            """
        ).format(table=object_identifier(schema, "schema_versions"))
    )


def ensure_database_schema(
    connection: Any, dsn: str, schema: str, flat_table: str
) -> None:
    valid_schema = sql_name(schema or DEFAULT_POSTGRES_SCHEMA, "PostgreSQL schema")
    valid_table = sql_name(flat_table or DEFAULT_POSTGRES_TABLE, "PostgreSQL table")
    key = (hashlib.sha256(dsn.encode("utf-8")).hexdigest(), valid_schema, valid_table)
    with SCHEMA_READY_LOCK:
        if key in SCHEMA_READY:
            return
        create_database_schema(connection, valid_schema, valid_table)
        if not connection.autocommit:
            connection.commit()
        SCHEMA_READY.add(key)


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
                primary_web_domain text,
                web_domains text[] NOT NULL DEFAULT '{{}}',
                web_urls text[] NOT NULL DEFAULT '{{}}',
                web_domain_status text,
                web_domain_sources text,
                web_domain_evidence jsonb,
                inventory_name text,
                inventory_version text,
                inventory_types text[] NOT NULL DEFAULT '{{}}',
                primary_language text,
                scanner_target text,
                semgrep_target text,
                sonarqube_project_key text,
                sonarqube_project_name text,
                nowsecure_target text,
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
                PRIMARY KEY (owner_user_id, provider, organization, project, repo_name, branch_name)
            )
            """
        ).format(table=target)
    )
    for column, definition in FLAT_TABLE_MIGRATIONS:
        connection.execute(
            sql.SQL(
                "ALTER TABLE {table} ADD COLUMN IF NOT EXISTS {column} {definition}"
            ).format(
                table=target,
                column=sql.Identifier(column),
                definition=sql.SQL(definition),
            )
        )
    migrate_flat_mobile_fields(connection, target)
    ensure_primary_key(
        connection,
        schema,
        table,
        (
            "owner_user_id",
            "provider",
            "organization",
            "project",
            "repo_name",
            "branch_name",
        ),
    )
    connection.execute(
        sql.SQL(
            "CREATE INDEX IF NOT EXISTS {index} ON {table} USING GIN (inventory_types)"
        ).format(
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
        sql.SQL(
            "CREATE INDEX IF NOT EXISTS {index} ON {table} USING GIN (categories)"
        ).format(
            index=sql.Identifier(f"{index_prefix}_categories_idx"),
            table=target,
        )
    )
    connection.execute(
        sql.SQL(
            "CREATE INDEX IF NOT EXISTS {index} ON {table} USING GIN (web_domains)"
        ).format(
            index=sql.Identifier(f"{index_prefix}_web_domains_idx"),
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
                owner_user_id text NOT NULL DEFAULT 'anonymous',
                owner_user_login text NOT NULL DEFAULT 'anonymous',
                provider text NOT NULL,
                organization text NOT NULL,
                project text NOT NULL,
                repo_name text NOT NULL,
                web_url text,
                source_url text,
                synced_at timestamptz NOT NULL DEFAULT now(),
                UNIQUE (owner_user_id, provider, organization, project, repo_name)
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
                nowsecure_target text,
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
                search_document text NOT NULL DEFAULT '',
                search_vector tsvector GENERATED ALWAYS AS (
                    to_tsvector('simple'::regconfig, search_document)
                ) STORED,
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
    branch_inventory = object_identifier(schema, "branch_inventory")
    connection.execute(
        sql.SQL(
            "ALTER TABLE {table} ADD COLUMN IF NOT EXISTS search_document text NOT NULL DEFAULT ''"
        ).format(table=branch_inventory)
    )
    connection.execute(
        sql.SQL(
            "ALTER TABLE {table} ADD COLUMN IF NOT EXISTS nowsecure_target text"
        ).format(table=branch_inventory)
    )
    connection.execute(
        sql.SQL(
            "ALTER TABLE {table} ADD COLUMN IF NOT EXISTS search_vector tsvector "
            "GENERATED ALWAYS AS (to_tsvector('simple'::regconfig, search_document)) STORED"
        ).format(table=branch_inventory)
    )
    connection.execute(
        sql.SQL(
            """
            CREATE TABLE IF NOT EXISTS {table} (
                web_domain_id bigserial PRIMARY KEY,
                branch_inventory_id bigint NOT NULL REFERENCES {branch_inventory}(branch_inventory_id) ON DELETE CASCADE,
                domain text NOT NULL,
                url text,
                confidence text NOT NULL,
                environment text,
                is_primary boolean NOT NULL DEFAULT false,
                UNIQUE (branch_inventory_id, domain)
            )
            """
        ).format(
            table=object_identifier(schema, "web_domains"),
            branch_inventory=object_identifier(schema, "branch_inventory"),
        )
    )
    connection.execute(
        sql.SQL(
            """
            CREATE TABLE IF NOT EXISTS {table} (
                web_domain_id bigint NOT NULL REFERENCES {web_domains}(web_domain_id) ON DELETE CASCADE,
                source text NOT NULL,
                PRIMARY KEY (web_domain_id, source)
            )
            """
        ).format(
            table=object_identifier(schema, "web_domain_sources"),
            web_domains=object_identifier(schema, "web_domains"),
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
    migrate_repository_scope(connection, schema)
    migrate_normalized_mobile_fields(connection, schema)
    connection.execute(
        sql.SQL(
            """
            UPDATE {branch_inventory} branch
            SET search_document = concat_ws(
                ' ',
                repository.provider,
                repository.organization,
                repository.project,
                repository.repo_name,
                branch.owner_user_login,
                branch.branch_name,
                branch.inventory_name,
                branch.inventory_version,
                branch.primary_language,
                branch.mobile_name,
                branch.mobile_version,
                branch.mobile_identifier,
                branch.row_data::text
            )
            FROM {repositories} repository
            WHERE repository.repository_id = branch.repository_id
              AND branch.search_document = ''
            """
        ).format(
            branch_inventory=branch_inventory,
            repositories=object_identifier(schema, "repositories"),
        )
    )
    for table_name, column_name in (
        ("repositories", "owner_user_id"),
        ("repositories", "provider"),
        ("branch_inventory", "owner_user_id"),
        ("branch_inventory", "last_updated"),
        ("web_domains", "branch_inventory_id"),
        ("web_domains", "domain"),
    ):
        connection.execute(
            sql.SQL("CREATE INDEX IF NOT EXISTS {index} ON {table} ({column})").format(
                index=sql.Identifier(f"{schema}_{table_name}_{column_name}_idx"[:63]),
                table=object_identifier(schema, table_name),
                column=sql.Identifier(column_name),
            )
        )
    connection.execute(
        sql.SQL(
            "CREATE INDEX IF NOT EXISTS {index} ON {table} USING GIN (search_vector)"
        ).format(
            index=sql.Identifier(f"{schema}_branch_inventory_search_vector_idx"[:63]),
            table=branch_inventory,
        )
    )
    connection.execute(
        sql.SQL(
            "CREATE INDEX IF NOT EXISTS {index} ON {table} (owner_user_id, last_updated DESC)"
        ).format(
            index=sql.Identifier(f"{schema}_branch_inventory_owner_updated_idx"[:63]),
            table=branch_inventory,
        )
    )
    connection.execute(
        sql.SQL(
            "CREATE INDEX IF NOT EXISTS {index} ON {table} (owner_user_id, lower(primary_language))"
        ).format(
            index=sql.Identifier(f"{schema}_branch_inventory_owner_language_idx"[:63]),
            table=branch_inventory,
        )
    )
    for table_name, column_name in (
        ("inventory_types", "inventory_type"),
        ("inventory_categories", "category"),
        ("branch_contributors", "developer"),
        ("web_domains", "confidence"),
        ("store_listings", "validation_passed"),
    ):
        connection.execute(
            sql.SQL(
                "CREATE INDEX IF NOT EXISTS {index} ON {table} ({column}, branch_inventory_id)"
            ).format(
                index=sql.Identifier(
                    f"{schema}_{table_name}_{column_name}_lookup_idx"[:63]
                ),
                table=object_identifier(schema, table_name),
                column=sql.Identifier(column_name),
            )
        )


def migrate_flat_mobile_fields(connection: Any, table: Any) -> None:
    connection.execute(
        sql.SQL(
            """
            UPDATE {table}
            SET nowsecure_target = scanner_target,
                row_data = row_data || jsonb_build_object('nowsecure_target', scanner_target)
            WHERE 'mobile_app' = ANY(inventory_types)
            """
        ).format(table=table)
    )
    connection.execute(
        sql.SQL(
            """
            UPDATE {table}
            SET nowsecure_target = NULL,
                {store_assignments},
                row_data = row_data - %s::text[]
            WHERE NOT ('mobile_app' = ANY(inventory_types))
            """
        ).format(
            table=table,
            store_assignments=null_assignments(STORE_FIELDNAMES),
        ),
        (list(MOBILE_ROUTING_FIELDS),),
    )


def migrate_normalized_mobile_fields(connection: Any, schema: str) -> None:
    branch_inventory = object_identifier(schema, "branch_inventory")
    inventory_types = object_identifier(schema, "inventory_types")
    store_listings = object_identifier(schema, "store_listings")
    connection.execute(
        sql.SQL(
            """
            UPDATE {branch_inventory} branch
            SET nowsecure_target = branch.scanner_target,
                row_data = branch.row_data || jsonb_build_object(
                    'nowsecure_target', branch.scanner_target
                )
            WHERE EXISTS (
                SELECT 1
                FROM {inventory_types} types
                WHERE types.branch_inventory_id = branch.branch_inventory_id
                  AND types.inventory_type = 'mobile_app'
            )
            """
        ).format(
            branch_inventory=branch_inventory,
            inventory_types=inventory_types,
        )
    )
    connection.execute(
        sql.SQL(
            """
            UPDATE {branch_inventory} branch
            SET nowsecure_target = NULL,
                {store_assignments},
                row_data = branch.row_data - %s::text[]
            WHERE NOT EXISTS (
                SELECT 1
                FROM {inventory_types} types
                WHERE types.branch_inventory_id = branch.branch_inventory_id
                  AND types.inventory_type = 'mobile_app'
            )
            """
        ).format(
            branch_inventory=branch_inventory,
            inventory_types=inventory_types,
            store_assignments=null_assignments(STORE_FIELDNAMES[:3]),
        ),
        (list(MOBILE_ROUTING_FIELDS),),
    )
    connection.execute(
        sql.SQL(
            """
            DELETE FROM {store_listings} listing
            WHERE EXISTS (
                SELECT 1
                FROM {branch_inventory} branch
                WHERE branch.branch_inventory_id = listing.branch_inventory_id
                  AND NOT EXISTS (
                      SELECT 1
                      FROM {inventory_types} types
                      WHERE types.branch_inventory_id = branch.branch_inventory_id
                        AND types.inventory_type = 'mobile_app'
                  )
            )
            """
        ).format(
            store_listings=store_listings,
            branch_inventory=branch_inventory,
            inventory_types=inventory_types,
        )
    )


def null_assignments(columns: Iterable[str]) -> Any:
    return sql.SQL(", ").join(
        sql.SQL("{column} = NULL").format(column=sql.Identifier(column))
        for column in columns
    )


def migrate_repository_scope(connection: Any, schema: str) -> None:
    owner_scope_columns = (
        "owner_user_id",
        "provider",
        "organization",
        "project",
        "repo_name",
    )
    if any(
        existing_columns == owner_scope_columns
        for _, _, existing_columns in constraint_columns(
            connection, schema, "repositories", {"u"}
        )
    ):
        return
    repositories = object_identifier(schema, "repositories")
    branch_inventory = object_identifier(schema, "branch_inventory")
    connection.execute(
        sql.SQL(
            "ALTER TABLE {table} ADD COLUMN IF NOT EXISTS owner_user_id text NOT NULL DEFAULT 'anonymous'"
        ).format(table=repositories)
    )
    connection.execute(
        sql.SQL(
            "ALTER TABLE {table} ADD COLUMN IF NOT EXISTS owner_user_login text NOT NULL DEFAULT 'anonymous'"
        ).format(table=repositories)
    )
    drop_unique_constraint(
        connection,
        schema,
        "repositories",
        ("provider", "organization", "project", "repo_name"),
    )
    connection.execute(
        sql.SQL(
            """
            WITH owners AS (
                SELECT
                    repository_id,
                    min(owner_user_id) AS owner_user_id,
                    min(owner_user_login) FILTER (WHERE owner_user_login <> '') AS owner_user_login
                FROM {branch_inventory}
                GROUP BY repository_id
            )
            UPDATE {repositories} repository
            SET
                owner_user_id = owners.owner_user_id,
                owner_user_login = COALESCE(owners.owner_user_login, owners.owner_user_id)
            FROM owners
            WHERE owners.repository_id = repository.repository_id
            """
        ).format(repositories=repositories, branch_inventory=branch_inventory)
    )
    ensure_unique_constraint(
        connection,
        schema,
        "repositories",
        owner_scope_columns,
    )
    connection.execute(
        sql.SQL(
            """
            INSERT INTO {repositories} (
                owner_user_id,
                owner_user_login,
                provider,
                organization,
                project,
                repo_name,
                web_url,
                source_url,
                synced_at
            )
            SELECT DISTINCT
                branch.owner_user_id,
                branch.owner_user_login,
                repository.provider,
                repository.organization,
                repository.project,
                repository.repo_name,
                repository.web_url,
                repository.source_url,
                repository.synced_at
            FROM {branch_inventory} branch
            JOIN {repositories} repository ON repository.repository_id = branch.repository_id
            WHERE branch.owner_user_id <> repository.owner_user_id
            ON CONFLICT (owner_user_id, provider, organization, project, repo_name)
            DO UPDATE SET
                owner_user_login = EXCLUDED.owner_user_login,
                web_url = EXCLUDED.web_url,
                source_url = EXCLUDED.source_url,
                synced_at = EXCLUDED.synced_at
            """
        ).format(repositories=repositories, branch_inventory=branch_inventory)
    )
    connection.execute(
        sql.SQL(
            """
            UPDATE {branch_inventory} branch
            SET repository_id = owned.repository_id
            FROM {repositories} original, {repositories} owned
            WHERE original.repository_id = branch.repository_id
              AND owned.owner_user_id = branch.owner_user_id
              AND owned.provider = original.provider
              AND owned.organization = original.organization
              AND owned.project = original.project
              AND owned.repo_name = original.repo_name
              AND branch.repository_id <> owned.repository_id
            """
        ).format(repositories=repositories, branch_inventory=branch_inventory)
    )


def ensure_primary_key(
    connection: Any, schema: str, table: str, columns: tuple[str, ...]
) -> None:
    constraints = constraint_columns(connection, schema, table, {"p"})
    if any(existing_columns == columns for _, _, existing_columns in constraints):
        return
    for name, _, _ in constraints:
        connection.execute(
            sql.SQL("ALTER TABLE {table} DROP CONSTRAINT {constraint}").format(
                table=object_identifier(schema, table),
                constraint=sql.Identifier(name),
            )
        )
    connection.execute(
        sql.SQL(
            "ALTER TABLE {table} ADD CONSTRAINT {constraint} PRIMARY KEY ({columns})"
        ).format(
            table=object_identifier(schema, table),
            constraint=sql.Identifier(f"{table}_pkey"[:63]),
            columns=sql.SQL(", ").join(sql.Identifier(column) for column in columns),
        )
    )


def ensure_unique_constraint(
    connection: Any, schema: str, table: str, columns: tuple[str, ...]
) -> None:
    constraints = constraint_columns(connection, schema, table, {"u"})
    if any(existing_columns == columns for _, _, existing_columns in constraints):
        return
    connection.execute(
        sql.SQL(
            "ALTER TABLE {table} ADD CONSTRAINT {constraint} UNIQUE ({columns})"
        ).format(
            table=object_identifier(schema, table),
            constraint=sql.Identifier(f"{table}_owner_scope_key"[:63]),
            columns=sql.SQL(", ").join(sql.Identifier(column) for column in columns),
        )
    )


def drop_unique_constraint(
    connection: Any, schema: str, table: str, columns: tuple[str, ...]
) -> None:
    for name, _, existing_columns in constraint_columns(
        connection, schema, table, {"u"}
    ):
        if existing_columns != columns:
            continue
        connection.execute(
            sql.SQL("ALTER TABLE {table} DROP CONSTRAINT {constraint}").format(
                table=object_identifier(schema, table),
                constraint=sql.Identifier(name),
            )
        )


def constraint_columns(
    connection: Any,
    schema: str,
    table: str,
    constraint_types: set[str],
) -> list[tuple[str, str, tuple[str, ...]]]:
    rows = connection.execute(
        """
        SELECT
            constraint_record.conname,
            constraint_record.contype,
            array_agg(attribute.attname ORDER BY key_column.ordinality)
        FROM pg_constraint constraint_record
        CROSS JOIN LATERAL unnest(constraint_record.conkey)
            WITH ORDINALITY AS key_column(attribute_number, ordinality)
        JOIN pg_attribute attribute
          ON attribute.attrelid = constraint_record.conrelid
         AND attribute.attnum = key_column.attribute_number
        WHERE constraint_record.conrelid = to_regclass(%s)
          AND constraint_record.contype::text = ANY(%s::text[])
        GROUP BY constraint_record.conname, constraint_record.contype
        """,
        (f"{schema}.{table}", list(constraint_types)),
    ).fetchall()
    return [(str(name), str(kind), tuple(columns)) for name, kind, columns in rows]


def create_observability_table(connection: Any, schema: str) -> None:
    connection.execute(
        sql.SQL(
            """
            CREATE TABLE IF NOT EXISTS {table} (
                event_id bigserial PRIMARY KEY,
                occurred_at timestamptz NOT NULL DEFAULT now(),
                level text NOT NULL,
                logger text NOT NULL,
                source text NOT NULL DEFAULT 'service',
                event_type text NOT NULL DEFAULT 'log',
                message text NOT NULL,
                scan_id text,
                owner_user_id text,
                owner_user_login text,
                provider text,
                organization text,
                duration_ms double precision,
                status text,
                metadata jsonb NOT NULL DEFAULT '{{}}'::jsonb
            )
            """
        ).format(table=object_identifier(schema, "observability_events"))
    )
    for index_name, columns in (
        ("occurred_at_idx", "occurred_at"),
        ("scan_id_idx", "scan_id"),
        ("owner_user_id_idx", "owner_user_id"),
        ("level_idx", "level"),
    ):
        connection.execute(
            sql.SQL("CREATE INDEX IF NOT EXISTS {index} ON {table} ({column})").format(
                index=sql.Identifier(
                    f"{schema}_observability_events_{index_name}"[:63]
                ),
                table=object_identifier(schema, "observability_events"),
                column=sql.Identifier(columns),
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
                b.synced_at,
                COALESCE(domains.primary_web_domain, '') AS primary_web_domain,
                COALESCE(domains.web_domains, '') AS web_domains,
                COALESCE(domains.web_urls, '') AS web_urls,
                COALESCE(domains.web_domain_status, 'not_detected') AS web_domain_status,
                COALESCE(domains.web_domain_sources, '') AS web_domain_sources,
                COALESCE(domains.web_domain_evidence, '[]'::jsonb) AS web_domain_evidence,
                b.branch_inventory_id,
                b.search_vector,
                b.nowsecure_target
            FROM {branch_inventory} b
            JOIN {repositories} r ON r.repository_id = b.repository_id
            LEFT JOIN LATERAL (
                SELECT string_agg(inventory_type, '; ' ORDER BY inventory_type) AS inventory_types
                FROM {inventory_types}
                WHERE branch_inventory_id = b.branch_inventory_id
            ) types ON true
            LEFT JOIN LATERAL (
                SELECT string_agg(category, '; ' ORDER BY category) AS categories
                FROM {inventory_categories}
                WHERE branch_inventory_id = b.branch_inventory_id
            ) categories ON true
            LEFT JOIN LATERAL (
                SELECT string_agg(developer, '; ' ORDER BY developer) AS contributing_developers
                FROM {branch_contributors}
                WHERE branch_inventory_id = b.branch_inventory_id
            ) contributors ON true
            LEFT JOIN LATERAL (
                SELECT
                    COALESCE(
                        max(d.domain) FILTER (WHERE d.is_primary),
                        (array_agg(d.domain ORDER BY d.is_primary DESC, d.domain))[1]
                    ) AS primary_web_domain,
                    string_agg(d.domain, '; ' ORDER BY d.is_primary DESC, d.domain) AS web_domains,
                    string_agg(d.url, '; ' ORDER BY d.is_primary DESC, d.domain) FILTER (WHERE d.url <> '') AS web_urls,
                    COALESCE(
                        max(d.confidence) FILTER (WHERE d.is_primary),
                        (array_agg(d.confidence ORDER BY d.is_primary DESC, d.domain))[1]
                    ) AS web_domain_status,
                    string_agg(
                        d.domain || ' [' || array_to_string(COALESCE(domain_sources.sources, ARRAY[]::text[]), ', ') || ']',
                        '; ' ORDER BY d.is_primary DESC, d.domain
                    ) AS web_domain_sources,
                    jsonb_agg(
                        jsonb_build_object(
                            'domain', d.domain,
                            'url', d.url,
                            'confidence', d.confidence,
                            'environment', d.environment,
                            'sources', COALESCE(domain_sources.sources, ARRAY[]::text[])
                        ) ORDER BY d.is_primary DESC, d.domain
                    ) AS web_domain_evidence
                FROM {web_domains} d
                LEFT JOIN LATERAL (
                    SELECT array_agg(source ORDER BY source) AS sources
                    FROM {web_domain_sources}
                    WHERE web_domain_id = d.web_domain_id
                ) domain_sources ON true
                WHERE d.branch_inventory_id = b.branch_inventory_id
            ) domains ON true
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
            web_domains=object_identifier(schema, "web_domains"),
            web_domain_sources=object_identifier(schema, "web_domain_sources"),
            store_listings=object_identifier(schema, "store_listings"),
        )
    )


def database_status(
    dsn: str,
    schema: str = DEFAULT_POSTGRES_SCHEMA,
    table: str = DEFAULT_POSTGRES_TABLE,
    owner_user_id: str = "",
) -> dict[str, Any]:
    started = time.perf_counter()
    if psycopg is None:
        return {
            "connected": False,
            "status": "missing_dependency",
            "message": MISSING_PSYCOPG_MESSAGE,
        }
    if not dsn:
        return {
            "connected": False,
            "status": "missing_dsn",
            "message": "PostgreSQL DSN is required.",
        }
    try:
        resolved_schema, resolved_table = schema_table_parts(schema, table)
        with psycopg.connect(dsn, autocommit=True, connect_timeout=3) as connection:
            ensure_database_schema(connection, dsn, resolved_schema, resolved_table)
            database = connection.execute("SELECT current_database()").fetchone()[0]
            branch_count = normalized_row_count(
                connection, resolved_schema, owner_user_id
            )
            flat_count = flat_row_count(
                connection, resolved_schema, resolved_table, owner_user_id
            )
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
                "observabilityRows": observability_row_count(
                    connection, resolved_schema
                ),
                "findingRows": aspm_finding_row_count(
                    connection, resolved_schema, owner_user_id
                ),
                "checkedAt": datetime.now(timezone.utc).isoformat(),
                "latencyMs": round((time.perf_counter() - started) * 1000, 2),
            }
    except Exception as exc:
        return {
            "connected": False,
            "status": "unavailable",
            "message": postgres_error_message(exc),
            "checkedAt": datetime.now(timezone.utc).isoformat(),
            "latencyMs": round((time.perf_counter() - started) * 1000, 2),
        }


def export_inventory_rows(
    dsn: str,
    schema: str = DEFAULT_POSTGRES_SCHEMA,
    owner_user_id: str = "",
    limit: int = 50000,
    query: str = "",
    table: str = DEFAULT_POSTGRES_TABLE,
    filters: dict[str, Any] | InventorySearchCriteria | None = None,
) -> list[dict[str, Any]]:
    return render_inventory_export(
        dsn,
        schema=schema,
        owner_user_id=owner_user_id,
        limit=limit,
        query=query,
        table=table,
        filters=filters,
        renderer=list,
    )


def render_inventory_export(
    dsn: str,
    schema: str,
    owner_user_id: str,
    limit: int,
    query: str,
    table: str,
    filters: dict[str, Any] | InventorySearchCriteria | None,
    renderer: Callable[[Iterable[dict[str, Any]]], Any],
) -> Any:
    if psycopg is None:
        raise RuntimeError(MISSING_PSYCOPG_MESSAGE)
    if not dsn:
        raise ValueError("PostgreSQL DSN is required.")
    resolved_schema = sql_name(schema or DEFAULT_POSTGRES_SCHEMA, "PostgreSQL schema")
    with psycopg.connect(dsn, connect_timeout=5) as connection:
        ensure_database_schema(connection, dsn, resolved_schema, table)
        criteria = resolve_inventory_criteria(query, filters)
        where_clause, parameters = inventory_search_filter(
            owner_user_id,
            criteria=criteria,
            schema=resolved_schema,
        )
        statement = sql.SQL(
            """
            SELECT {columns}
            FROM {view} AS inventory
            WHERE {where_clause}
            ORDER BY {order_by}
            LIMIT %s
            """
        ).format(
            columns=inventory_export_columns(),
            view=object_identifier(resolved_schema, "inventory_export"),
            where_clause=where_clause,
            order_by=inventory_order_by(criteria),
        )
        with connection.cursor(name=f"inventory_export_{uuid.uuid4().hex}") as cursor:
            cursor.itersize = 1000
            cursor.execute(
                statement,
                (*parameters, bounded_limit(limit, 50000, 250000)),
            )
            columns = [column.name for column in cursor.description]
            rows = (dict(zip(columns, row)) for row in cursor)
            return renderer(rows)


def search_inventory(
    dsn: str,
    schema: str = DEFAULT_POSTGRES_SCHEMA,
    owner_user_id: str = "",
    query: str = "",
    limit: int = 100,
    offset: int = 0,
    table: str = DEFAULT_POSTGRES_TABLE,
    filters: dict[str, Any] | InventorySearchCriteria | None = None,
    include_facets: bool = False,
) -> dict[str, Any]:
    if psycopg is None:
        raise RuntimeError(MISSING_PSYCOPG_MESSAGE)
    if not dsn:
        raise ValueError("PostgreSQL DSN is required.")
    resolved_schema = sql_name(schema or DEFAULT_POSTGRES_SCHEMA, "PostgreSQL schema")
    resolved_limit = bounded_limit(limit, 100, 500)
    resolved_offset = non_negative_int(offset)
    criteria = resolve_inventory_criteria(query, filters)
    with psycopg.connect(dsn, autocommit=True, connect_timeout=5) as connection:
        ensure_database_schema(connection, dsn, resolved_schema, table)
        where_clause, parameters = inventory_search_filter(
            owner_user_id,
            criteria=criteria,
            schema=resolved_schema,
        )
        total = int(
            connection.execute(
                sql.SQL(
                    "SELECT count(*) FROM {view} AS inventory WHERE {where_clause}"
                ).format(
                    view=object_identifier(resolved_schema, "inventory_export"),
                    where_clause=where_clause,
                ),
                parameters,
            ).fetchone()[0]
        )
        cursor = connection.execute(
            sql.SQL(
                """
                SELECT {columns}
                FROM {view} AS inventory
                WHERE {where_clause}
                ORDER BY {order_by}
                LIMIT %s OFFSET %s
                """
            ).format(
                columns=inventory_export_columns(include_internal=True),
                view=object_identifier(resolved_schema, "inventory_export"),
                where_clause=where_clause,
                order_by=inventory_order_by(criteria),
            ),
            (*parameters, resolved_limit, resolved_offset),
        )
        columns = [column.name for column in cursor.description]
        rows = []
        for row in cursor.fetchall():
            result = {column: json_cell(value) for column, value in zip(columns, row)}
            result["repository_url"] = repository_browse_url(result)
            rows.append(result)
        facets = (
            {
                "languages": inventory_language_options(
                    connection, resolved_schema, owner_user_id
                )
            }
            if include_facets
            else None
        )
    result = {
        "query": criteria.text,
        "filters": criteria.as_dict(),
        "rows": rows,
        "total": total,
        "limit": resolved_limit,
        "offset": resolved_offset,
    }
    if facets is not None:
        result["facets"] = facets
    return result


def export_inventory_csv(
    dsn: str,
    schema: str = DEFAULT_POSTGRES_SCHEMA,
    owner_user_id: str = "",
    limit: int = 50000,
    query: str = "",
    table: str = DEFAULT_POSTGRES_TABLE,
    filters: dict[str, Any] | InventorySearchCriteria | None = None,
) -> bytes:
    return render_inventory_export(
        dsn,
        schema=schema,
        owner_user_id=owner_user_id,
        limit=limit,
        query=query,
        table=table,
        filters=filters,
        renderer=lambda rows: rows_to_csv(rows, EXPORT_COLUMNS),
    )


def export_inventory_json(
    dsn: str,
    schema: str = DEFAULT_POSTGRES_SCHEMA,
    owner_user_id: str = "",
    limit: int = 50000,
    query: str = "",
    table: str = DEFAULT_POSTGRES_TABLE,
    filters: dict[str, Any] | InventorySearchCriteria | None = None,
) -> bytes:
    return render_inventory_export(
        dsn,
        schema=schema,
        owner_user_id=owner_user_id,
        limit=limit,
        query=query,
        table=table,
        filters=filters,
        renderer=rows_to_json,
    )


def export_inventory_xlsx(
    dsn: str,
    schema: str = DEFAULT_POSTGRES_SCHEMA,
    owner_user_id: str = "",
    limit: int = 50000,
    query: str = "",
    table: str = DEFAULT_POSTGRES_TABLE,
    filters: dict[str, Any] | InventorySearchCriteria | None = None,
) -> bytes:
    return render_inventory_export(
        dsn,
        schema=schema,
        owner_user_id=owner_user_id,
        limit=limit,
        query=query,
        table=table,
        filters=filters,
        renderer=lambda rows: rows_to_xlsx(rows, EXPORT_COLUMNS),
    )


def inventory_search_filter(
    owner_user_id: str,
    query: str = "",
    filters: dict[str, Any] | InventorySearchCriteria | None = None,
    *,
    criteria: InventorySearchCriteria | None = None,
    schema: str = DEFAULT_POSTGRES_SCHEMA,
) -> tuple[Any, list[Any]]:
    resolved = criteria or resolve_inventory_criteria(query, filters)
    clauses = [sql.SQL("(%s = '' OR inventory.owner_user_id = %s)")]
    parameters: list[Any] = [text_value(owner_user_id), text_value(owner_user_id)]
    if resolved.text:
        clauses.append(
            sql.SQL(
                "inventory.search_vector @@ websearch_to_tsquery('simple'::regconfig, %s)"
            )
        )
        parameters.append(resolved.text)
    for expression, value in (
        (
            sql.SQL(
                "COALESCE(inventory.inventory_name, inventory.mobile_name, inventory.repo_name, '')"
            ),
            resolved.application_search,
        ),
        (sql.SQL("COALESCE(inventory.repo_name, '')"), resolved.repository_search),
        (sql.SQL("COALESCE(inventory.branch_name, '')"), resolved.branch_search),
        (
            sql.SQL("COALESCE(inventory.primary_web_domain, '')"),
            resolved.domain_search,
        ),
    ):
        if value:
            clauses.append(
                sql.SQL("{expression} ILIKE %s ESCAPE E'\\\\'").format(
                    expression=expression
                )
            )
            parameters.append(contains_pattern(value))
    for column, values in (
        ("provider", resolved.providers),
        ("organization", resolved.organizations),
        ("project", resolved.projects),
        ("repo_name", resolved.repositories),
        ("confidence", resolved.confidences),
        ("web_domain_status", resolved.domain_statuses),
    ):
        if values:
            clauses.append(
                sql.SQL(
                    "lower(COALESCE(inventory.{column}, '')) = ANY(%s::text[])"
                ).format(column=sql.Identifier(column))
            )
            parameters.append([value.lower() for value in values])
    if resolved.languages:
        clauses.append(sql.SQL("lower(inventory.primary_language) = ANY(%s::text[])"))
        parameters.append([value.lower() for value in resolved.languages])
    if resolved.application_types:
        clauses.append(
            sql.SQL(
                "EXISTS (SELECT 1 FROM {types} AS selected_type "
                "WHERE selected_type.branch_inventory_id = inventory.branch_inventory_id "
                "AND selected_type.inventory_type = ANY(%s::text[]))"
            ).format(
                types=object_identifier(
                    sql_name(schema, "PostgreSQL schema"), "inventory_types"
                )
            )
        )
        parameters.append(list(resolved.application_types))
    updated_at = sql.SQL(
        "COALESCE(inventory.branch_last_updated, inventory.last_updated)"
    )
    if resolved.updated_within_days is not None:
        clauses.append(
            sql.SQL("{updated_at} >= now() - (%s * interval '1 day')").format(
                updated_at=updated_at
            )
        )
        parameters.append(resolved.updated_within_days)
    if resolved.older_than_days is not None:
        clauses.append(
            sql.SQL("{updated_at} < now() - (%s * interval '1 day')").format(
                updated_at=updated_at
            )
        )
        parameters.append(resolved.older_than_days)
    for expression, value in (
        (
            sql.SQL("COALESCE(inventory.primary_web_domain, '') <> ''"),
            resolved.has_domain,
        ),
        (
            sql.SQL("COALESCE(inventory.mobile_identifier, '') <> ''"),
            resolved.has_mobile_identifier,
        ),
    ):
        if value is not None:
            clauses.append(sql.SQL("({expression}) = %s").format(expression=expression))
            parameters.append(value)
    if resolved.store_validation_passed is not None:
        clauses.append(sql.SQL("inventory.store_validation_passed = %s"))
        parameters.append(resolved.store_validation_passed)
        clauses.append(
            sql.SQL(
                "EXISTS (SELECT 1 FROM {types} AS mobile_type "
                "WHERE mobile_type.branch_inventory_id = inventory.branch_inventory_id "
                "AND mobile_type.inventory_type = 'mobile_app')"
            ).format(
                types=object_identifier(
                    sql_name(schema, "PostgreSQL schema"), "inventory_types"
                )
            )
        )
    return sql.SQL(" AND ").join(clauses), parameters


def resolve_inventory_criteria(
    query: str = "",
    filters: dict[str, Any] | InventorySearchCriteria | None = None,
) -> InventorySearchCriteria:
    if isinstance(filters, InventorySearchCriteria):
        return filters.with_text(query) if query else filters
    return InventorySearchCriteria.from_mapping(filters, text=query)


def inventory_export_columns(include_internal: bool = False) -> Any:
    columns = EXPORT_COLUMNS + (("branch_inventory_id",) if include_internal else ())
    return sql.SQL(", ").join(
        sql.SQL("inventory.{column}").format(column=sql.Identifier(column))
        for column in columns
    )


def inventory_order_by(criteria: InventorySearchCriteria) -> Any:
    expressions = {
        "updated": sql.SQL(
            "COALESCE(inventory.branch_last_updated, inventory.last_updated)"
        ),
        "application": sql.SQL(
            "COALESCE(inventory.inventory_name, inventory.mobile_name, inventory.repo_name)"
        ),
        "repository": sql.SQL("inventory.repo_name"),
        "branch": sql.SQL("inventory.branch_name"),
        "domain": sql.SQL("inventory.primary_web_domain"),
        "language": sql.SQL("lower(inventory.primary_language)"),
        "source": sql.SQL("inventory.provider"),
        "types": sql.SQL("inventory.inventory_types"),
        "confidence": sql.SQL(
            "CASE lower(COALESCE(inventory.confidence, '')) "
            "WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END"
        ),
    }
    direction = sql.SQL("ASC") if criteria.sort_direction == "asc" else sql.SQL("DESC")
    return sql.SQL(
        "{primary} {direction} NULLS LAST, inventory.organization, inventory.project, "
        "inventory.repo_name, inventory.branch_name"
    ).format(primary=expressions[criteria.sort_by], direction=direction)


def inventory_language_options(
    connection: Any,
    schema: str,
    owner_user_id: str,
    limit: int = 200,
) -> list[str]:
    rows = connection.execute(
        sql.SQL(
            """
            SELECT min(btrim(primary_language)) AS language
            FROM {table}
            WHERE (%s = '' OR owner_user_id = %s)
              AND nullif(btrim(primary_language), '') IS NOT NULL
            GROUP BY lower(btrim(primary_language))
            ORDER BY lower(btrim(primary_language))
            LIMIT %s
            """
        ).format(table=object_identifier(schema, "branch_inventory")),
        (owner_user_id, owner_user_id, bounded_limit(limit, 200, 500)),
    ).fetchall()
    return [row[0] for row in rows]


def contains_pattern(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%"


def normalized_row_count(connection: Any, schema: str, owner_user_id: str) -> int:
    return int(
        connection.execute(
            sql.SQL(
                "SELECT count(*) FROM {table} WHERE (%s = '' OR owner_user_id = %s)"
            ).format(table=object_identifier(schema, "branch_inventory")),
            (owner_user_id, owner_user_id),
        ).fetchone()[0]
    )


def flat_row_count(connection: Any, schema: str, table: str, owner_user_id: str) -> int:
    return int(
        connection.execute(
            sql.SQL(
                "SELECT count(*) FROM {table} WHERE (%s = '' OR owner_user_id = %s)"
            ).format(table=object_identifier(schema, table)),
            (owner_user_id, owner_user_id),
        ).fetchone()[0]
    )


def observability_row_count(connection: Any, schema: str) -> int:
    return int(
        connection.execute(
            sql.SQL("SELECT count(*) FROM {table}").format(
                table=object_identifier(schema, "observability_events")
            )
        ).fetchone()[0]
    )


def aspm_finding_row_count(connection: Any, schema: str, owner_user_id: str) -> int:
    return int(
        connection.execute(
            sql.SQL(
                "SELECT count(*) FROM {table} WHERE (%s = '' OR owner_user_id = %s)"
            ).format(table=object_identifier(schema, "aspm_findings")),
            (owner_user_id, owner_user_id),
        ).fetchone()[0]
    )


PRIMARY_KEY_COLUMNS = (
    "owner_user_id",
    "provider",
    "organization",
    "project",
    "repo_name",
    "branch_name",
)

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
    "primary_web_domain",
    "web_domains",
    "web_urls",
    "web_domain_status",
    "web_domain_sources",
    "web_domain_evidence",
    "inventory_name",
    "inventory_version",
    "primary_language",
    "scanner_target",
    "semgrep_target",
    "sonarqube_project_key",
    "sonarqube_project_name",
    "nowsecure_target",
    "branch_contributing_developers",
    "contributing_developers",
    "last_updated",
    "confidence",
    "score",
    "row_data",
    "detection_evidence",
    "scan_started_at",
    "inventory_types",
    "categories",
    "mobile_name",
    "mobile_version",
    "mobile_identifier",
    "mobile_identifier_source",
    "mobile_identifier_status",
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
)

FLAT_TABLE_MIGRATIONS = (
    ("owner_user_id", "text NOT NULL DEFAULT 'anonymous'"),
    ("owner_user_login", "text NOT NULL DEFAULT 'anonymous'"),
    ("branch_contributing_developers", "text"),
    ("primary_web_domain", "text"),
    ("web_domains", "text[] NOT NULL DEFAULT '{}'"),
    ("web_urls", "text[] NOT NULL DEFAULT '{}'"),
    ("web_domain_status", "text"),
    ("web_domain_sources", "text"),
    ("web_domain_evidence", "jsonb"),
    ("nowsecure_target", "text"),
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
        if not any(
            (
                lookup_status,
                app_name,
                app_identifier,
                app_url,
                app_version,
                last_updated,
                validation_passed is not None,
            )
        ):
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


def web_domain_rows(result: dict[str, Any]) -> list[dict[str, Any]]:
    evidence = json_value(result.get("web_domain_evidence"))
    evidence_items = evidence if isinstance(evidence, list) else []
    primary_domain = text_value(result.get("primary_web_domain"))
    rows: dict[str, dict[str, Any]] = {}
    for index, item in enumerate(evidence_items):
        if not isinstance(item, dict):
            continue
        confidence = normalized_confidence(item.get("confidence"))
        normalized = normalize_web_endpoint(
            item.get("url") or item.get("domain"), confidence
        )
        if normalized is None:
            continue
        domain, url, confidence = normalized
        raw_sources = item.get("sources")
        if isinstance(raw_sources, (list, tuple, set)):
            sources = sorted(
                {text_value(source) for source in raw_sources if text_value(source)}
            )
        else:
            sources = semicolon_values(raw_sources)
        rows[domain] = {
            "domain": domain,
            "url": url,
            "confidence": confidence,
            "environment": text_value(item.get("environment")),
            "is_primary": domain == primary_domain
            or (not primary_domain and index == 0),
            "sources": sources,
        }
    if not rows:
        for index, value in enumerate(semicolon_values(result.get("web_domains"))):
            normalized = normalize_web_endpoint(value, result.get("web_domain_status"))
            if normalized is None:
                continue
            domain, url, confidence = normalized
            rows[domain] = {
                "domain": domain,
                "url": url,
                "confidence": confidence,
                "environment": "",
                "is_primary": domain == primary_domain
                or (not primary_domain and index == 0),
                "sources": [],
            }
    ordered = sorted(
        rows.values(), key=lambda row: (not row["is_primary"], row["domain"])
    )
    if ordered and not any(row["is_primary"] for row in ordered):
        ordered[0]["is_primary"] = True
    return ordered


def schema_table_parts(schema: str, table: str) -> tuple[str, str]:
    table_value = text_value(table) or DEFAULT_POSTGRES_TABLE
    parts = [part for part in table_value.split(".") if part]
    if len(parts) == 2:
        return sql_name(parts[0], "PostgreSQL schema"), sql_name(
            parts[1], "PostgreSQL table"
        )
    if len(parts) != 1:
        raise ValueError(
            "PostgreSQL table must be a valid table name or schema-qualified table name."
        )
    return sql_name(schema or DEFAULT_POSTGRES_SCHEMA, "PostgreSQL schema"), sql_name(
        parts[0], "PostgreSQL table"
    )


def table_identifier(table: str, schema: str = DEFAULT_POSTGRES_SCHEMA) -> Any:
    resolved_schema, resolved_table = schema_table_parts(schema, table)
    return object_identifier(resolved_schema, resolved_table)


def object_identifier(schema: str, name: str) -> Any:
    if sql is None:
        raise SystemExit(MISSING_PSYCOPG_MESSAGE)
    return sql.Identifier(
        sql_name(schema, "PostgreSQL schema"), sql_name(name, "PostgreSQL object")
    )


def sql_name(value: str, label: str) -> str:
    text = text_value(value)
    if not text or not SQL_NAME_RE.match(text):
        raise ValueError(
            f"{label} must use letters, numbers, and underscores and cannot start with a number."
        )
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
        return {
            text_value(key): postgres_json_value(item) for key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [postgres_json_value(item) for item in value]
    if isinstance(value, str):
        return text_value(value)
    return value


def inventory_search_document(
    result: dict[str, Any], owner_user_login: str = ""
) -> str:
    values: list[str] = [text_value(owner_user_login)]
    for column in SEARCHABLE_EXPORT_COLUMNS:
        value = result.get(column)
        if isinstance(value, (dict, list, tuple)):
            values.append(json.dumps(postgres_json_value(value), sort_keys=True))
        else:
            values.append(text_value(value))
    return " ".join(value for value in values if value)[:65_535]


def normalize_search_query(value: Any) -> str:
    return " ".join(text_value(value).split())[:500]


def search_tokens(value: Any) -> list[str]:
    return normalize_search_query(value).split()[:12]


def bounded_limit(value: Any, default: int, maximum: int) -> int:
    try:
        resolved = int(value)
    except (TypeError, ValueError):
        return default
    return max(1, min(resolved, maximum))


def non_negative_int(value: Any) -> int:
    try:
        resolved = int(value)
    except (TypeError, ValueError):
        return 0
    return max(0, resolved)


def postgres_error_message(error: Exception) -> str:
    detail = str(error).lower()
    if (
        "connection refused" in detail
        or "could not connect" in detail
        or "connection failed" in detail
    ):
        return "PostgreSQL is not running or is not reachable on the configured host and port."
    if "password authentication failed" in detail:
        return "PostgreSQL rejected the configured user or password."
    if "does not exist" in detail and "database" in detail:
        return "The configured PostgreSQL database does not exist."
    if "library not loaded" in detail or "dyld" in detail:
        return "The local PostgreSQL installation cannot start because a required library is missing."
    return text_value(error)


def positive_int_env(name: str, default: int) -> int:
    try:
        value = int(os.getenv(name, ""))
    except ValueError:
        return default
    return value if value > 0 else default


def positive_float_env(name: str, default: float) -> float:
    try:
        value = float(os.getenv(name, ""))
    except ValueError:
        return default
    return value if value > 0 else default
