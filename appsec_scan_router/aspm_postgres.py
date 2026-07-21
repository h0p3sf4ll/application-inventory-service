from __future__ import annotations

import hashlib
import re
import threading
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from .aspm_models import (
    ACTIVE_FINDING_STATUSES,
    FindingDocument,
    FindingInput,
    SourceLocation,
    bounded_text,
    normalize_status,
    utc_datetime,
    validate_transition,
)
from .aspm_risk import AssetRiskContext, RiskEngine
from .inventory_exports import rows_to_csv, rows_to_json, rows_to_xlsx

try:
    import psycopg
    from psycopg import sql
    from psycopg.rows import dict_row
    from psycopg.types.json import Jsonb
except ImportError:
    psycopg = None
    sql = None
    dict_row = None
    Jsonb = None


SQL_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
ASPM_SCHEMA_VERSION = 2
ASPM_SCHEMA_LOCK = threading.Lock()
ASPM_SCHEMA_READY: set[tuple[str, str]] = set()
FINDING_EXPORT_COLUMNS = (
    "finding_id",
    "title",
    "severity",
    "status",
    "risk_score",
    "risk_band",
    "tool_name",
    "tool_type",
    "rule_id",
    "category",
    "cwes",
    "cves",
    "provider",
    "organization",
    "project",
    "repository",
    "branch",
    "application",
    "application_types",
    "primary_web_domain",
    "path",
    "start_line",
    "package_name",
    "package_version",
    "fixed_version",
    "cvss_score",
    "epss_score",
    "exploit_available",
    "assignee",
    "due_at",
    "first_seen",
    "last_seen",
    "scanner_url",
    "remediation",
)


def create_aspm_schema(connection: Any, schema: str) -> None:
    resolved = schema_name(schema)
    connection.execute(
        sql.SQL(
            """
            CREATE TABLE IF NOT EXISTS {tools} (
                tool_id bigserial PRIMARY KEY,
                owner_user_id text NOT NULL,
                tool_key text NOT NULL,
                tool_name text NOT NULL,
                tool_type text NOT NULL DEFAULT 'other',
                enabled boolean NOT NULL DEFAULT true,
                first_seen_at timestamptz NOT NULL DEFAULT now(),
                last_seen_at timestamptz NOT NULL DEFAULT now(),
                metadata jsonb NOT NULL DEFAULT '{{}}'::jsonb,
                UNIQUE (owner_user_id, tool_key)
            );

            CREATE TABLE IF NOT EXISTS {imports} (
                import_id text PRIMARY KEY,
                owner_user_id text NOT NULL,
                tool_id bigint NOT NULL REFERENCES {tools}(tool_id) ON DELETE CASCADE,
                source_format text NOT NULL,
                status text NOT NULL,
                finding_count integer NOT NULL DEFAULT 0,
                inserted_count integer NOT NULL DEFAULT 0,
                updated_count integer NOT NULL DEFAULT 0,
                resolved_count integer NOT NULL DEFAULT 0,
                error_count integer NOT NULL DEFAULT 0,
                error_message text,
                complete_snapshot boolean NOT NULL DEFAULT false,
                metadata jsonb NOT NULL DEFAULT '{{}}'::jsonb,
                started_at timestamptz NOT NULL DEFAULT now(),
                completed_at timestamptz
            );

            CREATE TABLE IF NOT EXISTS {profiles} (
                branch_inventory_id bigint PRIMARY KEY REFERENCES {branches}(branch_inventory_id) ON DELETE CASCADE,
                owner_user_id text NOT NULL,
                criticality text NOT NULL DEFAULT 'medium',
                internet_exposed boolean,
                data_classification text NOT NULL DEFAULT 'internal',
                business_owner text,
                technical_owner text,
                tags text[] NOT NULL DEFAULT '{{}}',
                updated_by text NOT NULL,
                updated_at timestamptz NOT NULL DEFAULT now()
            );

            CREATE TABLE IF NOT EXISTS {findings} (
                finding_id text PRIMARY KEY,
                owner_user_id text NOT NULL,
                tool_id bigint NOT NULL REFERENCES {tools}(tool_id) ON DELETE CASCADE,
                branch_inventory_id bigint REFERENCES {branches}(branch_inventory_id) ON DELETE SET NULL,
                fingerprint text NOT NULL,
                external_id text,
                title text NOT NULL,
                description text,
                rule_id text,
                category text,
                severity text NOT NULL,
                status text NOT NULL DEFAULT 'open',
                confidence text,
                provider text,
                organization text,
                project text,
                repository text,
                branch text,
                path text,
                start_line integer,
                end_line integer,
                scanner_url text,
                remediation text,
                package_name text,
                package_version text,
                fixed_version text,
                cvss_score double precision,
                epss_score double precision,
                exploit_available boolean NOT NULL DEFAULT false,
                risk_score integer NOT NULL,
                risk_band text NOT NULL,
                risk_factors jsonb NOT NULL DEFAULT '[]'::jsonb,
                assignee text,
                due_at timestamptz,
                first_seen timestamptz NOT NULL,
                last_seen timestamptz NOT NULL,
                resolved_at timestamptz,
                raw_data jsonb NOT NULL DEFAULT '{{}}'::jsonb,
                created_at timestamptz NOT NULL DEFAULT now(),
                updated_at timestamptz NOT NULL DEFAULT now(),
                UNIQUE (owner_user_id, tool_id, fingerprint)
            );

            CREATE TABLE IF NOT EXISTS {identifiers} (
                finding_id text NOT NULL REFERENCES {findings}(finding_id) ON DELETE CASCADE,
                identifier_type text NOT NULL,
                identifier text NOT NULL,
                PRIMARY KEY (finding_id, identifier_type, identifier)
            );

            CREATE TABLE IF NOT EXISTS {import_findings} (
                import_id text NOT NULL REFERENCES {imports}(import_id) ON DELETE CASCADE,
                finding_id text NOT NULL REFERENCES {findings}(finding_id) ON DELETE CASCADE,
                PRIMARY KEY (import_id, finding_id)
            );

            CREATE TABLE IF NOT EXISTS {events} (
                event_id bigserial PRIMARY KEY,
                finding_id text NOT NULL REFERENCES {findings}(finding_id) ON DELETE CASCADE,
                owner_user_id text NOT NULL,
                actor text NOT NULL,
                event_type text NOT NULL,
                from_status text,
                to_status text,
                note text,
                metadata jsonb NOT NULL DEFAULT '{{}}'::jsonb,
                created_at timestamptz NOT NULL DEFAULT now()
            );

            CREATE TABLE IF NOT EXISTS {coverage} (
                branch_inventory_id bigint NOT NULL REFERENCES {branches}(branch_inventory_id) ON DELETE CASCADE,
                tool_id bigint NOT NULL REFERENCES {tools}(tool_id) ON DELETE CASCADE,
                owner_user_id text NOT NULL,
                last_import_id text REFERENCES {imports}(import_id) ON DELETE SET NULL,
                last_scan_at timestamptz NOT NULL,
                finding_count integer NOT NULL DEFAULT 0,
                status text NOT NULL DEFAULT 'scanned',
                metadata jsonb NOT NULL DEFAULT '{{}}'::jsonb,
                PRIMARY KEY (branch_inventory_id, tool_id)
            );

            CREATE INDEX IF NOT EXISTS {finding_owner_status_idx}
                ON {findings} (owner_user_id, status, risk_score DESC);
            CREATE INDEX IF NOT EXISTS {finding_owner_severity_idx}
                ON {findings} (owner_user_id, severity, last_seen DESC);
            CREATE INDEX IF NOT EXISTS {finding_asset_idx}
                ON {findings} (branch_inventory_id, status);
            CREATE INDEX IF NOT EXISTS {finding_due_idx}
                ON {findings} (owner_user_id, due_at) WHERE due_at IS NOT NULL;
            CREATE INDEX IF NOT EXISTS {finding_search_idx}
                ON {findings} USING GIN (
                    to_tsvector(
                        'simple'::regconfig,
                        COALESCE(title, '') || ' ' || COALESCE(description, '') || ' ' ||
                        COALESCE(rule_id, '') || ' ' || COALESCE(category, '') || ' ' ||
                        COALESCE(repository, '') || ' ' || COALESCE(path, '') || ' ' ||
                        COALESCE(package_name, '')
                    )
                );
            CREATE INDEX IF NOT EXISTS {coverage_owner_scan_idx}
                ON {coverage} (owner_user_id, last_scan_at DESC);
            CREATE INDEX IF NOT EXISTS {event_finding_idx}
                ON {events} (finding_id, created_at DESC);
            CREATE INDEX IF NOT EXISTS {import_owner_idx}
                ON {imports} (owner_user_id, started_at DESC);

            ALTER TABLE {imports}
                ADD COLUMN IF NOT EXISTS error_message text;
            """
        ).format(
            tools=identifier(resolved, "aspm_tools"),
            imports=identifier(resolved, "aspm_imports"),
            profiles=identifier(resolved, "asset_security_profiles"),
            branches=identifier(resolved, "branch_inventory"),
            findings=identifier(resolved, "aspm_findings"),
            identifiers=identifier(resolved, "aspm_finding_identifiers"),
            import_findings=identifier(resolved, "aspm_import_findings"),
            events=identifier(resolved, "aspm_finding_events"),
            coverage=identifier(resolved, "aspm_coverage"),
            finding_owner_status_idx=sql.Identifier(
                f"{resolved}_aspm_finding_owner_status_idx"[:63]
            ),
            finding_owner_severity_idx=sql.Identifier(
                f"{resolved}_aspm_finding_owner_severity_idx"[:63]
            ),
            finding_asset_idx=sql.Identifier(f"{resolved}_aspm_finding_asset_idx"[:63]),
            finding_due_idx=sql.Identifier(f"{resolved}_aspm_finding_due_idx"[:63]),
            finding_search_idx=sql.Identifier(
                f"{resolved}_aspm_finding_search_idx"[:63]
            ),
            coverage_owner_scan_idx=sql.Identifier(
                f"{resolved}_aspm_coverage_owner_scan_idx"[:63]
            ),
            event_finding_idx=sql.Identifier(f"{resolved}_aspm_event_finding_idx"[:63]),
            import_owner_idx=sql.Identifier(f"{resolved}_aspm_import_owner_idx"[:63]),
        )
    )
    connection.execute(
        sql.SQL(
            """
            INSERT INTO {versions} (component, version, updated_at)
            VALUES ('aspm', %s, now())
            ON CONFLICT (component)
            DO UPDATE SET version = EXCLUDED.version, updated_at = now()
            """
        ).format(versions=identifier(resolved, "schema_versions")),
        (ASPM_SCHEMA_VERSION,),
    )


class AspmRepository:
    def __init__(
        self, dsn: str, schema: str, risk_engine: RiskEngine | None = None
    ) -> None:
        if psycopg is None or sql is None or Jsonb is None or dict_row is None:
            raise RuntimeError("psycopg is required for ASPM persistence.")
        if not dsn:
            raise ValueError("PostgreSQL DSN is required for ASPM operations.")
        self.dsn = dsn
        self.schema = schema_name(schema)
        self.risk_engine = risk_engine or RiskEngine()

    def ensure_schema(self) -> None:
        key = (hashlib.sha256(self.dsn.encode("utf-8")).hexdigest(), self.schema)
        with ASPM_SCHEMA_LOCK:
            if key in ASPM_SCHEMA_READY:
                return
            with psycopg.connect(self.dsn) as connection:
                create_aspm_schema(connection, self.schema)
            ASPM_SCHEMA_READY.add(key)

    def ingest(
        self,
        owner_user_id: str,
        owner_user_login: str,
        document: FindingDocument,
    ) -> dict[str, Any]:
        self.ensure_schema()
        owner = bounded_text(owner_user_id, 500) or "anonymous"
        actor = bounded_text(owner_user_login, 500) or owner
        import_id = uuid.uuid4().hex
        now = datetime.now(timezone.utc)
        with psycopg.connect(self.dsn, row_factory=dict_row) as connection:
            tool_id = self._upsert_tool(connection, owner, document)
            connection.execute(
                sql.SQL(
                    """
                    INSERT INTO {imports} (
                        import_id, owner_user_id, tool_id, source_format, status,
                        finding_count, complete_snapshot, metadata
                    ) VALUES (%s, %s, %s, %s, 'processing', %s, %s, %s)
                    """
                ).format(imports=self._table("aspm_imports")),
                (
                    import_id,
                    owner,
                    tool_id,
                    document.source_format,
                    len(document.findings),
                    document.complete_snapshot,
                    Jsonb(dict(document.metadata)),
                ),
            )
        try:
            result = self._ingest_document(
                owner,
                actor,
                import_id,
                tool_id,
                document,
                now,
            )
        except Exception as exc:
            with psycopg.connect(self.dsn) as connection:
                connection.execute(
                    sql.SQL(
                        """
                        UPDATE {imports}
                        SET status = 'failed', error_count = 1, error_message = %s,
                            completed_at = now()
                        WHERE import_id = %s AND owner_user_id = %s
                        """
                    ).format(imports=self._table("aspm_imports")),
                    (bounded_text(exc, 2000), import_id, owner),
                )
            raise
        return {
            "importId": import_id,
            "status": "completed",
            "tool": {
                "key": document.tool_key,
                "name": document.tool_name,
                "type": document.tool_type,
            },
            "findings": len(document.findings),
            **result,
        }

    def _ingest_document(
        self,
        owner: str,
        actor: str,
        import_id: str,
        tool_id: int,
        document: FindingDocument,
        now: datetime,
    ) -> dict[str, int]:
        with psycopg.connect(self.dsn, row_factory=dict_row) as connection:
            inserted = 0
            updated = 0
            linked_assets: dict[int, int] = {}
            asset_cache: dict[str, dict[str, Any] | None] = {}
            for finding in document.findings:
                location_key = finding.location.scope_key()
                if location_key not in asset_cache:
                    asset_cache[location_key] = self._resolve_asset(
                        connection, owner, finding.location
                    )
                asset = asset_cache[location_key]
                asset_id = int(asset["branch_inventory_id"]) if asset else None
                context = self._asset_risk_context(asset)
                assessment = self.risk_engine.assess(finding, context, now)
                finding_id, was_inserted = self._upsert_finding(
                    connection,
                    owner,
                    tool_id,
                    finding,
                    asset_id,
                    assessment.score,
                    assessment.band,
                    assessment.factors,
                    now,
                )
                self._sync_identifiers(connection, finding_id, finding)
                connection.execute(
                    sql.SQL(
                        "INSERT INTO {table} (import_id, finding_id) VALUES (%s, %s) ON CONFLICT DO NOTHING"
                    ).format(table=self._table("aspm_import_findings")),
                    (import_id, finding_id),
                )
                if was_inserted:
                    inserted += 1
                    self._record_event(
                        connection,
                        finding_id,
                        owner,
                        actor,
                        "created",
                        "",
                        finding.status,
                        "Imported from scanner.",
                        {"import_id": import_id},
                    )
                else:
                    updated += 1
                if asset_id is not None:
                    linked_assets[asset_id] = linked_assets.get(asset_id, 0) + 1
            for target in document.scanned_targets:
                location_key = target.scope_key()
                if location_key not in asset_cache:
                    asset_cache[location_key] = self._resolve_asset(
                        connection, owner, target
                    )
                asset = asset_cache[location_key]
                if asset:
                    linked_assets.setdefault(int(asset["branch_inventory_id"]), 0)
            for asset_id, finding_count in linked_assets.items():
                self._upsert_coverage(
                    connection,
                    owner,
                    tool_id,
                    import_id,
                    asset_id,
                    finding_count,
                    now,
                )
            resolved = 0
            if document.complete_snapshot and linked_assets:
                resolved = self._reconcile_snapshot(
                    connection,
                    owner,
                    actor,
                    tool_id,
                    import_id,
                    tuple(linked_assets),
                    now,
                )
            connection.execute(
                sql.SQL(
                    """
                    UPDATE {imports}
                    SET status = 'completed', inserted_count = %s, updated_count = %s,
                        resolved_count = %s, completed_at = %s
                    WHERE import_id = %s AND owner_user_id = %s
                    """
                ).format(imports=self._table("aspm_imports")),
                (inserted, updated, resolved, now, import_id, owner),
            )
        return {
            "inserted": inserted,
            "updated": updated,
            "resolved": resolved,
            "assetsCovered": len(linked_assets),
        }

    def posture(self, owner_user_id: str) -> dict[str, Any]:
        self.ensure_schema()
        owner = bounded_text(owner_user_id, 500) or "anonymous"
        with psycopg.connect(self.dsn, row_factory=dict_row) as connection:
            summary = connection.execute(
                sql.SQL(
                    """
                    SELECT
                        (SELECT count(*) FROM {branches} WHERE owner_user_id = %s) AS assets,
                        count(*) AS findings,
                        count(*) FILTER (WHERE f.status = ANY(%s::text[])) AS active_findings,
                        count(*) FILTER (WHERE f.status = ANY(%s::text[]) AND f.severity = 'critical') AS critical_findings,
                        count(*) FILTER (WHERE f.status = ANY(%s::text[]) AND f.severity = 'high') AS high_findings,
                        count(*) FILTER (WHERE f.status = ANY(%s::text[]) AND f.due_at < now()) AS overdue_findings,
                        count(DISTINCT f.branch_inventory_id) FILTER (WHERE f.status = ANY(%s::text[])) AS affected_assets,
                        COALESCE(round(avg(f.risk_score) FILTER (WHERE f.status = ANY(%s::text[]))), 0) AS average_risk
                    FROM {findings} f
                    WHERE f.owner_user_id = %s
                    """
                ).format(
                    branches=self._table("branch_inventory"),
                    findings=self._table("aspm_findings"),
                ),
                (
                    owner,
                    list(ACTIVE_FINDING_STATUSES),
                    list(ACTIVE_FINDING_STATUSES),
                    list(ACTIVE_FINDING_STATUSES),
                    list(ACTIVE_FINDING_STATUSES),
                    list(ACTIVE_FINDING_STATUSES),
                    list(ACTIVE_FINDING_STATUSES),
                    owner,
                ),
            ).fetchone()
            breakdowns = {
                dimension: self._breakdown(connection, owner, dimension)
                for dimension in ("severity", "status", "risk_band")
            }
            top_assets = connection.execute(
                sql.SQL(
                    """
                    SELECT
                        b.branch_inventory_id,
                        COALESCE(b.inventory_name, b.mobile_name, r.repo_name) AS application,
                        r.provider,
                        r.organization,
                        r.project,
                        r.repo_name AS repository,
                        b.branch_name AS branch,
                        max(f.risk_score) AS max_risk_score,
                        count(*) AS active_findings,
                        count(*) FILTER (WHERE f.severity = 'critical') AS critical_findings,
                        count(*) FILTER (WHERE f.due_at < now()) AS overdue_findings
                    FROM {findings} f
                    JOIN {branches} b ON b.branch_inventory_id = f.branch_inventory_id
                    JOIN {repositories} r ON r.repository_id = b.repository_id
                    WHERE f.owner_user_id = %s AND f.status = ANY(%s::text[])
                    GROUP BY b.branch_inventory_id, r.provider, r.organization, r.project,
                             r.repo_name, b.branch_name
                    ORDER BY max(f.risk_score) DESC, count(*) DESC
                    LIMIT 10
                    """
                ).format(
                    findings=self._table("aspm_findings"),
                    branches=self._table("branch_inventory"),
                    repositories=self._table("repositories"),
                ),
                (owner, list(ACTIVE_FINDING_STATUSES)),
            ).fetchall()
            tools = connection.execute(
                sql.SQL(
                    """
                    SELECT t.tool_key, t.tool_name, t.tool_type, t.last_seen_at,
                           COALESCE(c.covered_assets, 0) AS covered_assets,
                           COALESCE(f.active_findings, 0) AS active_findings,
                           i.status AS last_import_status,
                           i.started_at AS last_import_at,
                           i.error_message AS last_import_error
                    FROM {tools} t
                    LEFT JOIN (
                        SELECT tool_id, owner_user_id,
                               count(DISTINCT branch_inventory_id) AS covered_assets
                        FROM {coverage}
                        WHERE owner_user_id = %s
                        GROUP BY tool_id, owner_user_id
                    ) c ON c.tool_id = t.tool_id AND c.owner_user_id = t.owner_user_id
                    LEFT JOIN (
                        SELECT tool_id, owner_user_id, count(*) AS active_findings
                        FROM {findings}
                        WHERE owner_user_id = %s AND status = ANY(%s::text[])
                        GROUP BY tool_id, owner_user_id
                    ) f ON f.tool_id = t.tool_id AND f.owner_user_id = t.owner_user_id
                    LEFT JOIN LATERAL (
                        SELECT status, started_at, error_message
                        FROM {imports}
                        WHERE tool_id = t.tool_id AND owner_user_id = t.owner_user_id
                        ORDER BY started_at DESC
                        LIMIT 1
                    ) i ON true
                    WHERE t.owner_user_id = %s
                    ORDER BY t.tool_name
                    """
                ).format(
                    tools=self._table("aspm_tools"),
                    coverage=self._table("aspm_coverage"),
                    findings=self._table("aspm_findings"),
                    imports=self._table("aspm_imports"),
                ),
                (owner, owner, list(ACTIVE_FINDING_STATUSES), owner),
            ).fetchall()
            trends = connection.execute(
                sql.SQL(
                    """
                    SELECT date_trunc('day', started_at)::date AS day,
                           sum(finding_count) AS findings_observed,
                           sum(inserted_count) AS new_findings,
                           sum(resolved_count) AS resolved_findings
                    FROM {imports}
                    WHERE owner_user_id = %s AND started_at >= now() - interval '30 days'
                    GROUP BY date_trunc('day', started_at)::date
                    ORDER BY day
                    """
                ).format(imports=self._table("aspm_imports")),
                (owner,),
            ).fetchall()
            coverage_summary = self._coverage_summary(connection, owner)
        return {
            "summary": json_rows([summary])[0],
            "breakdowns": breakdowns,
            "topAssets": json_rows(top_assets),
            "tools": json_rows(tools),
            "trends": json_rows(trends),
            "coverage": coverage_summary,
            "generatedAt": datetime.now(timezone.utc).isoformat(),
        }

    def search_findings(
        self,
        owner_user_id: str,
        query: str = "",
        filters: dict[str, Any] | None = None,
        limit: int = 100,
        offset: int = 0,
        include_facets: bool = True,
    ) -> dict[str, Any]:
        self.ensure_schema()
        owner = bounded_text(owner_user_id, 500) or "anonymous"
        resolved_filters = normalize_finding_filters(filters)
        where, parameters = self._finding_filter(owner, query, resolved_filters)
        bounded_limit = max(1, min(int(limit), 500))
        bounded_offset = max(0, int(offset))
        order = finding_order(resolved_filters)
        with psycopg.connect(self.dsn, row_factory=dict_row) as connection:
            total = connection.execute(
                sql.SQL("SELECT count(*) FROM {view} f WHERE {where}").format(
                    view=self._finding_view(), where=where
                ),
                parameters,
            ).fetchone()["count"]
            rows = connection.execute(
                sql.SQL(
                    "SELECT * FROM {view} f WHERE {where} ORDER BY {order} LIMIT %s OFFSET %s"
                ).format(view=self._finding_view(), where=where, order=order),
                (*parameters, bounded_limit, bounded_offset),
            ).fetchall()
            facets = self._finding_facets(connection, owner) if include_facets else {}
        return {
            "rows": json_rows(rows),
            "total": int(total),
            "limit": bounded_limit,
            "offset": bounded_offset,
            "filters": resolved_filters,
            "facets": facets,
        }

    def export_findings(
        self,
        owner_user_id: str,
        export_format: str,
        query: str = "",
        filters: dict[str, Any] | None = None,
    ) -> bytes:
        result = self.search_findings(
            owner_user_id,
            query=query,
            filters=filters,
            limit=500,
            include_facets=False,
        )
        rows = result["rows"]
        offset = len(rows)
        while offset < result["total"] and offset < 100_000:
            page = self.search_findings(
                owner_user_id,
                query=query,
                filters=filters,
                limit=500,
                offset=offset,
                include_facets=False,
            )["rows"]
            if not page:
                break
            rows.extend(page)
            offset += len(page)
        if export_format == "json":
            return rows_to_json(rows)
        if export_format == "csv":
            return rows_to_csv(rows, FINDING_EXPORT_COLUMNS)
        if export_format == "xlsx":
            return rows_to_xlsx(rows, FINDING_EXPORT_COLUMNS, "Security Findings")
        raise ValueError("Finding export format must be xlsx, csv, or json.")

    def update_finding(
        self,
        owner_user_id: str,
        actor: str,
        finding_id: str,
        status: str,
        assignee: str = "",
        due_at: Any = None,
        note: str = "",
    ) -> dict[str, Any]:
        self.ensure_schema()
        owner = bounded_text(owner_user_id, 500) or "anonymous"
        resolved_id = bounded_text(finding_id, 100)
        target_status = normalize_status(status, "")
        if not target_status:
            raise ValueError("Finding status is invalid.")
        parsed_due_at = utc_datetime(due_at)
        with psycopg.connect(self.dsn, row_factory=dict_row) as connection:
            current = connection.execute(
                sql.SQL(
                    "SELECT finding_id, status, assignee, due_at FROM {table} WHERE finding_id = %s AND owner_user_id = %s FOR UPDATE"
                ).format(table=self._table("aspm_findings")),
                (resolved_id, owner),
            ).fetchone()
            if not current:
                raise KeyError("Finding not found.")
            validate_transition(current["status"], target_status)
            resolved_at = (
                datetime.now(timezone.utc) if target_status == "resolved" else None
            )
            updated = connection.execute(
                sql.SQL(
                    """
                    UPDATE {table}
                    SET status = %s, assignee = %s, due_at = %s, resolved_at = %s,
                        updated_at = now()
                    WHERE finding_id = %s AND owner_user_id = %s
                    RETURNING finding_id, status, assignee, due_at, resolved_at, updated_at
                    """
                ).format(table=self._table("aspm_findings")),
                (
                    target_status,
                    bounded_text(assignee, 500) or None,
                    parsed_due_at,
                    resolved_at,
                    resolved_id,
                    owner,
                ),
            ).fetchone()
            self._record_event(
                connection,
                resolved_id,
                owner,
                bounded_text(actor, 500) or owner,
                "workflow_updated",
                current["status"],
                target_status,
                bounded_text(note, 5000),
                {
                    "assignee": bounded_text(assignee, 500),
                    "due_at": parsed_due_at.isoformat() if parsed_due_at else None,
                },
            )
        return json_rows([updated])[0]

    def finding_detail(self, owner_user_id: str, finding_id: str) -> dict[str, Any]:
        result = self.search_findings(
            owner_user_id,
            filters={"finding_id": bounded_text(finding_id, 100)},
            limit=1,
            include_facets=False,
        )
        if not result["rows"]:
            raise KeyError("Finding not found.")
        owner = bounded_text(owner_user_id, 500) or "anonymous"
        with psycopg.connect(self.dsn, row_factory=dict_row) as connection:
            events = connection.execute(
                sql.SQL(
                    """
                    SELECT event_type, actor, from_status, to_status, note, metadata, created_at
                    FROM {events}
                    WHERE finding_id = %s AND owner_user_id = %s
                    ORDER BY created_at DESC, event_id DESC
                    LIMIT 100
                    """
                ).format(events=self._table("aspm_finding_events")),
                (finding_id, owner),
            ).fetchall()
        return {"finding": result["rows"][0], "events": json_rows(events)}

    def coverage(
        self, owner_user_id: str, limit: int = 100, offset: int = 0
    ) -> dict[str, Any]:
        self.ensure_schema()
        owner = bounded_text(owner_user_id, 500) or "anonymous"
        bounded_limit = max(1, min(int(limit), 500))
        bounded_offset = max(0, int(offset))
        with psycopg.connect(self.dsn, row_factory=dict_row) as connection:
            summary = self._coverage_summary(connection, owner)
            total = connection.execute(
                sql.SQL(
                    "SELECT count(*) FROM {branches} WHERE owner_user_id = %s"
                ).format(branches=self._table("branch_inventory")),
                (owner,),
            ).fetchone()["count"]
            rows = connection.execute(
                sql.SQL(
                    """
                    SELECT
                        b.branch_inventory_id,
                        COALESCE(b.inventory_name, b.mobile_name, r.repo_name) AS application,
                        r.provider,
                        r.organization,
                        r.project,
                        r.repo_name AS repository,
                        b.branch_name AS branch,
                        COALESCE(types.inventory_types, '') AS application_types,
                        max(c.last_scan_at) AS last_scan_at,
                        count(DISTINCT c.tool_id) AS tool_count,
                        COALESCE(string_agg(DISTINCT t.tool_name, '; ' ORDER BY t.tool_name), '') AS tools,
                        CASE
                            WHEN max(c.last_scan_at) IS NULL THEN 'not_scanned'
                            WHEN max(c.last_scan_at) < now() - interval '90 days' THEN 'expired'
                            WHEN max(c.last_scan_at) < now() - interval '30 days' THEN 'stale'
                            ELSE 'current'
                        END AS coverage_status
                    FROM {branches} b
                    JOIN {repositories} r ON r.repository_id = b.repository_id
                    LEFT JOIN {coverage} c ON c.branch_inventory_id = b.branch_inventory_id AND c.owner_user_id = b.owner_user_id
                    LEFT JOIN {tools} t ON t.tool_id = c.tool_id
                    LEFT JOIN LATERAL (
                        SELECT string_agg(inventory_type, '; ' ORDER BY inventory_type) AS inventory_types
                        FROM {types}
                        WHERE branch_inventory_id = b.branch_inventory_id
                    ) types ON true
                    WHERE b.owner_user_id = %s
                    GROUP BY b.branch_inventory_id, r.provider, r.organization, r.project,
                             r.repo_name, b.branch_name, types.inventory_types
                    ORDER BY
                        CASE WHEN max(c.last_scan_at) IS NULL THEN 0 ELSE 1 END,
                        max(c.last_scan_at), r.organization, r.repo_name
                    LIMIT %s OFFSET %s
                    """
                ).format(
                    branches=self._table("branch_inventory"),
                    repositories=self._table("repositories"),
                    coverage=self._table("aspm_coverage"),
                    tools=self._table("aspm_tools"),
                    types=self._table("inventory_types"),
                ),
                (owner, bounded_limit, bounded_offset),
            ).fetchall()
        return {
            "summary": summary,
            "rows": json_rows(rows),
            "total": int(total),
            "limit": bounded_limit,
            "offset": bounded_offset,
        }

    def update_asset_profile(
        self,
        owner_user_id: str,
        actor: str,
        branch_inventory_id: int,
        profile: dict[str, Any],
    ) -> dict[str, Any]:
        self.ensure_schema()
        owner = bounded_text(owner_user_id, 500) or "anonymous"
        criticality = bounded_text(profile.get("criticality"), 50) or "medium"
        classification = (
            bounded_text(profile.get("dataClassification"), 50) or "internal"
        )
        if criticality not in {"low", "medium", "high", "mission_critical"}:
            raise ValueError("Asset criticality is invalid.")
        if classification not in {"public", "internal", "confidential", "restricted"}:
            raise ValueError("Asset data classification is invalid.")
        internet_exposed = profile.get("internetExposed")
        if internet_exposed not in {True, False, None}:
            raise ValueError("Internet exposure must be true, false, or null.")
        tags = sorted(
            {
                bounded_text(item, 100)
                for item in profile.get("tags", [])
                if bounded_text(item, 100)
            }
        )[:50]
        with psycopg.connect(self.dsn, row_factory=dict_row) as connection:
            branch = connection.execute(
                sql.SQL(
                    "SELECT branch_inventory_id FROM {branches} WHERE branch_inventory_id = %s AND owner_user_id = %s"
                ).format(branches=self._table("branch_inventory")),
                (branch_inventory_id, owner),
            ).fetchone()
            if not branch:
                raise KeyError("Inventory asset not found.")
            row = connection.execute(
                sql.SQL(
                    """
                    INSERT INTO {profiles} (
                        branch_inventory_id, owner_user_id, criticality, internet_exposed,
                        data_classification, business_owner, technical_owner, tags, updated_by
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (branch_inventory_id) DO UPDATE SET
                        criticality = EXCLUDED.criticality,
                        internet_exposed = EXCLUDED.internet_exposed,
                        data_classification = EXCLUDED.data_classification,
                        business_owner = EXCLUDED.business_owner,
                        technical_owner = EXCLUDED.technical_owner,
                        tags = EXCLUDED.tags,
                        updated_by = EXCLUDED.updated_by,
                        updated_at = now()
                    RETURNING *
                    """
                ).format(profiles=self._table("asset_security_profiles")),
                (
                    branch_inventory_id,
                    owner,
                    criticality,
                    internet_exposed,
                    classification,
                    bounded_text(profile.get("businessOwner"), 500) or None,
                    bounded_text(profile.get("technicalOwner"), 500) or None,
                    tags,
                    bounded_text(actor, 500) or owner,
                ),
            ).fetchone()
            self._rerisk_asset(connection, owner, branch_inventory_id)
        return json_rows([row])[0]

    def asset_profile(
        self, owner_user_id: str, branch_inventory_id: int
    ) -> dict[str, Any]:
        self.ensure_schema()
        owner = bounded_text(owner_user_id, 500) or "anonymous"
        with psycopg.connect(self.dsn, row_factory=dict_row) as connection:
            row = connection.execute(
                sql.SQL(
                    """
                    SELECT
                        b.branch_inventory_id,
                        COALESCE(b.inventory_name, b.mobile_name, r.repo_name) AS application,
                        COALESCE(p.criticality, 'medium') AS criticality,
                        p.internet_exposed,
                        COALESCE(p.data_classification, 'internal') AS data_classification,
                        COALESCE(p.business_owner, '') AS business_owner,
                        COALESCE(p.technical_owner, '') AS technical_owner,
                        COALESCE(p.tags, '{{}}'::text[]) AS tags,
                        EXISTS (
                            SELECT 1 FROM {domains} d
                            WHERE d.branch_inventory_id = b.branch_inventory_id
                        ) AS domain_detected,
                        p.updated_by,
                        p.updated_at
                    FROM {branches} b
                    JOIN {repositories} r ON r.repository_id = b.repository_id
                    LEFT JOIN {profiles} p ON p.branch_inventory_id = b.branch_inventory_id
                    WHERE b.branch_inventory_id = %s AND b.owner_user_id = %s
                    """
                ).format(
                    branches=self._table("branch_inventory"),
                    repositories=self._table("repositories"),
                    profiles=self._table("asset_security_profiles"),
                    domains=self._table("web_domains"),
                ),
                (branch_inventory_id, owner),
            ).fetchone()
        if not row:
            raise KeyError("Inventory asset not found.")
        return json_rows([row])[0]

    def _upsert_tool(
        self, connection: Any, owner: str, document: FindingDocument
    ) -> int:
        row = connection.execute(
            sql.SQL(
                """
                INSERT INTO {tools} (
                    owner_user_id, tool_key, tool_name, tool_type, metadata
                ) VALUES (%s, %s, %s, %s, %s)
                ON CONFLICT (owner_user_id, tool_key) DO UPDATE SET
                    tool_name = EXCLUDED.tool_name,
                    tool_type = EXCLUDED.tool_type,
                    last_seen_at = now(),
                    metadata = {tools}.metadata || EXCLUDED.metadata
                RETURNING tool_id
                """
            ).format(tools=self._table("aspm_tools")),
            (
                owner,
                document.tool_key,
                document.tool_name,
                document.tool_type or "other",
                Jsonb(dict(document.metadata)),
            ),
        ).fetchone()
        return int(row["tool_id"])

    def _resolve_asset(
        self, connection: Any, owner: str, location: SourceLocation
    ) -> dict[str, Any] | None:
        if not location.repository:
            return None
        clauses = [
            sql.SQL("b.owner_user_id = %s"),
            sql.SQL("lower(r.repo_name) = lower(%s)"),
        ]
        parameters: list[Any] = [owner, location.repository]
        for column, value in (
            ("provider", location.provider),
            ("organization", location.organization),
            ("project", location.project),
        ):
            if value:
                clauses.append(
                    sql.SQL("lower(r.{column}) = lower(%s)").format(
                        column=sql.Identifier(column)
                    )
                )
                parameters.append(value)
        if location.branch:
            clauses.append(sql.SQL("lower(b.branch_name) = lower(%s)"))
            parameters.append(location.branch.removeprefix("refs/heads/"))
        rows = connection.execute(
            sql.SQL(
                """
                SELECT b.branch_inventory_id, b.owner_user_id,
                       COALESCE(domains.domain, '') AS primary_web_domain,
                       profile.criticality, profile.internet_exposed,
                       profile.data_classification
                FROM {branches} b
                JOIN {repositories} r ON r.repository_id = b.repository_id
                LEFT JOIN LATERAL (
                    SELECT domain FROM {domains}
                    WHERE branch_inventory_id = b.branch_inventory_id
                    ORDER BY is_primary DESC, domain LIMIT 1
                ) domains ON true
                LEFT JOIN {profiles} profile ON profile.branch_inventory_id = b.branch_inventory_id
                WHERE {where}
                ORDER BY b.last_updated DESC NULLS LAST
                LIMIT 2
                """
            ).format(
                branches=self._table("branch_inventory"),
                repositories=self._table("repositories"),
                domains=self._table("web_domains"),
                profiles=self._table("asset_security_profiles"),
                where=sql.SQL(" AND ").join(clauses),
            ),
            parameters,
        ).fetchall()
        return rows[0] if len(rows) == 1 else None

    def _asset_risk_context(
        self,
        asset: dict[str, Any] | None,
    ) -> AssetRiskContext:
        if not asset:
            return AssetRiskContext()
        exposed = asset.get("internet_exposed")
        if exposed is None:
            exposed = bool(asset.get("primary_web_domain"))
        return AssetRiskContext(
            criticality=asset.get("criticality") or "medium",
            internet_exposed=bool(exposed),
            data_classification=asset.get("data_classification") or "internal",
        )

    def _upsert_finding(
        self,
        connection: Any,
        owner: str,
        tool_id: int,
        finding: FindingInput,
        asset_id: int | None,
        risk_score: int,
        risk_band: str,
        risk_factors: tuple[dict[str, Any], ...],
        now: datetime,
    ) -> tuple[str, bool]:
        first_seen = finding.first_seen or now
        last_seen = finding.last_seen or now
        due_at = first_seen + timedelta(days=severity_sla_days(finding.severity))
        row = connection.execute(
            sql.SQL(
                """
                INSERT INTO {findings} (
                    finding_id, owner_user_id, tool_id, branch_inventory_id,
                    fingerprint, external_id, title, description, rule_id, category,
                    severity, status, confidence, provider, organization, project,
                    repository, branch, path, start_line, end_line, scanner_url,
                    remediation, package_name, package_version, fixed_version,
                    cvss_score, epss_score, exploit_available, risk_score, risk_band,
                    risk_factors, due_at, first_seen, last_seen, resolved_at, raw_data
                ) VALUES (
                    %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                    %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                    %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                    %s, %s, %s, %s, %s, %s, %s
                )
                ON CONFLICT (owner_user_id, tool_id, fingerprint) DO UPDATE SET
                    branch_inventory_id = COALESCE(EXCLUDED.branch_inventory_id, {findings}.branch_inventory_id),
                    external_id = EXCLUDED.external_id,
                    title = EXCLUDED.title,
                    description = EXCLUDED.description,
                    rule_id = EXCLUDED.rule_id,
                    category = EXCLUDED.category,
                    severity = EXCLUDED.severity,
                    status = CASE
                        WHEN {findings}.status = 'resolved'
                             AND EXCLUDED.status IN ('open', 'triaged', 'in_progress')
                            THEN EXCLUDED.status
                        ELSE {findings}.status
                    END,
                    confidence = EXCLUDED.confidence,
                    provider = EXCLUDED.provider,
                    organization = EXCLUDED.organization,
                    project = EXCLUDED.project,
                    repository = EXCLUDED.repository,
                    branch = EXCLUDED.branch,
                    path = EXCLUDED.path,
                    start_line = EXCLUDED.start_line,
                    end_line = EXCLUDED.end_line,
                    scanner_url = EXCLUDED.scanner_url,
                    remediation = EXCLUDED.remediation,
                    package_name = EXCLUDED.package_name,
                    package_version = EXCLUDED.package_version,
                    fixed_version = EXCLUDED.fixed_version,
                    cvss_score = EXCLUDED.cvss_score,
                    epss_score = EXCLUDED.epss_score,
                    exploit_available = EXCLUDED.exploit_available,
                    risk_score = EXCLUDED.risk_score,
                    risk_band = EXCLUDED.risk_band,
                    risk_factors = EXCLUDED.risk_factors,
                    due_at = COALESCE({findings}.due_at, EXCLUDED.due_at),
                    first_seen = LEAST({findings}.first_seen, EXCLUDED.first_seen),
                    last_seen = GREATEST({findings}.last_seen, EXCLUDED.last_seen),
                    resolved_at = CASE
                        WHEN {findings}.status = 'resolved'
                             AND EXCLUDED.status IN ('open', 'triaged', 'in_progress')
                            THEN NULL
                        ELSE {findings}.resolved_at
                    END,
                    raw_data = EXCLUDED.raw_data,
                    updated_at = now()
                RETURNING finding_id, (xmax = 0) AS inserted
                """
            ).format(findings=self._table("aspm_findings")),
            (
                uuid.uuid4().hex,
                owner,
                tool_id,
                asset_id,
                finding.fingerprint(str(tool_id)),
                finding.external_id or None,
                finding.title,
                finding.description or None,
                finding.rule_id or None,
                finding.category or None,
                finding.severity,
                finding.status,
                finding.confidence or None,
                finding.location.provider or None,
                finding.location.organization or None,
                finding.location.project or None,
                finding.location.repository or None,
                finding.location.branch.removeprefix("refs/heads/") or None,
                finding.location.path or None,
                finding.location.start_line,
                finding.location.end_line,
                finding.scanner_url or None,
                finding.remediation or None,
                finding.package_name or None,
                finding.package_version or None,
                finding.fixed_version or None,
                finding.cvss_score,
                finding.epss_score,
                finding.exploit_available,
                risk_score,
                risk_band,
                Jsonb(list(risk_factors)),
                due_at,
                first_seen,
                last_seen,
                now if finding.status == "resolved" else None,
                Jsonb(finding.as_raw_json()),
            ),
        ).fetchone()
        return row["finding_id"], bool(row["inserted"])

    def _sync_identifiers(
        self, connection: Any, finding_id: str, finding: FindingInput
    ) -> None:
        desired = {("cwe", value) for value in finding.cwes} | {
            ("cve", value) for value in finding.cves
        }
        connection.execute(
            sql.SQL("DELETE FROM {table} WHERE finding_id = %s").format(
                table=self._table("aspm_finding_identifiers")
            ),
            (finding_id,),
        )
        for identifier_type, value in sorted(desired):
            connection.execute(
                sql.SQL(
                    "INSERT INTO {table} (finding_id, identifier_type, identifier) VALUES (%s, %s, %s)"
                ).format(table=self._table("aspm_finding_identifiers")),
                (finding_id, identifier_type, value),
            )

    def _upsert_coverage(
        self,
        connection: Any,
        owner: str,
        tool_id: int,
        import_id: str,
        asset_id: int,
        finding_count: int,
        now: datetime,
    ) -> None:
        connection.execute(
            sql.SQL(
                """
                INSERT INTO {coverage} (
                    branch_inventory_id, tool_id, owner_user_id, last_import_id,
                    last_scan_at, finding_count, status
                ) VALUES (%s, %s, %s, %s, %s, %s, 'scanned')
                ON CONFLICT (branch_inventory_id, tool_id) DO UPDATE SET
                    last_import_id = EXCLUDED.last_import_id,
                    last_scan_at = EXCLUDED.last_scan_at,
                    finding_count = EXCLUDED.finding_count,
                    status = EXCLUDED.status,
                    metadata = EXCLUDED.metadata
                """
            ).format(coverage=self._table("aspm_coverage")),
            (asset_id, tool_id, owner, import_id, now, finding_count),
        )

    def _reconcile_snapshot(
        self,
        connection: Any,
        owner: str,
        actor: str,
        tool_id: int,
        import_id: str,
        asset_ids: tuple[int, ...],
        now: datetime,
    ) -> int:
        missing = connection.execute(
            sql.SQL(
                """
                SELECT f.finding_id, f.status
                FROM {findings} f
                WHERE f.owner_user_id = %s
                  AND f.tool_id = %s
                  AND f.branch_inventory_id = ANY(%s::bigint[])
                  AND f.status = ANY(%s::text[])
                  AND NOT EXISTS (
                      SELECT 1 FROM {import_findings} current_import
                      WHERE current_import.import_id = %s
                        AND current_import.finding_id = f.finding_id
                  )
                FOR UPDATE
                """
            ).format(
                findings=self._table("aspm_findings"),
                import_findings=self._table("aspm_import_findings"),
            ),
            (
                owner,
                tool_id,
                list(asset_ids),
                list(ACTIVE_FINDING_STATUSES),
                import_id,
            ),
        ).fetchall()
        if not missing:
            return 0
        ids = [row["finding_id"] for row in missing]
        connection.execute(
            sql.SQL(
                """
                UPDATE {findings}
                SET status = 'resolved', resolved_at = %s, updated_at = %s
                WHERE finding_id = ANY(%s::text[])
                """
            ).format(findings=self._table("aspm_findings")),
            (now, now, ids),
        )
        for row in missing:
            self._record_event(
                connection,
                row["finding_id"],
                owner,
                actor,
                "snapshot_resolved",
                row["status"],
                "resolved",
                "Finding was absent from a complete scanner snapshot.",
                {"import_id": import_id},
            )
        return len(missing)

    def _record_event(
        self,
        connection: Any,
        finding_id: str,
        owner: str,
        actor: str,
        event_type: str,
        from_status: str,
        to_status: str,
        note: str,
        metadata: dict[str, Any],
    ) -> None:
        connection.execute(
            sql.SQL(
                """
                INSERT INTO {events} (
                    finding_id, owner_user_id, actor, event_type,
                    from_status, to_status, note, metadata
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                """
            ).format(events=self._table("aspm_finding_events")),
            (
                finding_id,
                owner,
                actor,
                event_type,
                from_status or None,
                to_status or None,
                note or None,
                Jsonb(metadata),
            ),
        )

    def _rerisk_asset(self, connection: Any, owner: str, asset_id: int) -> None:
        context_row = connection.execute(
            sql.SQL(
                """
                SELECT p.criticality, p.internet_exposed, p.data_classification,
                       EXISTS (SELECT 1 FROM {domains} d WHERE d.branch_inventory_id = b.branch_inventory_id) AS has_domain
                FROM {branches} b
                LEFT JOIN {profiles} p ON p.branch_inventory_id = b.branch_inventory_id
                WHERE b.branch_inventory_id = %s AND b.owner_user_id = %s
                """
            ).format(
                domains=self._table("web_domains"),
                branches=self._table("branch_inventory"),
                profiles=self._table("asset_security_profiles"),
            ),
            (asset_id, owner),
        ).fetchone()
        context = AssetRiskContext(
            criticality=context_row["criticality"] or "medium",
            internet_exposed=(
                context_row["internet_exposed"]
                if context_row["internet_exposed"] is not None
                else context_row["has_domain"]
            ),
            data_classification=context_row["data_classification"] or "internal",
        )
        rows = connection.execute(
            sql.SQL(
                """
                SELECT finding_id, external_id, title, severity, status, description,
                       rule_id, category, confidence, scanner_url, remediation,
                       package_name, package_version, fixed_version, cvss_score,
                       epss_score, exploit_available, first_seen, last_seen,
                       provider, organization, project, repository, branch, path,
                       start_line, end_line, raw_data
                FROM {findings}
                WHERE owner_user_id = %s AND branch_inventory_id = %s
                """
            ).format(findings=self._table("aspm_findings")),
            (owner, asset_id),
        ).fetchall()
        for row in rows:
            finding = FindingInput(
                external_id=row["external_id"] or "",
                title=row["title"],
                severity=row["severity"],
                status=row["status"],
                description=row["description"] or "",
                rule_id=row["rule_id"] or "",
                category=row["category"] or "",
                confidence=row["confidence"] or "",
                location=SourceLocation(
                    provider=row["provider"] or "",
                    organization=row["organization"] or "",
                    project=row["project"] or "",
                    repository=row["repository"] or "",
                    branch=row["branch"] or "",
                    path=row["path"] or "",
                    start_line=row["start_line"],
                    end_line=row["end_line"],
                ),
                scanner_url=row["scanner_url"] or "",
                remediation=row["remediation"] or "",
                package_name=row["package_name"] or "",
                package_version=row["package_version"] or "",
                fixed_version=row["fixed_version"] or "",
                cvss_score=row["cvss_score"],
                epss_score=row["epss_score"],
                exploit_available=row["exploit_available"],
                first_seen=row["first_seen"],
                last_seen=row["last_seen"],
                raw_data=row["raw_data"],
            )
            assessment = self.risk_engine.assess(finding, context)
            connection.execute(
                sql.SQL(
                    "UPDATE {findings} SET risk_score = %s, risk_band = %s, risk_factors = %s, updated_at = now() WHERE finding_id = %s"
                ).format(findings=self._table("aspm_findings")),
                (
                    assessment.score,
                    assessment.band,
                    Jsonb(list(assessment.factors)),
                    row["finding_id"],
                ),
            )

    def _breakdown(
        self, connection: Any, owner: str, dimension: str
    ) -> list[dict[str, Any]]:
        if dimension not in {"severity", "status", "risk_band"}:
            raise ValueError("Unsupported posture dimension.")
        rows = connection.execute(
            sql.SQL(
                "SELECT {dimension} AS name, count(*) AS count FROM {findings} WHERE owner_user_id = %s GROUP BY {dimension} ORDER BY count(*) DESC"
            ).format(
                dimension=sql.Identifier(dimension),
                findings=self._table("aspm_findings"),
            ),
            (owner,),
        ).fetchall()
        return json_rows(rows)

    def _coverage_summary(self, connection: Any, owner: str) -> dict[str, Any]:
        row = connection.execute(
            sql.SQL(
                """
                SELECT
                    count(*) AS total_assets,
                    count(*) FILTER (WHERE latest_scan >= now() - interval '30 days') AS current_assets,
                    count(*) FILTER (
                        WHERE latest_scan < now() - interval '30 days'
                          AND latest_scan >= now() - interval '90 days'
                    ) AS stale_assets,
                    count(*) FILTER (
                        WHERE latest_scan IS NULL OR latest_scan < now() - interval '90 days'
                    ) AS untested_assets
                FROM (
                    SELECT b.branch_inventory_id, max(c.last_scan_at) AS latest_scan
                    FROM {branches} b
                    LEFT JOIN {coverage} c ON c.branch_inventory_id = b.branch_inventory_id
                        AND c.owner_user_id = b.owner_user_id
                    WHERE b.owner_user_id = %s
                    GROUP BY b.branch_inventory_id
                ) assets
                """
            ).format(
                branches=self._table("branch_inventory"),
                coverage=self._table("aspm_coverage"),
            ),
            (owner,),
        ).fetchone()
        result = json_rows([row])[0]
        total = int(result["total_assets"] or 0)
        current = int(result["current_assets"] or 0)
        result["coverage_percent"] = round((current / total) * 100, 1) if total else 0
        return result

    def _finding_facets(self, connection: Any, owner: str) -> dict[str, Any]:
        facets: dict[str, Any] = {}
        for column in ("severity", "status", "risk_band"):
            rows = connection.execute(
                sql.SQL(
                    "SELECT {column} AS value, count(*) AS count FROM {findings} WHERE owner_user_id = %s GROUP BY {column} ORDER BY count(*) DESC, {column}"
                ).format(
                    column=sql.Identifier(column),
                    findings=self._table("aspm_findings"),
                ),
                (owner,),
            ).fetchall()
            facets[column] = json_rows(rows)
        tool_types = connection.execute(
            sql.SQL(
                """
                SELECT t.tool_type AS value, count(*) AS count
                FROM {findings} f
                JOIN {tools} t ON t.tool_id = f.tool_id
                WHERE f.owner_user_id = %s
                GROUP BY t.tool_type
                ORDER BY count(*) DESC, t.tool_type
                """
            ).format(
                findings=self._table("aspm_findings"),
                tools=self._table("aspm_tools"),
            ),
            (owner,),
        ).fetchall()
        facets["tool_type"] = json_rows(tool_types)
        tools = connection.execute(
            sql.SQL(
                """
                SELECT t.tool_key AS value, max(t.tool_name) AS label, count(*) AS count
                FROM {findings} f
                JOIN {tools} t ON t.tool_id = f.tool_id
                WHERE f.owner_user_id = %s
                GROUP BY t.tool_key
                ORDER BY max(t.tool_name), t.tool_key
                """
            ).format(
                findings=self._table("aspm_findings"),
                tools=self._table("aspm_tools"),
            ),
            (owner,),
        ).fetchall()
        facets["tools"] = json_rows(tools)
        return facets

    def _finding_filter(
        self, owner: str, query: str, filters: dict[str, Any]
    ) -> tuple[Any, list[Any]]:
        clauses = [sql.SQL("f.owner_user_id = %s")]
        parameters: list[Any] = [owner]
        search = bounded_text(query, 500)
        if search:
            clauses.append(
                sql.SQL(
                    "to_tsvector('simple'::regconfig, "
                    "COALESCE(f.title, '') || ' ' || COALESCE(f.description, '') || ' ' || "
                    "COALESCE(f.rule_id, '') || ' ' || COALESCE(f.category, '') || ' ' || "
                    "COALESCE(f.repository, '') || ' ' || COALESCE(f.path, '') || ' ' || "
                    "COALESCE(f.package_name, '')) @@ websearch_to_tsquery('simple'::regconfig, %s)"
                )
            )
            parameters.append(search)
        for column, key in (
            ("severity", "severities"),
            ("status", "statuses"),
            ("risk_band", "risk_bands"),
            ("tool_key", "tools"),
            ("tool_type", "tool_types"),
        ):
            values = filters.get(key, [])
            if values:
                clauses.append(
                    sql.SQL("lower(f.{column}) = ANY(%s::text[])").format(
                        column=sql.Identifier(column)
                    )
                )
                parameters.append(values)
        if filters.get("finding_id"):
            clauses.append(sql.SQL("f.finding_id = %s"))
            parameters.append(filters["finding_id"])
        if filters.get("repository"):
            clauses.append(sql.SQL("f.repository ILIKE %s"))
            parameters.append(f"%{escape_like(filters['repository'])}%")
        if filters.get("assignee"):
            clauses.append(sql.SQL("f.assignee ILIKE %s"))
            parameters.append(f"%{escape_like(filters['assignee'])}%")
        if filters.get("overdue") is True:
            clauses.append(sql.SQL("f.due_at < now() AND f.status = ANY(%s::text[])"))
            parameters.append(list(ACTIVE_FINDING_STATUSES))
        if filters.get("unassigned") is True:
            clauses.append(sql.SQL("COALESCE(f.assignee, '') = ''"))
        if filters.get("has_asset") is True:
            clauses.append(sql.SQL("f.branch_inventory_id IS NOT NULL"))
        if filters.get("has_asset") is False:
            clauses.append(sql.SQL("f.branch_inventory_id IS NULL"))
        return sql.SQL(" AND ").join(clauses), parameters

    def _finding_view(self) -> Any:
        return sql.SQL(
            """
            (
                SELECT
                    f.finding_id, f.owner_user_id, f.title, f.description,
                    f.severity, f.status, f.risk_score, f.risk_band, f.risk_factors,
                    t.tool_key, t.tool_name, t.tool_type, f.external_id, f.rule_id,
                    f.category, f.confidence, f.provider, f.organization, f.project,
                    f.repository, f.branch, f.path, f.start_line, f.end_line,
                    f.scanner_url, f.remediation, f.package_name, f.package_version,
                    f.fixed_version, f.cvss_score, f.epss_score, f.exploit_available,
                    f.assignee, f.due_at, f.first_seen, f.last_seen, f.resolved_at,
                    f.branch_inventory_id,
                    COALESCE(b.inventory_name, b.mobile_name, f.repository, 'Unlinked finding') AS application,
                    COALESCE(types.inventory_types, '') AS application_types,
                    COALESCE(domains.primary_web_domain, '') AS primary_web_domain,
                    COALESCE(ids.cwes, '') AS cwes,
                    COALESCE(ids.cves, '') AS cves,
                    r.web_url AS repository_url
                FROM {findings} f
                JOIN {tools} t ON t.tool_id = f.tool_id
                LEFT JOIN {branches} b ON b.branch_inventory_id = f.branch_inventory_id
                LEFT JOIN {repositories} r ON r.repository_id = b.repository_id
                LEFT JOIN LATERAL (
                    SELECT string_agg(inventory_type, '; ' ORDER BY inventory_type) AS inventory_types
                    FROM {types} WHERE branch_inventory_id = b.branch_inventory_id
                ) types ON true
                LEFT JOIN LATERAL (
                    SELECT max(domain) FILTER (WHERE is_primary) AS primary_web_domain
                    FROM {domains} WHERE branch_inventory_id = b.branch_inventory_id
                ) domains ON true
                LEFT JOIN LATERAL (
                    SELECT
                        string_agg(identifier, '; ' ORDER BY identifier) FILTER (WHERE identifier_type = 'cwe') AS cwes,
                        string_agg(identifier, '; ' ORDER BY identifier) FILTER (WHERE identifier_type = 'cve') AS cves
                    FROM {identifiers} WHERE finding_id = f.finding_id
                ) ids ON true
            )
            """
        ).format(
            findings=self._table("aspm_findings"),
            tools=self._table("aspm_tools"),
            branches=self._table("branch_inventory"),
            repositories=self._table("repositories"),
            types=self._table("inventory_types"),
            domains=self._table("web_domains"),
            identifiers=self._table("aspm_finding_identifiers"),
        )

    def _table(self, name: str) -> Any:
        return identifier(self.schema, name)


def normalize_finding_filters(filters: dict[str, Any] | None) -> dict[str, Any]:
    value = filters if isinstance(filters, dict) else {}
    normalized: dict[str, Any] = {}
    for key in ("severities", "statuses", "risk_bands", "tools", "tool_types"):
        items = value.get(key, [])
        normalized[key] = (
            sorted(
                {
                    bounded_text(item, 200).lower()
                    for item in items
                    if bounded_text(item, 200)
                }
            )
            if isinstance(items, list)
            else []
        )
    for key in ("finding_id", "repository", "assignee"):
        normalized[key] = bounded_text(value.get(key), 500)
    for key in ("overdue", "unassigned", "has_asset"):
        normalized[key] = value.get(key) if isinstance(value.get(key), bool) else None
    sort_by = bounded_text(value.get("sort_by"), 50)
    normalized["sort_by"] = (
        sort_by
        if sort_by
        in {"risk", "severity", "updated", "due", "application", "tool", "status"}
        else "risk"
    )
    normalized["sort_direction"] = (
        "asc"
        if bounded_text(value.get("sort_direction"), 10).lower() == "asc"
        else "desc"
    )
    return normalized


def finding_order(filters: dict[str, Any]) -> Any:
    expressions = {
        "risk": sql.SQL("f.risk_score"),
        "severity": sql.SQL(
            "CASE f.severity WHEN 'critical' THEN 5 WHEN 'high' THEN 4 WHEN 'medium' THEN 3 WHEN 'low' THEN 2 ELSE 1 END"
        ),
        "updated": sql.SQL("f.last_seen"),
        "due": sql.SQL("f.due_at"),
        "application": sql.SQL("lower(f.application)"),
        "tool": sql.SQL("lower(f.tool_name)"),
        "status": sql.SQL("f.status"),
    }
    direction = (
        sql.SQL("ASC") if filters["sort_direction"] == "asc" else sql.SQL("DESC")
    )
    return sql.SQL(
        "{expression} {direction} NULLS LAST, f.last_seen DESC, f.finding_id"
    ).format(expression=expressions[filters["sort_by"]], direction=direction)


def severity_sla_days(severity: str) -> int:
    return {
        "critical": 7,
        "high": 30,
        "medium": 90,
        "low": 180,
        "info": 365,
    }.get(severity, 90)


def schema_name(value: str) -> str:
    resolved = bounded_text(value, 63)
    if not SQL_NAME_RE.fullmatch(resolved):
        raise ValueError("PostgreSQL schema must be a valid SQL identifier.")
    return resolved


def identifier(schema: str, name: str) -> Any:
    return sql.Identifier(schema_name(schema), name)


def escape_like(value: str) -> str:
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def json_rows(rows: Any) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for row in rows:
        item = dict(row)
        for key, value in tuple(item.items()):
            if isinstance(value, datetime):
                item[key] = value.isoformat()
            elif hasattr(value, "isoformat"):
                item[key] = value.isoformat()
            elif hasattr(value, "__float__") and value.__class__.__name__ == "Decimal":
                item[key] = float(value)
        result.append(item)
    return result
