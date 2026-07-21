from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from .aspm_ingest import SUPPORTED_FINDING_FORMATS
from .aspm_models import FindingSeverity, FindingStatus, bounded_text
from .constants import DEFAULT_POSTGRES_SCHEMA
from .sdk import AspmService


DEFAULT_ASPM_DSN = "postgresql://postgres:postgres@localhost:5432/postgres"
DEFAULT_IMPORT_LIMIT_BYTES = 256 * 1024 * 1024


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="application-inventory-aspm",
        description="Ingest, prioritize, query, and manage application security findings.",
    )
    parser.add_argument(
        "--postgres-dsn",
        default=os.getenv("APPLICATION_INVENTORY_POSTGRES_DSN", DEFAULT_ASPM_DSN),
        help="PostgreSQL DSN. Prefer APPLICATION_INVENTORY_POSTGRES_DSN.",
    )
    parser.add_argument(
        "--postgres-schema",
        default=os.getenv(
            "APPLICATION_INVENTORY_POSTGRES_SCHEMA", DEFAULT_POSTGRES_SCHEMA
        ),
    )
    parser.add_argument(
        "--owner-user-id",
        default=os.getenv("APPLICATION_INVENTORY_OWNER_USER_ID", "cli"),
        help="Stable owner scope for inventory and findings.",
    )
    parser.add_argument(
        "--owner-user-login",
        default=os.getenv("APPLICATION_INVENTORY_OWNER_USER_LOGIN", ""),
        help="Actor identity recorded in workflow events.",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    add_ingest_parser(commands)
    add_findings_parser(commands)
    add_update_parser(commands)
    add_profile_parser(commands)
    commands.add_parser("posture", help="Show the current security posture.")
    coverage = commands.add_parser(
        "coverage", help="List application scanner coverage."
    )
    coverage.add_argument("--limit", type=positive_int, default=100)
    coverage.add_argument("--offset", type=nonnegative_int, default=0)
    return parser


def add_ingest_parser(commands: Any) -> None:
    ingest = commands.add_parser("ingest", help="Import scanner findings.")
    ingest.add_argument("file", type=Path)
    ingest.add_argument("--format", choices=SUPPORTED_FINDING_FORMATS, default="auto")
    ingest.add_argument("--tool-key", default="")
    ingest.add_argument("--tool-name", default="")
    ingest.add_argument("--tool-type", default="")
    ingest.add_argument("--provider", default="")
    ingest.add_argument("--organization", default="")
    ingest.add_argument("--project", default="")
    ingest.add_argument("--repository", default="")
    ingest.add_argument("--branch", default="")
    ingest.add_argument("--complete-snapshot", action="store_true")


def add_findings_parser(commands: Any) -> None:
    findings = commands.add_parser("findings", help="Search or export findings.")
    findings.add_argument("--query", default="")
    findings.add_argument(
        "--severity", action="append", choices=[item.value for item in FindingSeverity]
    )
    findings.add_argument(
        "--status", action="append", choices=[item.value for item in FindingStatus]
    )
    findings.add_argument(
        "--risk-band", action="append", choices=("low", "medium", "high", "critical")
    )
    findings.add_argument("--tool", action="append")
    findings.add_argument("--repository", default="")
    findings.add_argument("--assignee", default="")
    findings.add_argument("--overdue", action="store_true")
    findings.add_argument("--unassigned", action="store_true")
    findings.add_argument("--unlinked", action="store_true")
    findings.add_argument("--limit", type=positive_int, default=100)
    findings.add_argument("--offset", type=nonnegative_int, default=0)
    findings.add_argument("--export", choices=("xlsx", "csv", "json"))
    findings.add_argument("--output", type=Path)


def add_update_parser(commands: Any) -> None:
    update = commands.add_parser("update", help="Update finding workflow.")
    update.add_argument("finding_id")
    update.add_argument(
        "--status", required=True, choices=[item.value for item in FindingStatus]
    )
    update.add_argument("--assignee", default="")
    update.add_argument("--due-at", default="")
    update.add_argument("--note", default="")


def add_profile_parser(commands: Any) -> None:
    profile = commands.add_parser(
        "profile", help="Read or update application security context."
    )
    profile.add_argument("branch_inventory_id", type=positive_int)
    profile.add_argument(
        "--criticality", choices=("low", "medium", "high", "mission_critical")
    )
    profile.add_argument("--internet-exposure", choices=("auto", "true", "false"))
    profile.add_argument(
        "--data-classification",
        choices=("public", "internal", "confidential", "restricted"),
    )
    profile.add_argument("--business-owner")
    profile.add_argument("--technical-owner")
    profile.add_argument("--tag", action="append")


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        service = AspmService(
            args.postgres_dsn,
            args.postgres_schema,
            args.owner_user_id,
            args.owner_user_login,
        )
        result = execute(service, args, parser)
        if result is not None:
            write_json(result)
        return 0
    except (OSError, ValueError, KeyError, RuntimeError) as exc:
        message = str(exc).strip("'")
        parser.exit(2, f"error: {message}\n")
    return 2


def execute(
    service: AspmService, args: argparse.Namespace, parser: argparse.ArgumentParser
) -> dict[str, Any] | None:
    if args.command == "ingest":
        return service.ingest(ingest_payload(args))
    if args.command == "posture":
        return service.posture()
    if args.command == "coverage":
        return service.coverage(limit=args.limit, offset=args.offset)
    if args.command == "update":
        return service.update_finding(
            args.finding_id,
            args.status,
            assignee=args.assignee,
            due_at=args.due_at or None,
            note=args.note,
        )
    if args.command == "profile":
        profile = profile_payload(args)
        if not profile:
            return service.asset_profile(args.branch_inventory_id)
        current = service.asset_profile(args.branch_inventory_id)
        merged = {
            "criticality": current["criticality"],
            "internetExposed": current["internet_exposed"],
            "dataClassification": current["data_classification"],
            "businessOwner": current["business_owner"],
            "technicalOwner": current["technical_owner"],
            "tags": current["tags"],
            **profile,
        }
        return service.update_asset_profile(args.branch_inventory_id, merged)
    if args.command == "findings":
        filters = finding_filters(args)
        if args.export:
            destination = args.output or Path(f"aspm_findings_export.{args.export}")
            content = service.export_findings(
                args.export, query=args.query, filters=filters
            )
            destination.write_bytes(content)
            destination.chmod(0o600)
            return {
                "format": args.export,
                "output": str(destination),
                "bytes": len(content),
            }
        if args.output:
            parser.error("--output requires --export.")
        return service.findings(
            query=args.query,
            filters=filters,
            limit=args.limit,
            offset=args.offset,
        )
    parser.error("An ASPM command is required.")
    return None


def ingest_payload(args: argparse.Namespace) -> dict[str, Any]:
    limit = positive_environment_int(
        "APPLICATION_INVENTORY_ASPM_CLI_MAX_IMPORT_BYTES", DEFAULT_IMPORT_LIMIT_BYTES
    )
    size = args.file.stat().st_size
    if size > limit:
        raise ValueError(f"Scanner input exceeds the {limit:,}-byte CLI limit.")
    loaded = json.loads(args.file.read_text(encoding="utf-8"))
    if isinstance(loaded, Mapping) and ("document" in loaded or "findings" in loaded):
        payload = dict(loaded)
        payload.setdefault("format", args.format)
    else:
        payload = {"format": args.format, "document": loaded}
    context = {
        key: bounded_text(getattr(args, key), 2000)
        for key in ("provider", "organization", "project", "repository", "branch")
        if bounded_text(getattr(args, key), 2000)
    }
    if context:
        payload["context"] = {**mapping_value(payload.get("context")), **context}
    if args.tool_key or args.tool_name or args.tool_type:
        payload["tool"] = {
            **mapping_value(payload.get("tool")),
            **{
                key: value
                for key, value in {
                    "key": args.tool_key,
                    "name": args.tool_name,
                    "type": args.tool_type,
                }.items()
                if value
            },
        }
    if args.complete_snapshot:
        payload["completeSnapshot"] = True
        target = mapping_value(payload.get("context"))
        if target.get("repository") and not payload.get("scannedTargets"):
            payload["scannedTargets"] = [target]
    return payload


def finding_filters(args: argparse.Namespace) -> dict[str, Any]:
    return {
        "severities": args.severity or [],
        "statuses": args.status or [],
        "risk_bands": args.risk_band or [],
        "tools": args.tool or [],
        "repository": args.repository,
        "assignee": args.assignee,
        "overdue": True if args.overdue else None,
        "unassigned": True if args.unassigned else None,
        "has_asset": False if args.unlinked else None,
    }


def profile_payload(args: argparse.Namespace) -> dict[str, Any]:
    values: dict[str, Any] = {}
    for argument, field in (
        ("criticality", "criticality"),
        ("data_classification", "dataClassification"),
        ("business_owner", "businessOwner"),
        ("technical_owner", "technicalOwner"),
    ):
        value = getattr(args, argument)
        if value is not None:
            values[field] = value
    if args.internet_exposure is not None:
        values["internetExposed"] = {
            "auto": None,
            "true": True,
            "false": False,
        }[args.internet_exposure]
    if args.tag is not None:
        values["tags"] = args.tag
    return values


def mapping_value(value: Any) -> dict[str, Any]:
    return dict(value) if isinstance(value, Mapping) else {}


def positive_int(value: str) -> int:
    parsed = int(value)
    if parsed < 1:
        raise argparse.ArgumentTypeError("value must be greater than zero")
    return parsed


def nonnegative_int(value: str) -> int:
    parsed = int(value)
    if parsed < 0:
        raise argparse.ArgumentTypeError("value must be zero or greater")
    return parsed


def positive_environment_int(name: str, default: int) -> int:
    try:
        value = int(os.getenv(name, str(default)))
    except ValueError:
        return default
    return value if value > 0 else default


def write_json(value: Any) -> None:
    json.dump(value, sys.stdout, ensure_ascii=True, indent=2, default=str)
    sys.stdout.write("\n")


if __name__ == "__main__":
    raise SystemExit(main())
