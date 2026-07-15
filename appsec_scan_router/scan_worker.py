from __future__ import annotations

import argparse
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from .scan_persistence import write_private_json


def run(command: list[str], completion_file: Path) -> int:
    exit_code = 1
    error = ""
    try:
        exit_code = subprocess.run(command, check=False).returncode
    except FileNotFoundError as exc:
        exit_code = 127
        error = str(exc)
        print(error, file=sys.stderr, flush=True)
    except Exception as exc:
        error = str(exc)
        print(error, file=sys.stderr, flush=True)
    write_private_json(
        completion_file,
        {
            "exitCode": exit_code,
            "endedAt": datetime.now(timezone.utc).isoformat(),
            "error": error,
        },
    )
    return exit_code


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--completion-file", required=True)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    if args.command and args.command[0] == "--":
        args.command = args.command[1:]
    if not args.command:
        parser.error("scan command is required")
    return args


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    return run(args.command, Path(args.completion_file))


if __name__ == "__main__":
    raise SystemExit(main())
