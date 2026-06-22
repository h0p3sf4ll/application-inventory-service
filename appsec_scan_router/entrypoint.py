from __future__ import annotations

import os
import sys


def main() -> int:
    args = sys.argv[1:]
    if not args:
        exec_module("appsec_scan_router", ["--help"])
    first = args[0]
    if first == "ui":
        exec_callable("appsec_scan_router.ui", "main", args[1:])
    if first == "cli":
        exec_module("appsec_scan_router", args[1:])
    if first.startswith("-"):
        exec_module("appsec_scan_router", args)
    os.execvp(first, args)
    return 0


def exec_module(module: str, args: list[str]) -> None:
    os.execv(sys.executable, [sys.executable, "-m", module, *args])


def exec_callable(module: str, function: str, args: list[str]) -> None:
    code = f"from {module} import {function}; raise SystemExit({function}())"
    os.execv(sys.executable, [sys.executable, "-c", code, *args])
