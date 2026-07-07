from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

from .models import ScanConfig
from .scanner import scan, scan_to_reports


class ApplicationInventoryService:
    def __init__(self, config: ScanConfig) -> None:
        self.config = config

    def scan(self, on_result: Callable[[dict[str, Any]], None] | None = None) -> list[dict[str, Any]]:
        return scan(self.config, on_result=on_result)

    def scan_to_reports(self) -> tuple[list[dict[str, Any]], Path, Path, Path]:
        return scan_to_reports(self.config)


AppSecInventoryService = ApplicationInventoryService
AppSecScanRouter = ApplicationInventoryService
