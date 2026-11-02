from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any

from . import paths
from .database import Database

log = logging.getLogger(__name__)


def default_watch_folders() -> list[str]:
    home = Path.home()
    candidates = [
        home / "Desktop",
        home / "Downloads",
        home / "Documents",
        Path(os.environ.get("PUBLIC", "C:\\Users\\Public")) / "Downloads",
    ]
    return [str(path) for path in candidates if path.is_dir()]


def default_exclusions() -> list[str]:
    local = os.environ.get("LOCALAPPDATA")
    values = [
        str(paths.data_dir()),
        str(paths.bundled_definitions_dir()),
        "C:\\$Recycle.Bin",
        "C:\\System Volume Information",
        "C:\\Windows\\WinSxS",
        "C:\\Windows\\Prefetch",
    ]
    if local:
        values.append(str(Path(local) / "NexusAntivirus"))
    return values


DEFAULTS: dict[str, str] = {
    "realtime_enabled": "0",
    "autostart_enabled": "0",
    "auto_quarantine": "1",
    "ransomware_enabled": "1",
    "ransomware_window_seconds": "10",
    "ransomware_file_threshold": "30",
    "usb_scan_enabled": "1",
    "notifications_enabled": "1",
    "clamav_enabled": "1",
    "clamav_path": "",
    "yara_enabled": "1",
    "heuristics_enabled": "1",
    "max_file_size_mb": "256",
    "update_url": "",
    "update_public_key": "",
    "vt_api_key": "",
    "last_update": "",
    "last_scan": "",
    "last_full_scan": "",
    "watch_folders": "",
    "excluded_paths": "",
    "backup_folders": "",
    "start_minimized": "0",
    "theme": "nexus-dark",
}


class Settings:
    def __init__(self, db: Database):
        self.db = db
        self._ensure_defaults()

    def _ensure_defaults(self) -> None:
        for key, value in DEFAULTS.items():
            if self.db.get_setting(key) is None:
                self.db.set_setting(key, value)
        if self.db.get_setting("watch_folders") in (None, ""):
            self.set_list("watch_folders", default_watch_folders())
        if self.db.get_setting("excluded_paths") in (None, ""):
            self.set_list("excluded_paths", default_exclusions())
        if self.db.get_setting("backup_folders") in (None, ""):
            self.set_list("backup_folders", [])

    def get(self, key: str, default: Any = None) -> str:
        value = self.db.get_setting(key)
        if value is None:
            return str(default) if default is not None else ""
        return value

    def set(self, key: str, value: Any) -> None:
        if isinstance(value, bool):
            value = "1" if value else "0"
        self.db.set_setting(key, str(value))
        log.debug("Configuracion actualizada: %s", key)

    def get_bool(self, key: str, default: bool = False) -> bool:
        value = self.db.get_setting(key)
        if value is None:
            return default
        return value.strip().lower() in {"1", "true", "yes", "on"}

    def set_bool(self, key: str, value: bool) -> None:
        self.set(key, "1" if value else "0")

    def get_int(self, key: str, default: int = 0) -> int:
        try:
            return int(self.get(key, default))
        except (TypeError, ValueError):
            return default

    def get_list(self, key: str, default: list[str] | None = None) -> list[str]:
        raw = self.db.get_setting(key)
        if raw is None or raw == "":
            return list(default or [])
        try:
            value = json.loads(raw)
        except json.JSONDecodeError:
            return list(default or [])
        if not isinstance(value, list):
            return list(default or [])
        return [str(item) for item in value]

    def set_list(self, key: str, values: list[str]) -> None:
        self.set(key, json.dumps(values, ensure_ascii=False))

    @property
    def watch_folders(self) -> list[str]:
        return self.get_list("watch_folders")

    @property
    def excluded_paths(self) -> list[str]:
        return self.get_list("excluded_paths")

    @property
    def max_file_size(self) -> int:
        return max(1, self.get_int("max_file_size_mb", 256)) * 1024 * 1024

    @property
    def ransomware_threshold(self) -> int:
        return max(5, self.get_int("ransomware_file_threshold", 30))

    @property
    def ransomware_window(self) -> int:
        return max(2, self.get_int("ransomware_window_seconds", 10))
