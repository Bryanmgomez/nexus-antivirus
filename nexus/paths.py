from __future__ import annotations

import os
import sys
from pathlib import Path

APP_NAME = "NEXUS ANTIVIRUS"
APP_SLUG = "NexusAntivirus"
APP_VERSION = "1.0.0"


def bundle_root() -> Path:
    """Directorio de solo lectura con los recursos empaquetados."""
    if getattr(sys, "frozen", False):
        return Path(getattr(sys, "_MEIPASS", Path(sys.executable).parent))
    return Path(__file__).resolve().parent.parent


def data_dir() -> Path:
    override = os.environ.get("NEXUS_DATA_DIR")
    if override:
        base = Path(override).expanduser().resolve()
    elif os.name == "nt":
        base = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local")) / APP_SLUG
    else:
        base = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share")) / APP_SLUG
    base.mkdir(parents=True, exist_ok=True)
    return base


def definitions_dir() -> Path:
    """Definiciones actualizadas por el usuario; tienen prioridad sobre las incluidas."""
    path = data_dir() / "definitions"
    path.mkdir(parents=True, exist_ok=True)
    return path


def bundled_definitions_dir() -> Path:
    return bundle_root() / "definitions"


def active_definitions_dir() -> Path:
    user_file = definitions_dir() / "signatures.json"
    if user_file.is_file():
        return definitions_dir()
    return bundled_definitions_dir()


def active_yara_file() -> Path:
    user_rules = definitions_dir() / "yara" / "nexus_rules.yar"
    if user_rules.is_file():
        return user_rules
    return bundled_definitions_dir() / "yara" / "nexus_rules.yar"


def public_key_path() -> Path:
    user_key = definitions_dir() / "update_public_key.pem"
    if user_key.is_file():
        return user_key
    return bundled_definitions_dir() / "update_public_key.pem"


def quarantine_dir() -> Path:
    path = data_dir() / "quarantine"
    path.mkdir(parents=True, exist_ok=True)
    return path


def logs_dir() -> Path:
    path = data_dir() / "logs"
    path.mkdir(parents=True, exist_ok=True)
    return path


def backups_dir() -> Path:
    path = data_dir() / "backups"
    path.mkdir(parents=True, exist_ok=True)
    return path


def reports_dir() -> Path:
    path = data_dir() / "reports"
    path.mkdir(parents=True, exist_ok=True)
    return path


def cache_dir() -> Path:
    path = data_dir() / "cache"
    path.mkdir(parents=True, exist_ok=True)
    return path


def database_path() -> Path:
    return data_dir() / "nexus.db"


def ensure_directories() -> None:
    for path in (
        data_dir(),
        definitions_dir(),
        quarantine_dir(),
        logs_dir(),
        backups_dir(),
        reports_dir(),
        cache_dir(),
    ):
        path.mkdir(parents=True, exist_ok=True)
