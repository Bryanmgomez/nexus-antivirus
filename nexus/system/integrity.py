from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass, field
from pathlib import Path

from ..models import SystemCheck
from ..paths import data_dir
from ..util import atomic_write_bytes, hash_file, utc_now
from .inventory import list_services, list_startup_entries, system_checks

log = logging.getLogger(__name__)


@dataclass(slots=True)
class IntegrityDiff:
    baseline_created: str = ""
    changed_files: list[str] = field(default_factory=list)
    added_startup: list[str] = field(default_factory=list)
    removed_startup: list[str] = field(default_factory=list)
    changed_services: list[str] = field(default_factory=list)
    checks: list[SystemCheck] = field(default_factory=list)

    @property
    def has_changes(self) -> bool:
        return bool(self.changed_files or self.added_startup or self.removed_startup or self.changed_services)


def _baseline_path() -> Path:
    return data_dir() / "integrity_baseline.json"


def _critical_files() -> list[str]:
    if os.name != "nt":
        return []
    windows = os.environ.get("WINDIR", "C:\\Windows")
    return [
        str(Path(windows) / "System32" / "drivers" / "etc" / "hosts"),
        str(Path(windows) / "win.ini"),
        str(Path(windows) / "System32" / "drivers" / "etc" / "networks"),
    ]


def _snapshot() -> dict:
    files: dict[str, str] = {}
    for path in _critical_files():
        if os.path.isfile(path):
            try:
                files[path] = hash_file(path).get("sha256", "")
            except OSError:
                continue
    return {
        "created_at": utc_now(),
        "files": files,
        "startup": [
            {"source": item.source, "name": item.name, "command": item.command}
            for item in list_startup_entries()
        ],
        "services": [
            {
                "name": item.name,
                "status": item.status,
                "start_type": item.start_type,
                "binary_path": item.binary_path,
            }
            for item in list_services()
        ],
    }


def create_baseline() -> Path:
    snapshot = _snapshot()
    target = _baseline_path()
    atomic_write_bytes(
        target,
        json.dumps(snapshot, ensure_ascii=False, indent=2).encode("utf-8"),
    )
    log.info("Linea base de integridad creada en %s", target)
    return target


def compare_baseline() -> IntegrityDiff:
    target = _baseline_path()
    diff = IntegrityDiff()
    if not target.is_file():
        diff.checks.append(
            SystemCheck(
                key="integrity",
                title="Linea base de integridad",
                status="unknown",
                detail="No existe. Cree una linea base para detectar cambios futuros.",
                severity="medium",
            )
        )
        return diff
    try:
        baseline = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        diff.checks.append(
            SystemCheck(
                key="integrity",
                title="Linea base de integridad",
                status="warning",
                detail=f"No se pudo leer la linea base: {exc}",
                severity="medium",
            )
        )
        return diff
    diff.baseline_created = str(baseline.get("created_at", ""))
    current_files = _snapshot()["files"]
    old_files = baseline.get("files", {})
    for path, old_hash in old_files.items():
        new_hash = current_files.get(path)
        if new_hash != old_hash:
            diff.changed_files.append(path)
    current_startup = {
        (item.get("source"), item.get("name")): item.get("command")
        for item in baseline.get("startup", [])
        if isinstance(item, dict)
    }
    live_startup = {
        (item.source, item.name): item.command for item in list_startup_entries()
    }
    for key, command in live_startup.items():
        if key not in current_startup:
            diff.added_startup.append(f"{key[0]}: {key[1]}")
        elif current_startup[key] != command:
            diff.added_startup.append(f"{key[0]}: {key[1]} (comando modificado)")
    for key in current_startup:
        if key not in live_startup:
            diff.removed_startup.append(f"{key[0]}: {key[1]}")
    old_services = {
        item.get("name"): item
        for item in baseline.get("services", [])
        if isinstance(item, dict)
    }
    live_services = {item.name: item for item in list_services()}
    for name, service in live_services.items():
        previous = old_services.get(name)
        if previous and (
            previous.get("binary_path") != service.binary_path
            or previous.get("start_type") != service.start_type
        ):
            diff.changed_services.append(name)
    diff.checks.append(
        SystemCheck(
            key="integrity",
            title="Integridad del sistema",
            status="warning" if diff.has_changes else "ok",
            detail=(
                f"Cambios desde {diff.baseline_created}."
                if diff.has_changes
                else f"Sin cambios desde {diff.baseline_created}."
            ),
            severity="high" if diff.has_changes else "info",
        )
    )
    return diff


def integrity_status() -> list[SystemCheck]:
    checks = compare_baseline().checks
    checks.extend(system_checks())
    return checks
