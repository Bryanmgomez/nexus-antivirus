from __future__ import annotations

import json
import logging
import os
import tempfile
import uuid
import zipfile
from datetime import datetime
from pathlib import Path
from typing import Callable

from ..paths import backups_dir, data_dir
from ..util import is_within, iter_files, normalize_path, utc_now

log = logging.getLogger(__name__)
MAX_BACKUP_BYTES = 4 * 1024 * 1024 * 1024
CHUNK = 1024 * 1024


class BackupError(RuntimeError):
    pass


def create_backup(
    folder: str,
    progress_cb: Callable[[int, int, str], None] | None = None,
    max_bytes: int = MAX_BACKUP_BYTES,
) -> Path:
    source = Path(folder)
    if not source.is_dir():
        raise BackupError("La carpeta seleccionada no existe.")
    files = list(iter_files([source], excluded=[data_dir()]))
    total = sum(size for _, size in files)
    if total > max_bytes:
        raise BackupError(
            f"La copia supera el limite de {max_bytes // (1024**3)} GB. Seleccione una carpeta menor."
        )
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    name = f"backup-{source.name or 'unidad'}-{timestamp}-{uuid.uuid4().hex[:6]}.zip"
    target = backups_dir() / name
    manifest = {
        "created_at": utc_now(),
        "source": str(source),
        "files": len(files),
        "bytes": total,
    }
    try:
        with zipfile.ZipFile(target, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
            archive.writestr("nexus-backup-manifest.json", json.dumps(manifest, ensure_ascii=False, indent=2))
            for index, (path, _size) in enumerate(files, start=1):
                try:
                    relative = os.path.relpath(path, source)
                    archive.write(path, arcname=relative)
                except (OSError, ValueError):
                    continue
                if progress_cb:
                    progress_cb(index, len(files), path)
    except (OSError, zipfile.BadZipFile) as exc:
        try:
            target.unlink(missing_ok=True)
        except OSError:
            pass
        raise BackupError(f"No se pudo crear la copia: {exc}") from exc
    log.info("Copia de seguridad creada: %s", target)
    return target


def list_backups() -> list[dict]:
    result: list[dict] = []
    for path in sorted(backups_dir().glob("*.zip"), key=lambda item: item.stat().st_mtime, reverse=True):
        try:
            with zipfile.ZipFile(path) as archive:
                manifest = {}
                if "nexus-backup-manifest.json" in archive.namelist():
                    manifest = json.loads(archive.read("nexus-backup-manifest.json").decode("utf-8"))
                result.append(
                    {
                        "path": str(path),
                        "name": path.name,
                        "size": path.stat().st_size,
                        "created_at": manifest.get("created_at", ""),
                        "source": manifest.get("source", ""),
                        "files": manifest.get("files", 0),
                    }
                )
        except (OSError, zipfile.BadZipFile, json.JSONDecodeError):
            continue
    return result


def restore_backup(
    archive_path: str,
    destination: str,
    progress_cb: Callable[[int, int, str], None] | None = None,
) -> int:
    archive_file = Path(archive_path)
    target_root = Path(destination)
    if not archive_file.is_file():
        raise BackupError("La copia de seguridad no existe.")
    if not target_root.is_dir():
        raise BackupError("La carpeta de destino no existe.")
    restored = 0
    try:
        with zipfile.ZipFile(archive_file) as archive:
            members = [item for item in archive.infolist() if not item.is_dir()]
            for index, member in enumerate(members, start=1):
                name = member.filename.replace("\\", "/")
                if name == "nexus-backup-manifest.json":
                    continue
                if name.startswith("/") or ".." in Path(name).parts:
                    continue
                destination_path = target_root / name
                destination_path.parent.mkdir(parents=True, exist_ok=True)
                if destination_path.exists():
                    stem, suffix = destination_path.stem, destination_path.suffix
                    for counter in range(1, 10000):
                        candidate = destination_path.with_name(f"{stem} (restaurado {counter}){suffix}")
                        if not candidate.exists():
                            destination_path = candidate
                            break
                with archive.open(member) as source, open(destination_path, "wb") as output:
                    while True:
                        chunk = source.read(CHUNK)
                        if not chunk:
                            break
                        output.write(chunk)
                restored += 1
                if progress_cb:
                    progress_cb(index, len(members), member.filename)
    except (OSError, zipfile.BadZipFile) as exc:
        raise BackupError(f"No se pudo restaurar la copia: {exc}") from exc
    log.info("Copia restaurada en %s (%d archivos)", target_root, restored)
    return restored
