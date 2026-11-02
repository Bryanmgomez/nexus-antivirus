from __future__ import annotations

import logging
import os
import secrets
from pathlib import Path
from typing import Callable

from ..util import is_reparse_point, normalize_path

log = logging.getLogger(__name__)
CHUNK = 1024 * 1024
PROTECTED_PREFIXES = (
    "c:\\windows",
    "c:\\program files",
    "c:\\program files (x86)",
    "c:\\programdata\\microsoft",
    "c:\\$recycle.bin",
    "c:\\system volume information",
)


class ShredError(RuntimeError):
    pass


def _validate(path: str) -> Path:
    target = Path(path)
    if not target.exists():
        raise ShredError("El archivo no existe.")
    if target.is_dir():
        raise ShredError("El destructor seguro solo acepta archivos, no carpetas.")
    if is_reparse_point(target):
        raise ShredError("No se permiten enlaces simbolicos o puntos de reanalisis.")
    normalized = normalize_path(target)
    if any(normalized == prefix or normalized.startswith(prefix + "\\") for prefix in PROTECTED_PREFIXES):
        raise ShredError("Por seguridad no se destruyen archivos de sistema o programas instalados.")
    return target


def secure_delete(
    path: str,
    passes: int = 3,
    progress_cb: Callable[[int, int], None] | None = None,
) -> None:
    """Sobrescribe un archivo con datos aleatorios, lo renombra y lo elimina.

    En SSD con wear leveling o sistemas con journaling/copias, la garantia fisica
    no es absoluta. Se documenta esta limitacion en la interfaz.
    """
    target = _validate(path)
    passes = max(1, min(7, int(passes)))
    try:
        size = target.stat().st_size
        os.chmod(target, 0o600)
        with open(target, "r+b", buffering=0) as handle:
            for pass_index in range(passes):
                handle.seek(0)
                remaining = size
                while remaining > 0:
                    block = os.urandom(min(CHUNK, remaining))
                    handle.write(block)
                    remaining -= len(block)
                handle.flush()
                os.fsync(handle.fileno())
                if progress_cb:
                    progress_cb(pass_index + 1, passes)
        random_name = target.with_name(f".{secrets.token_hex(12)}.deleted")
        os.replace(target, random_name)
        os.unlink(random_name)
        log.warning("Archivo destruido de forma segura: %s", target)
    except OSError as exc:
        raise ShredError(f"No se pudo destruir el archivo: {exc}") from exc
