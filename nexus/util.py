from __future__ import annotations

import hashlib
import os
import re
import stat
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Iterator

CHUNK_SIZE = 4 * 1024 * 1024


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def local_now_display(value: str | None) -> str:
    if not value:
        return "Nunca"
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone().strftime("%d/%m/%Y %H:%M")
    except (ValueError, OSError):
        return value


def format_bytes(size: int | float) -> str:
    value = float(max(0, size))
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024.0 or unit == "TB":
            return f"{value:.1f} {unit}" if unit != "B" else f"{int(value)} B"
        value /= 1024.0
    return f"{value:.1f} TB"


def format_duration(seconds: float) -> str:
    seconds = max(0, int(seconds))
    hours, remainder = divmod(seconds, 3600)
    minutes, secs = divmod(remainder, 60)
    if hours:
        return f"{hours:02d}:{minutes:02d}:{secs:02d}"
    return f"{minutes:02d}:{secs:02d}"


def normalize_path(path: str | os.PathLike[str]) -> str:
    return os.path.normcase(os.path.abspath(os.path.expandvars(os.path.expanduser(str(path)))))


def is_within(path: str | os.PathLike[str], parent: str | os.PathLike[str]) -> bool:
    try:
        return os.path.commonpath([normalize_path(path), normalize_path(parent)]) == normalize_path(parent)
    except (ValueError, OSError):
        return False


def is_reparse_point(path: str | os.PathLike[str]) -> bool:
    try:
        attrs = os.lstat(path).st_file_attributes  # type: ignore[attr-defined]
    except (AttributeError, OSError):
        return os.path.islink(path)
    return bool(attrs & stat.FILE_ATTRIBUTE_REPARSE_POINT)


def hash_file(path: str | os.PathLike[str], algorithms: Iterable[str] = ("sha256",)) -> dict[str, str]:
    hashers = {name: hashlib.new(name) for name in algorithms}
    with open(path, "rb") as handle:
        while True:
            chunk = handle.read(CHUNK_SIZE)
            if not chunk:
                break
            for hasher in hashers.values():
                hasher.update(chunk)
    return {name: hasher.hexdigest() for name, hasher in hashers.items()}


def iter_files(
    roots: Iterable[str | os.PathLike[str]],
    excluded: Iterable[str | os.PathLike[str]] = (),
    max_size: int | None = None,
) -> Iterator[tuple[str, int]]:
    """Recorre archivos accesibles sin seguir enlaces/reparse points."""
    excluded_norm = [normalize_path(p) for p in excluded]
    seen: set[str] = set()

    def ignored(path: str) -> bool:
        norm = normalize_path(path)
        if norm in seen:
            return True
        return any(is_within(norm, exc) for exc in excluded_norm)

    for root in roots:
        root_str = os.path.abspath(os.path.expandvars(os.path.expanduser(str(root))))
        if os.path.isfile(root_str):
            if not ignored(root_str):
                try:
                    size = os.path.getsize(root_str)
                except OSError:
                    continue
                if max_size is None or size <= max_size:
                    seen.add(normalize_path(root_str))
                    yield root_str, size
            continue
        if not os.path.isdir(root_str):
            continue
        stack = [root_str]
        while stack:
            current = stack.pop()
            if ignored(current):
                continue
            try:
                with os.scandir(current) as entries:
                    for entry in entries:
                        try:
                            if entry.is_dir(follow_symlinks=False):
                                if not ignored(entry.path) and not is_reparse_point(entry.path):
                                    stack.append(entry.path)
                            elif entry.is_file(follow_symlinks=False):
                                if ignored(entry.path):
                                    continue
                                size = entry.stat(follow_symlinks=False).st_size
                                if max_size is not None and size > max_size:
                                    continue
                                norm = normalize_path(entry.path)
                                if norm not in seen:
                                    seen.add(norm)
                                    yield entry.path, size
                        except (OSError, PermissionError):
                            continue
            except (OSError, PermissionError):
                continue


def unique_path(path: str | os.PathLike[str]) -> Path:
    target = Path(path)
    if not target.exists():
        return target
    stem, suffix = target.stem, target.suffix
    parent = target.parent
    for index in range(1, 10_000):
        candidate = parent / f"{stem} ({index}){suffix}"
        if not candidate.exists():
            return candidate
    raise FileExistsError(f"No se pudo encontrar un nombre libre para {target}")


def atomic_write_bytes(target: str | os.PathLike[str], data: bytes) -> None:
    target_path = Path(target)
    target_path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=f".{target_path.name}.", dir=str(target_path.parent))
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_name, target_path)
    except BaseException:
        try:
            os.unlink(temp_name)
        except OSError:
            pass
        raise


def safe_filename(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", value).strip("._")
    return cleaned[:120] or "archivo"


def parse_semver(value: str) -> tuple[int, ...]:
    parts = re.findall(r"\d+", value)
    return tuple(int(part) for part in parts[:5]) if parts else (0,)


def is_probably_text(data: bytes) -> bool:
    if not data:
        return False
    if b"\x00" in data[:4096]:
        return False
    printable = sum(1 for byte in data[:4096] if 9 <= byte <= 13 or 32 <= byte <= 126 or byte >= 160)
    return printable / min(len(data), 4096) > 0.85
