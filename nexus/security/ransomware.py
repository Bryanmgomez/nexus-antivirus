from __future__ import annotations

import logging
import os
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path

import psutil

from ..config import Settings
from ..util import utc_now

log = logging.getLogger(__name__)

RANSOM_EXTENSIONS = {
    ".locked", ".locky", ".encrypted", ".enc", ".crypt", ".crypto", ".crypted", ".wncry",
    ".wcry", ".ryk", ".ryuk", ".conti", ".revil", ".sodinokibi", ".djvu", ".phobos",
    ".makop", ".stop", ".basta", ".blackcat", ".alphv", ".clop", ".kann", ".karma",
}
RANSOM_NOTE_TOKENS = (
    "readme", "read_me", "recover", "restore", "decrypt", "recuperar", "descifrar",
    "how_to", "help_restore", "ransom", "bitcoin", "your_files",
)


@dataclass(slots=True)
class RansomAlert:
    timestamp: str
    files_in_window: int
    window_seconds: int
    severity: str
    reason: str
    sample_paths: list[str] = field(default_factory=list)
    candidate_processes: list[dict] = field(default_factory=list)


class RansomwareDetector:
    def __init__(self, settings: Settings, cooldown_seconds: int = 60):
        self.settings = settings
        self.cooldown_seconds = cooldown_seconds
        self._events: deque[tuple[float, str]] = deque()
        self._lock = threading.RLock()
        self._last_alert = 0.0
        self._last_note_alert: dict[str, float] = {}

    def configure(self, window_seconds: int | None = None, threshold: int | None = None) -> None:
        with self._lock:
            if window_seconds is not None:
                self.settings.set("ransomware_window_seconds", max(2, window_seconds))
            if threshold is not None:
                self.settings.set("ransomware_file_threshold", max(5, threshold))

    def record(self, path: str, operation: str = "modified") -> RansomAlert | None:
        if not self.settings.get_bool("ransomware_enabled", True):
            return None
        now = time.monotonic()
        window = self.settings.ransomware_window
        threshold = self.settings.ransomware_threshold
        with self._lock:
            self._events.append((now, path))
            while self._events and now - self._events[0][0] > window:
                self._events.popleft()
            count = len(self._events)
            note_path = self._is_ransom_note(path)
            if note_path:
                last = self._last_note_alert.get(path, 0.0)
                if now - last < 300:
                    note_path = False
                else:
                    self._last_note_alert[path] = now
            if now - self._last_alert < self.cooldown_seconds and not note_path:
                return None
            if count < threshold and not note_path:
                return None
            self._last_alert = now
            samples = [item[1] for item in list(self._events)[-12:]]
        reason = (
            "Nombre de archivo compatible con nota de rescate"
            if note_path
            else f"{count} modificaciones en {window} segundos"
        )
        severity = "critical" if note_path or count >= threshold * 2 else "high"
        alert = RansomAlert(
            timestamp=utc_now(),
            files_in_window=count,
            window_seconds=window,
            severity=severity,
            reason=reason,
            sample_paths=samples,
            candidate_processes=self._candidate_processes(),
        )
        log.warning("Alerta ransomware: %s", reason)
        return alert

    @staticmethod
    def _is_ransom_note(path: str) -> bool:
        name = os.path.basename(path).lower()
        suffix = Path(name).suffix.lower()
        if suffix in RANSOM_EXTENSIONS:
            return True
        return suffix in {".txt", ".html", ".htm", ".hta", ".rtf"} and any(
            token in name for token in RANSOM_NOTE_TOKENS
        )

    def _candidate_processes(self) -> list[dict]:
        try:
            first: dict[int, int] = {}
            for process in psutil.process_iter(["pid"]):
                try:
                    first[process.pid] = process.io_counters().write_bytes
                except (psutil.NoSuchProcess, psutil.AccessDenied, AttributeError, OSError):
                    continue
            time.sleep(0.4)
            rows: list[dict] = []
            for process in psutil.process_iter(["pid", "name", "exe"]):
                try:
                    delta = process.io_counters().write_bytes - first.get(process.pid, 0)
                except (psutil.NoSuchProcess, psutil.AccessDenied, AttributeError, OSError):
                    continue
                if delta <= 0:
                    continue
                try:
                    info = process.info
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
                rows.append(
                    {
                        "pid": process.pid,
                        "name": info.get("name") or "",
                        "exe": info.get("exe") or "",
                        "write_bytes": delta,
                    }
                )
            rows.sort(key=lambda row: row["write_bytes"], reverse=True)
            return rows[:5]
        except Exception:
            log.exception("No se pudieron correlacionar procesos de escritura")
            return []

    def clear(self) -> None:
        with self._lock:
            self._events.clear()
