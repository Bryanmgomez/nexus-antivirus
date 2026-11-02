from __future__ import annotations

import ctypes
import logging
import os
import threading
from typing import Callable

log = logging.getLogger(__name__)


def removable_drives() -> list[str]:
    if os.name != "nt":
        return []
    drives: list[str] = []
    try:
        kernel32 = ctypes.windll.kernel32
        mask = kernel32.GetLogicalDrives()
        for index in range(26):
            if not mask & (1 << index):
                continue
            root = f"{chr(ord('A') + index)}:\\"
            if kernel32.GetDriveTypeW(ctypes.c_wchar_p(root)) == 2:
                drives.append(root)
    except OSError:
        log.exception("No se pudieron enumerar unidades removibles")
    return drives


class UsbWatcher:
    def __init__(self, on_insert: Callable[[str], None], interval: float = 3.0):
        self.on_insert = on_insert
        self.interval = interval
        self._known: set[str] = set()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._known = set(removable_drives())
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="nexus-usb-watch", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2)
            self._thread = None

    def _run(self) -> None:
        while not self._stop.wait(self.interval):
            current = set(removable_drives())
            new_drives = current - self._known
            self._known = current
            for drive in sorted(new_drives):
                try:
                    self.on_insert(drive)
                except Exception:
                    log.exception("Error procesando unidad USB %s", drive)
