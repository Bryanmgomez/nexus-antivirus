from __future__ import annotations

import logging
import os

import psutil

from ..models import Detection
from ..system.inventory import command_suspicion
from ..util import utc_now
from .scanner import AntivirusScanner

log = logging.getLogger(__name__)


class MemoryScanner:
    """Inspecciona ejecutables de procesos activos e indicadores de linea de comandos."""

    def __init__(self, scanner: AntivirusScanner):
        self.scanner = scanner

    def scan(self, progress_cb=None) -> list[Detection]:
        detections: list[Detection] = []
        seen_exe: set[str] = set()
        try:
            total = len(psutil.pids())
        except Exception:
            total = 0
        scanned = 0
        for process in psutil.process_iter(["pid", "name", "exe", "cmdline"]):
            scanned += 1
            if progress_cb:
                try:
                    progress_cb(scanned, total, f"PID {process.pid}")
                except Exception:
                    pass
            try:
                info = process.info
                pid = process.pid
                exe = info.get("exe") or ""
                name = info.get("name") or f"PID {pid}"
                cmdline_list = info.get("cmdline") or []
                cmdline = " ".join(cmdline_list) if cmdline_list else exe
            except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
                continue
            if pid == os.getpid():
                continue
            suspicion = command_suspicion(cmdline)
            if suspicion:
                detections.append(
                    Detection(
                        path=f"process://{pid}/{name}",
                        sha256="",
                        name="Memory.SuspiciousCommandLine",
                        verdict="suspicious",
                        severity="high",
                        engine="analisis de memoria",
                        details=f"PID {pid}: {suspicion}. Linea: {cmdline[:800]}",
                        size=0,
                        timestamp=utc_now(),
                    )
                )
            if not exe:
                continue
            if not os.path.isfile(exe):
                detections.append(
                    Detection(
                        path=f"process://{pid}/{name}",
                        sha256="",
                        name="Memory.ImageWithoutFile",
                        verdict="suspicious",
                        severity="medium",
                        engine="analisis de memoria",
                        details=f"PID {pid}: la imagen del proceso no esta accesible en disco: {exe}",
                        size=0,
                        timestamp=utc_now(),
                    )
                )
                continue
            normalized = os.path.normcase(os.path.abspath(exe))
            if normalized in seen_exe:
                continue
            seen_exe.add(normalized)
            try:
                file_detections = self.scanner.scan_single_file(exe, include_clamav=False)
            except Exception:
                log.exception("Error analizando imagen de proceso %s", exe)
                continue
            for detection in file_detections:
                detection.details = (
                    f"Proceso PID {pid} ({name}). " + detection.details
                ).strip()
                detections.append(detection)
        return detections
