from __future__ import annotations

import logging
import os
import queue
import threading
import time
from pathlib import Path
from typing import Callable

from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer

from ..config import Settings
from ..database import Database
from ..engine.scanner import AntivirusScanner
from ..models import Detection
from ..util import is_within, normalize_path, utc_now
from .ransomware import RansomAlert, RansomwareDetector

log = logging.getLogger(__name__)
IGNORED_SUFFIXES = {
    ".tmp", ".temp", ".part", ".crdownload", ".nxq", ".log", ".db-shm", ".db-wal", ".lock",
}


class _Handler(FileSystemEventHandler):
    def __init__(self, owner: "RealtimeProtection"):
        self.owner = owner

    def on_created(self, event: FileSystemEvent) -> None:
        if not event.is_directory:
            self.owner._handle_path(str(event.src_path), "created")

    def on_modified(self, event: FileSystemEvent) -> None:
        if not event.is_directory:
            self.owner._handle_path(str(event.src_path), "modified")

    def on_moved(self, event: FileSystemEvent) -> None:
        if not event.is_directory:
            destination = getattr(event, "dest_path", "")
            if destination:
                self.owner._handle_path(str(destination), "moved")


class RealtimeProtection:
    def __init__(
        self,
        settings: Settings,
        db: Database,
        scanner: AntivirusScanner,
        ransomware: RansomwareDetector,
        quarantine=None,
        on_detection: Callable[[Detection], None] | None = None,
        on_alert: Callable[[RansomAlert], None] | None = None,
        on_status: Callable[[str], None] | None = None,
    ):
        self.settings = settings
        self.db = db
        self.scanner = scanner
        self.ransomware = ransomware
        self.quarantine = quarantine
        self.on_detection = on_detection
        self.on_alert = on_alert
        self.on_status = on_status
        self._observer: Observer | None = None
        self._queue: queue.Queue[tuple[str, str] | None] = queue.Queue(maxsize=1000)
        self._workers: list[threading.Thread] = []
        self._stop = threading.Event()
        self._recent: dict[str, float] = {}
        self._recent_lock = threading.Lock()
        self._scanned_fingerprints: dict[str, tuple[int, int]] = {}
        self._running = False
        self._lock = threading.RLock()

    @property
    def running(self) -> bool:
        return self._running

    def watched_folders(self) -> list[str]:
        return [folder for folder in self.settings.watch_folders if os.path.isdir(folder)]

    def start(self) -> tuple[bool, str]:
        with self._lock:
            if self._running:
                return True, "La proteccion en tiempo real ya esta activa."
            folders = self.watched_folders()
            if not folders:
                return False, "No hay carpetas de vigilancia validas configuradas."
            self._stop.clear()
            self._clear_queue()
            observer = Observer()
            handler = _Handler(self)
            scheduled = 0
            for folder in folders:
                try:
                    observer.schedule(handler, folder, recursive=True)
                    scheduled += 1
                except Exception as exc:
                    log.warning("No se pudo vigilar %s: %s", folder, exc)
            if scheduled == 0:
                return False, "No se pudo vigilar ninguna carpeta. Revise permisos."
            for index in range(2):
                worker = threading.Thread(
                    target=self._worker_loop,
                    name=f"nexus-realtime-{index + 1}",
                    daemon=True,
                )
                worker.start()
                self._workers.append(worker)
            try:
                observer.start()
            except Exception as exc:
                log.exception("No se pudo iniciar watchdog")
                self._stop.set()
                self._workers.clear()
                return False, f"No se pudo iniciar la supervision: {exc}"
            self._observer = observer
            self._running = True
            self.settings.set_bool("realtime_enabled", True)
            self.db.add_event(
                "info",
                "realtime",
                "Proteccion en tiempo real activada",
                {"folders": folders},
            )
            log.info("Proteccion en tiempo real activa: %s", folders)
            self._status("active")
            return True, f"Proteccion activa en {scheduled} carpeta(s)."

    def stop(self, update_setting: bool = True) -> None:
        with self._lock:
            if not self._running:
                if update_setting:
                    self.settings.set_bool("realtime_enabled", False)
                return
            self._stop.set()
            if self._observer is not None:
                try:
                    self._observer.stop()
                    self._observer.join(timeout=5)
                except Exception:
                    log.exception("Error deteniendo watchdog")
                self._observer = None
            self._clear_queue()
            for worker in self._workers:
                worker.join(timeout=2)
            self._workers.clear()
            self._running = False
            if update_setting:
                self.settings.set_bool("realtime_enabled", False)
            self.db.add_event("info", "realtime", "Proteccion en tiempo real desactivada")
            log.info("Proteccion en tiempo real detenida")
            self._status("inactive")

    def restart(self) -> tuple[bool, str]:
        self.stop(update_setting=False)
        return self.start()

    def _status(self, status: str) -> None:
        if self.on_status:
            try:
                self.on_status(status)
            except Exception:
                log.exception("Error en callback de estado en tiempo real")

    def _clear_queue(self) -> None:
        while True:
            try:
                self._queue.get_nowait()
            except queue.Empty:
                break

    def _is_excluded(self, path: str) -> bool:
        if any(is_within(path, excluded) for excluded in self.settings.excluded_paths):
            return True
        suffix = Path(path).suffix.lower()
        if suffix in IGNORED_SUFFIXES or os.path.basename(path).startswith("~$"):
            return True
        return False

    def _handle_path(self, path: str, operation: str) -> None:
        if not path or not os.path.exists(path) or self._is_excluded(path):
            return
        if not os.path.isfile(path):
            return
        now = time.monotonic()
        with self._recent_lock:
            last = self._recent.get(path, 0.0)
            if now - last < 1.2:
                return
            self._recent[path] = now
            if len(self._recent) > 5000:
                cutoff = now - 300
                self._recent = {key: value for key, value in self._recent.items() if value >= cutoff}
        if self.settings.get_bool("ransomware_enabled", True):
            try:
                alert = self.ransomware.record(path, operation)
                if alert is not None:
                    self.db.add_event(
                        "critical",
                        "ransomware",
                        f"Actividad compatible con ransomware: {alert.reason}",
                        {
                            "files": alert.files_in_window,
                            "samples": alert.sample_paths,
                            "processes": alert.candidate_processes,
                        },
                    )
                    if self.on_alert:
                        threading.Thread(
                            target=self.on_alert, args=(alert,), daemon=True, name="nexus-ransom-alert"
                        ).start()
            except Exception:
                log.exception("Error del detector ransomware")
        try:
            self._queue.put_nowait((path, operation))
        except queue.Full:
            self.db.add_event(
                "error",
                "realtime",
                "Cola de analisis en tiempo real llena; evento descartado",
                {"path": path, "operation": operation},
            )

    def _worker_loop(self) -> None:
        while not self._stop.is_set():
            try:
                item = self._queue.get(timeout=0.5)
            except queue.Empty:
                continue
            if item is None:
                break
            path, operation = item
            try:
                self._scan_path(path, operation)
            except Exception:
                log.exception("Error analizando archivo en tiempo real: %s", path)
                self.db.add_event("error", "realtime", f"Error analizando {path}")

    def _scan_path(self, path: str, operation: str) -> None:
        time.sleep(0.15)
        try:
            stat = os.stat(path)
        except OSError:
            return
        fingerprint = (stat.st_size, stat.st_mtime_ns)
        if self._scanned_fingerprints.get(path) == fingerprint:
            return
        self._scanned_fingerprints[path] = fingerprint
        if len(self._scanned_fingerprints) > 5000:
            self._scanned_fingerprints.clear()
        detections = self.scanner.scan_single_file(path)
        if not detections:
            return
        for detection in detections:
            try:
                threat_id = self.db.add_threat(detection, None)
                detection.id = threat_id
            except Exception:
                log.exception("No se pudo registrar deteccion en tiempo real")
            self.db.add_event(
                "critical" if detection.verdict == "malware" else "warning",
                "realtime",
                f"Deteccion en tiempo real: {detection.name}",
                {
                    "path": detection.path,
                    "engine": detection.engine,
                    "verdict": detection.verdict,
                    "operation": operation,
                },
            )
            if (
                detection.verdict == "malware"
                and self.settings.get_bool("auto_quarantine", False)
                and self.quarantine is not None
            ):
                try:
                    self.quarantine.quarantine_file(
                        detection.path,
                        detection.name,
                        detection.engine,
                        detection.sha256,
                        detection.details,
                    )
                    detection.action = "quarantined"
                    if detection.id:
                        self.db.update_threat_action(detection.id, "quarantined")
                except Exception as exc:
                    log.exception("No se pudo aislar archivo en tiempo real")
                    self.db.add_event(
                        "error", "realtime", f"Cuarentena fallida para {detection.path}: {exc}"
                    )
            if self.on_detection:
                try:
                    self.on_detection(detection)
                except Exception:
                    log.exception("Error en callback de deteccion en tiempo real")
