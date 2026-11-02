from __future__ import annotations

import logging
import time
import uuid
from typing import Callable

from . import paths
from .config import Settings
from .database import Database
from .engine.clamav import ClamAVEngine
from .engine.heuristics import HeuristicAnalyzer
from .engine.process_scan import MemoryScanner
from .engine.scanner import AntivirusScanner
from .engine.signatures import SignatureDatabase
from .engine.yara_engine import YaraEngine
from .models import Detection, ScanSummary
from .security.quarantine import QuarantineManager
from .security.ransomware import RansomAlert, RansomwareDetector
from .security.realtime import RealtimeProtection
from .updates import UpdateManager
from .usb import UsbWatcher
from .util import utc_now

log = logging.getLogger(__name__)


class NexusServices:
    def __init__(self, on_detection: Callable[[Detection], None] | None = None,
                 on_ransomware: Callable[[RansomAlert], None] | None = None,
                 on_usb: Callable[[str], None] | None = None):
        paths.ensure_directories()
        self.db = Database()
        self.settings = Settings(self.db)
        self.on_detection = on_detection
        self.on_ransomware = on_ransomware
        self.on_usb = on_usb
        self.signatures = SignatureDatabase()
        self.yara = YaraEngine()
        self.clamav = ClamAVEngine(self.settings.get("clamav_path", ""))
        self.heuristics = HeuristicAnalyzer()
        self.quarantine = QuarantineManager(self.db)
        self.ransomware = RansomwareDetector(self.settings)
        self.scanner = AntivirusScanner(
            self.settings,
            self.db,
            self.signatures,
            self.yara,
            self.clamav,
            self.heuristics,
            quarantine=self.quarantine,
        )
        self.memory = MemoryScanner(self.scanner)
        self.realtime = RealtimeProtection(
            self.settings,
            self.db,
            self.scanner,
            self.ransomware,
            quarantine=self.quarantine,
            on_detection=self.on_detection,
            on_alert=self.on_ransomware,
        )
        self.update_manager = UpdateManager(self.settings, self.db)
        self.usb = UsbWatcher(self._usb_inserted)
        self.db.add_event("info", "app", "NEXUS iniciado")
        log.info("Servicios NEXUS inicializados")

    def _usb_inserted(self, drive: str) -> None:
        self.db.add_event("info", "usb", f"Unidad removible detectada: {drive}")
        if self.on_usb:
            try:
                self.on_usb(drive)
            except Exception:
                log.exception("Error en callback USB")

    def start_background(self) -> tuple[bool, str]:
        if self.settings.get_bool("usb_scan_enabled", True):
            self.usb.start()
        if self.settings.get_bool("realtime_enabled", False):
            ok, message = self.realtime.start()
            if not ok:
                self.db.add_event("error", "realtime", f"No se pudo restaurar proteccion: {message}")
            return ok, message
        return True, "Proteccion en tiempo real desactivada."

    def reload_engines(self, reload_clamav_path: bool = False) -> None:
        self.signatures.reload()
        self.yara.compile()
        if reload_clamav_path:
            self.clamav = ClamAVEngine(self.settings.get("clamav_path", ""))
            self.scanner.clamav = self.clamav
        log.info("Motores de deteccion recargados")

    def scan_memory(self, progress_cb=None) -> ScanSummary:
        scan_id = uuid.uuid4().hex
        started = utc_now()
        started_monotonic = time.monotonic()
        self.db.create_scan(scan_id, "memory", [], started)
        detections = self.memory.scan(progress_cb=progress_cb)
        for detection in detections:
            try:
                detection.id = self.db.add_threat(detection, scan_id)
            except Exception:
                log.exception("No se pudo registrar hallazgo de memoria")
        finished = utc_now()
        self.db.finish_scan(
            scan_id, finished, 0, 0, len(detections), 0, "completed"
        )
        self.settings.set("last_scan", finished)
        self.db.add_event(
            "warning" if detections else "info",
            "memory",
            f"Analisis de memoria completado: {len(detections)} hallazgos",
            {"scan_id": scan_id, "elapsed": time.monotonic() - started_monotonic},
        )
        return ScanSummary(
            scan_id=scan_id,
            scan_type="memory",
            roots=[],
            started_at=started,
            finished_at=finished,
            files_scanned=0,
            bytes_scanned=0,
            threats_found=len(detections),
            errors=0,
            detections=detections,
        )

    def engine_info(self) -> dict[str, str]:
        yara_state = (
            f"{self.yara.rule_count} reglas" if self.yara.ready else f"No disponible ({self.yara.last_error})"
        )
        clam_state = self.clamav.version if self.clamav.available else "No instalado (opcional)"
        return {
            "Firmas SHA-256": f"{self.signatures.count} firmas, version {self.signatures.version}",
            "Ultima actualizacion de firmas": self.signatures.updated_at or "desconocida",
            "YARA": yara_state,
            "ClamAV": clam_state,
            "Heuristica": "Activa" if self.settings.get_bool("heuristics_enabled", True) else "Desactivada",
        }

    def shutdown(self) -> None:
        try:
            self.realtime.stop(update_setting=False)
        except Exception:
            log.exception("Error deteniendo proteccion en tiempo real")
        try:
            self.usb.stop()
        except Exception:
            log.exception("Error deteniendo monitor USB")
        try:
            self.db.add_event("info", "app", "NEXUS cerrado")
            self.db.close()
        except Exception:
            log.exception("Error cerrando base de datos")
