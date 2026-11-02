from __future__ import annotations

import ctypes
import logging
import os
import threading
import time
import uuid
from pathlib import Path
from typing import Callable

from ..config import Settings
from ..database import Database
from ..models import Detection, ScanOptions, ScanProgress, ScanSummary
from ..util import hash_file, iter_files, utc_now
from .clamav import ClamAVEngine
from .heuristics import HeuristicAnalyzer
from .signatures import SignatureDatabase
from .yara_engine import YaraEngine

log = logging.getLogger(__name__)
ProgressCallback = Callable[[ScanProgress], None]
DetectionCallback = Callable[[Detection], None]


def fixed_drives() -> list[str]:
    drives: list[str] = []
    if os.name == "nt":
        try:
            kernel32 = ctypes.windll.kernel32
            mask = kernel32.GetLogicalDrives()
            for index in range(26):
                if not mask & (1 << index):
                    continue
                letter = chr(ord("A") + index)
                root = f"{letter}:\\"
                if kernel32.GetDriveTypeW(ctypes.c_wchar_p(root)) == 3:
                    drives.append(root)
        except OSError:
            pass
    if not drives:
        anchor = Path.home().anchor
        if anchor:
            drives.append(anchor)
    return drives


def quick_roots() -> list[str]:
    home = Path.home()
    candidates = [
        home / "Downloads",
        home / "Desktop",
        home / "Documents",
        home / "AppData" / "Local" / "Temp",
        home / "AppData" / "Roaming" / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup",
        Path(os.environ.get("ProgramData", "C:\\ProgramData"))
        / "Microsoft"
        / "Windows"
        / "Start Menu"
        / "Programs"
        / "Startup",
        Path(os.environ.get("WINDIR", "C:\\Windows")) / "System32" / "Tasks",
    ]
    result: list[str] = []
    for path in candidates:
        if path.is_dir() and str(path) not in result:
            result.append(str(path))
    return result


class AntivirusScanner:
    def __init__(
        self,
        settings: Settings,
        db: Database,
        signatures: SignatureDatabase,
        yara: YaraEngine,
        clamav: ClamAVEngine,
        heuristics: HeuristicAnalyzer,
        quarantine=None,
    ):
        self.settings = settings
        self.db = db
        self.signatures = signatures
        self.yara = yara
        self.clamav = clamav
        self.heuristics = heuristics
        self.quarantine = quarantine
        self._cancel = threading.Event()
        self._active_scan_id: str | None = None

    @property
    def cancel_event(self) -> threading.Event:
        return self._cancel

    def cancel(self) -> None:
        self._cancel.set()

    def _resolve_roots(self, options: ScanOptions) -> list[str]:
        if options.scan_type == "quick":
            roots = quick_roots()
        elif options.scan_type in {"full", "deep"}:
            roots = fixed_drives()
        else:
            roots = options.roots
        result: list[str] = []
        for root in roots:
            expanded = os.path.abspath(os.path.expandvars(os.path.expanduser(root)))
            if os.path.exists(expanded) and expanded not in result:
                result.append(expanded)
        return result

    def scan(
        self,
        options: ScanOptions,
        progress_cb: ProgressCallback | None = None,
        detection_cb: DetectionCallback | None = None,
    ) -> ScanSummary:
        self._cancel.clear()
        scan_id = uuid.uuid4().hex
        self._active_scan_id = scan_id
        started_at = utc_now()
        roots = self._resolve_roots(options)
        excluded = list(self.settings.excluded_paths) + list(options.excluded)
        self.db.create_scan(scan_id, options.scan_type, roots, started_at)
        self.db.add_event(
            "info",
            "scanner",
            f"Analisis {options.scan_type} iniciado",
            {"scan_id": scan_id, "roots": roots},
        )

        start_monotonic = time.monotonic()
        files_scanned = 0
        bytes_scanned = 0
        detections: list[Detection] = []
        errors = 0
        error_samples: list[str] = []
        cancelled = False
        phase = "preparing"
        total_files = 0

        def emit(progress: ScanProgress) -> None:
            if progress_cb is None:
                return
            try:
                progress_cb(progress)
            except Exception:
                log.exception("Error en callback de progreso")

        emit(ScanProgress(phase="enumerating", message="Enumerando archivos accesibles..."))
        try:
            files = list(
                iter_files(roots, excluded=excluded, max_size=options.max_file_size)
            )
        except Exception as exc:
            errors += 1
            error_samples.append(f"Enumeracion: {exc}")
            log.exception("Error enumerando archivos")
            files = []
        total_files = len(files)
        total_bytes = sum(size for _, size in files)
        emit(
            ScanProgress(
                phase="ready",
                percent=1.0,
                total_files=total_files,
                message=f"{total_files} archivos accesibles, {total_bytes} bytes",
            )
        )

        clam_hits: dict[str, tuple[str, str]] = {}
        clamav_ready = bool(
            options.use_clamav and self.clamav.available and self.clamav.scan_binary
        )
        if clamav_ready and files:
            chunk_size = 64
            clam_start = 2.0
            clam_span = 28.0
            for offset in range(0, len(files), chunk_size):
                if self._cancel.is_set():
                    cancelled = True
                    break
                chunk = files[offset : offset + chunk_size]
                paths = [path for path, _ in chunk]
                try:
                    hits = self.clamav.scan_files(paths)
                    clam_hits.update(hits)
                except Exception as exc:
                    errors += 1
                    error_samples.append(f"ClamAV: {exc}")
                    log.exception("Error en lote de ClamAV")
                percent = clam_start + clam_span * min(1.0, (offset + len(chunk)) / len(files))
                emit(
                    ScanProgress(
                        phase="clamav",
                        percent=percent,
                        current_path=paths[-1] if paths else "",
                        files_scanned=0,
                        total_files=total_files,
                        threats_found=len(detections) + len(clam_hits),
                        elapsed_seconds=time.monotonic() - start_monotonic,
                        message=f"ClamAV: {min(offset + len(chunk), len(files))}/{len(files)}",
                    )
                )

        local_start = 30.0 if clamav_ready else 2.0
        local_span = 98.0 - local_start
        last_emit = 0.0
        for index, (path, size) in enumerate(files):
            if self._cancel.is_set():
                cancelled = True
                break
            phase = "scanning"
            normalized = os.path.normcase(os.path.abspath(path))
            file_detections: list[Detection] = []
            try:
                digest = hash_file(path).get("sha256", "")
            except (OSError, PermissionError) as exc:
                errors += 1
                if len(error_samples) < 50:
                    error_samples.append(f"{path}: {exc}")
                digest = ""
            if digest:
                signature = self.signatures.lookup(digest)
                if signature:
                    file_detections.append(
                        Detection(
                            path=path,
                            sha256=digest,
                            name=signature.name,
                            verdict="malware",
                            severity=signature.severity,
                            engine="firmas SHA-256",
                            details=f"Coincidencia exacta con {signature.source}",
                            size=size,
                            timestamp=utc_now(),
                        )
                    )
                if options.use_yara and self.yara.ready:
                    try:
                        for match in self.yara.scan_file(path):
                            verdict = "malware" if match.meta.get("verdict", "").lower() == "malware" else "suspicious"
                            file_detections.append(
                                Detection(
                                    path=path,
                                    sha256=digest,
                                    name=match.name,
                                    verdict=verdict,
                                    severity=match.severity,
                                    engine="YARA",
                                    details=match.details,
                                    size=size,
                                    timestamp=utc_now(),
                                )
                            )
                    except Exception as exc:
                        errors += 1
                        if len(error_samples) < 50:
                            error_samples.append(f"YARA {path}: {exc}")
                if options.use_heuristics:
                    try:
                        heuristic = self.heuristics.analyze(path, size)
                        if heuristic.suspicious and heuristic.findings:
                            top = sorted(heuristic.findings, key=lambda item: item.score, reverse=True)[0]
                            severity = (
                                "critical"
                                if any(item.severity == "critical" for item in heuristic.findings)
                                else "high"
                                if any(item.severity == "high" for item in heuristic.findings)
                                else "medium"
                            )
                            file_detections.append(
                                Detection(
                                    path=path,
                                    sha256=digest,
                                    name=f"Heuristic.{top.code}",
                                    verdict="suspicious",
                                    severity=severity,
                                    engine="heuristica",
                                    details=heuristic.details + f"; puntuacion={heuristic.score}",
                                    size=size,
                                    timestamp=utc_now(),
                                )
                            )
                    except Exception as exc:
                        errors += 1
                        if len(error_samples) < 50:
                            error_samples.append(f"Heuristica {path}: {exc}")
                clam_hit = clam_hits.get(normalized)
                if clam_hit:
                    file_detections.append(
                        Detection(
                            path=path,
                            sha256=digest,
                            name=clam_hit[0],
                            verdict="malware",
                            severity="high",
                            engine="ClamAV",
                            details=clam_hit[1],
                            size=size,
                            timestamp=utc_now(),
                        )
                    )

                for detection in self._deduplicate(file_detections):
                    try:
                        threat_id = self.db.add_threat(detection, scan_id)
                        detection.id = threat_id
                    except Exception:
                        log.exception("No se pudo registrar la amenaza")
                    detections.append(detection)
                    if detection_cb:
                        try:
                            detection_cb(detection)
                        except Exception:
                            log.exception("Error en callback de deteccion")
                    if (
                        options.auto_quarantine
                        and detection.verdict == "malware"
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
                            self.db.add_event(
                                "warning",
                                "quarantine",
                                f"Amenaza confirmada enviada a cuarentena: {detection.name}",
                                {"path": detection.path},
                            )
                        except Exception as exc:
                            log.exception("Fallo la cuarentena automatica")
                            self.db.add_event(
                                "error",
                                "quarantine",
                                f"No se pudo poner en cuarentena {detection.path}: {exc}",
                            )

            files_scanned += 1
            bytes_scanned += size
            now = time.monotonic()
            if progress_cb and (now - last_emit >= 0.12 or index == len(files) - 1):
                last_emit = now
                percent = local_start + local_span * ((index + 1) / max(1, len(files)))
                emit(
                    ScanProgress(
                        phase="scanning",
                        percent=min(99.0, percent),
                        current_path=path,
                        files_scanned=files_scanned,
                        total_files=total_files,
                        bytes_scanned=bytes_scanned,
                        threats_found=len(detections),
                        elapsed_seconds=now - start_monotonic,
                        message="Analizando archivos",
                    )
                )

        if options.scan_type == "deep" and not cancelled:
            emit(
                ScanProgress(
                    phase="deep_audit",
                    percent=99.0,
                    files_scanned=files_scanned,
                    total_files=total_files,
                    threats_found=len(detections),
                    elapsed_seconds=time.monotonic() - start_monotonic,
                    message="Auditando persistencia e integridad",
                )
            )
            try:
                from ..system.deep_audit import deep_audit_detections

                for detection in deep_audit_detections():
                    if self._cancel.is_set():
                        cancelled = True
                        break
                    try:
                        detection.id = self.db.add_threat(detection, scan_id)
                    except Exception:
                        log.exception("No se pudo registrar hallazgo de auditoria profunda")
                    detections.append(detection)
                    if detection_cb:
                        try:
                            detection_cb(detection)
                        except Exception:
                            log.exception("Error en callback de auditoria profunda")
            except Exception as exc:
                errors += 1
                if len(error_samples) < 50:
                    error_samples.append(f"Auditoria profunda: {exc}")
                log.exception("Fallo la auditoria profunda")

        finished_at = utc_now()
        status = "cancelled" if cancelled else "completed"
        summary = ScanSummary(
            scan_id=scan_id,
            scan_type=options.scan_type,
            roots=roots,
            started_at=started_at,
            finished_at=finished_at,
            files_scanned=files_scanned,
            bytes_scanned=bytes_scanned,
            threats_found=len(detections),
            errors=errors,
            cancelled=cancelled,
            detections=detections,
            status=status,
        )
        try:
            self.db.finish_scan(
                scan_id,
                finished_at,
                files_scanned,
                bytes_scanned,
                len(detections),
                errors,
                status,
                "\n".join(error_samples),
            )
            self.settings.set("last_scan", finished_at)
            if options.scan_type == "full":
                self.settings.set("last_full_scan", finished_at)
            self.db.add_event(
                "info" if not detections else "warning",
                "scanner",
                f"Analisis {options.scan_type} {status}: {files_scanned} archivos, {len(detections)} detecciones",
                {"scan_id": scan_id, "cancelled": cancelled},
            )
        except Exception:
            log.exception("No se pudo finalizar el registro del analisis")
        emit(
            ScanProgress(
                phase="finished",
                percent=100.0,
                current_path="",
                files_scanned=files_scanned,
                total_files=total_files,
                bytes_scanned=bytes_scanned,
                threats_found=len(detections),
                elapsed_seconds=time.monotonic() - start_monotonic,
                message="Analisis cancelado" if cancelled else "Analisis completado",
            )
        )
        self._active_scan_id = None
        return summary

    def scan_single_file(self, path: str, include_clamav: bool = True) -> list[Detection]:
        """Analisis puntual sin registrar en la base de datos (tiempo real)."""
        if not os.path.isfile(path):
            return []
        try:
            size = os.path.getsize(path)
        except OSError:
            return []
        if size > self.settings.max_file_size:
            return []
        try:
            digest = hash_file(path).get("sha256", "")
        except OSError:
            return []
        detections: list[Detection] = []
        signature = self.signatures.lookup(digest)
        if signature:
            detections.append(
                Detection(
                    path=path,
                    sha256=digest,
                    name=signature.name,
                    verdict="malware",
                    severity=signature.severity,
                    engine="firmas SHA-256",
                    details=f"Coincidencia exacta con {signature.source}",
                    size=size,
                    timestamp=utc_now(),
                )
            )
        if self.settings.get_bool("yara_enabled", True) and self.yara.ready:
            try:
                for match in self.yara.scan_file(path):
                    detections.append(
                        Detection(
                            path=path,
                            sha256=digest,
                            name=match.name,
                            verdict="malware" if match.meta.get("verdict", "").lower() == "malware" else "suspicious",
                            severity=match.severity,
                            engine="YARA",
                            details=match.details,
                            size=size,
                            timestamp=utc_now(),
                        )
                    )
            except Exception:
                log.exception("Error YARA en analisis puntual")
        if self.settings.get_bool("heuristics_enabled", True):
            try:
                heuristic = self.heuristics.analyze(path, size)
                if heuristic.suspicious and heuristic.findings:
                    top = sorted(heuristic.findings, key=lambda item: item.score, reverse=True)[0]
                    severity = (
                        "critical"
                        if any(item.severity == "critical" for item in heuristic.findings)
                        else "high"
                        if any(item.severity == "high" for item in heuristic.findings)
                        else "medium"
                    )
                    detections.append(
                        Detection(
                            path=path,
                            sha256=digest,
                            name=f"Heuristic.{top.code}",
                            verdict="suspicious",
                            severity=severity,
                            engine="heuristica",
                            details=heuristic.details + f"; puntuacion={heuristic.score}",
                            size=size,
                            timestamp=utc_now(),
                        )
                    )
            except Exception:
                log.exception("Error heuristico en analisis puntual")
        if include_clamav and self.settings.get_bool("clamav_enabled", True) and self.clamav.available:
            try:
                hit = self.clamav.scan_file(path)
                if hit:
                    detections.append(
                        Detection(
                            path=path,
                            sha256=digest,
                            name=hit[0],
                            verdict="malware",
                            severity="high",
                            engine="ClamAV",
                            details=hit[1],
                            size=size,
                            timestamp=utc_now(),
                        )
                    )
            except Exception:
                log.exception("Error ClamAV en analisis puntual")
        return self._deduplicate(detections)

    @staticmethod
    def _deduplicate(detections: list[Detection]) -> list[Detection]:
        seen: set[tuple[str, str]] = set()
        result: list[Detection] = []
        for detection in detections:
            key = (detection.engine, detection.name)
            if key not in seen:
                seen.add(key)
                result.append(detection)
        return result
