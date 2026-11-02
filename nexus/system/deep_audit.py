from __future__ import annotations

import logging
import os

from ..models import Detection
from ..util import utc_now
from .integrity import compare_baseline
from .inventory import list_scheduled_tasks, list_services, list_startup_entries

log = logging.getLogger(__name__)


def _service_suspicion(binary: str) -> str:
    if not binary:
        return ""
    lowered = binary.lower()
    if any(
        token in lowered
        for token in ("\\temp\\", "\\downloads\\", "\\users\\public\\", "\\appdata\\local\\temp\\")
    ):
        return "Servicio ejecuta binario en ubicacion de usuario"
    if binary.strip().startswith('"'):
        return ""
    executable_part = binary.split(" ")[0]
    if " " in binary and not executable_part.lower().endswith(".exe"):
        return "Ruta de servicio sin comillas (riesgo de secuestro de ruta)"
    return ""


def service_suspicion(binary: str) -> str:
    return _service_suspicion(binary)


def deep_audit_detections() -> list[Detection]:
    detections: list[Detection] = []
    for entry in list_startup_entries():
        if entry.suspicion:
            detections.append(
                Detection(
                    path=f"startup://{entry.source}/{entry.name}",
                    sha256="",
                    name="Persistence.SuspiciousStartup",
                    verdict="suspicious",
                    severity="high",
                    engine="auditoria de persistencia",
                    details=f"{entry.suspicion}. Comando: {entry.command[:800]}",
                    size=0,
                    timestamp=utc_now(),
                )
            )
    for task in list_scheduled_tasks():
        if task.suspicion:
            detections.append(
                Detection(
                    path=f"task://{task.path}{task.name}",
                    sha256="",
                    name="Persistence.SuspiciousScheduledTask",
                    verdict="suspicious",
                    severity="high",
                    engine="auditoria de persistencia",
                    details=f"{task.suspicion}. Accion: {task.action[:800]}",
                    size=0,
                    timestamp=utc_now(),
                )
            )
    for service in list_services():
        reason = _service_suspicion(service.binary_path)
        if reason:
            detections.append(
                Detection(
                    path=f"service://{service.name}",
                    sha256="",
                    name="Persistence.SuspiciousService",
                    verdict="suspicious",
                    severity="high",
                    engine="auditoria de persistencia",
                    details=f"{reason}. Binario: {service.binary_path[:800]}",
                    size=0,
                    timestamp=utc_now(),
                )
            )
    diff = compare_baseline()
    for path in diff.changed_files:
        detections.append(
            Detection(
                path=path,
                sha256="",
                name="Integrity.CriticalFileChanged",
                verdict="suspicious",
                severity="high",
                engine="integridad",
                details=f"El archivo cambio desde la linea base ({diff.baseline_created}).",
                size=0,
                timestamp=utc_now(),
            )
        )
    for item in diff.added_startup:
        detections.append(
            Detection(
                path=f"integrity://startup/{item}",
                sha256="",
                name="Integrity.StartupChanged",
                verdict="suspicious",
                severity="medium",
                engine="integridad",
                details=f"Persistencia nueva o modificada: {item}",
                size=0,
                timestamp=utc_now(),
            )
        )
    for name in diff.changed_services:
        detections.append(
            Detection(
                path=f"integrity://service/{name}",
                sha256="",
                name="Integrity.ServiceChanged",
                verdict="suspicious",
                severity="medium",
                engine="integridad",
                details=f"El binario o tipo de inicio del servicio cambio: {name}",
                size=0,
                timestamp=utc_now(),
            )
        )
    return detections
