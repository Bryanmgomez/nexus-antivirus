from __future__ import annotations

import logging
import os

import psutil

log = logging.getLogger(__name__)


def suspend_process(pid: int) -> tuple[bool, str]:
    if pid in {0, 4, os.getpid()}:
        return False, "No se puede suspender un proceso del sistema ni NEXUS."
    try:
        process = psutil.Process(pid)
        process.suspend()
        log.warning("Proceso suspendido temporalmente por el usuario: PID %s (%s)", pid, process.name())
        return True, f"Proceso {process.name()} (PID {pid}) suspendido temporalmente."
    except (psutil.NoSuchProcess, psutil.AccessDenied, OSError) as exc:
        return False, f"No se pudo suspender el proceso {pid}: {exc}"


def resume_process(pid: int) -> tuple[bool, str]:
    try:
        process = psutil.Process(pid)
        process.resume()
        log.info("Proceso reanudado: PID %s (%s)", pid, process.name())
        return True, f"Proceso {process.name()} (PID {pid}) reanudado."
    except (psutil.NoSuchProcess, psutil.AccessDenied, OSError) as exc:
        return False, f"No se pudo reanudar el proceso {pid}: {exc}"
