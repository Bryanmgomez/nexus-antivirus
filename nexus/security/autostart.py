from __future__ import annotations

import logging
import os
import subprocess
import sys
from pathlib import Path

log = logging.getLogger(__name__)
RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
VALUE_NAME = "NexusAntivirus"


def _command() -> str:
    if getattr(sys, "frozen", False):
        return subprocess.list2cmdline([sys.executable, "--background"])
    pythonw = Path(sys.executable).with_name("pythonw.exe")
    executable = pythonw if pythonw.is_file() else Path(sys.executable)
    return subprocess.list2cmdline([str(executable), "-m", "nexus", "--background"])


def is_enabled() -> bool:
    if os.name != "nt":
        return False
    try:
        import winreg

        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY) as key:
            value, _ = winreg.QueryValueEx(key, VALUE_NAME)
        return bool(value)
    except (ImportError, FileNotFoundError, OSError):
        return False


def registered_command() -> str:
    if os.name != "nt":
        return ""
    try:
        import winreg

        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY) as key:
            value, _ = winreg.QueryValueEx(key, VALUE_NAME)
        return str(value)
    except (ImportError, FileNotFoundError, OSError):
        return ""


def enable() -> tuple[bool, str]:
    if os.name != "nt":
        return False, "El inicio automatico solo esta disponible en Windows."
    try:
        import winreg

        command = _command()
        with winreg.CreateKeyEx(
            winreg.HKEY_CURRENT_USER, RUN_KEY, 0, winreg.KEY_SET_VALUE
        ) as key:
            winreg.SetValueEx(key, VALUE_NAME, 0, winreg.REG_SZ, command)
        log.info("Inicio automatico activado: %s", command)
        return True, "NEXUS se iniciara con Windows para el usuario actual."
    except OSError as exc:
        log.exception("No se pudo activar el inicio automatico")
        return False, f"No se pudo activar el inicio automatico: {exc}"


def disable() -> tuple[bool, str]:
    if os.name != "nt":
        return False, "El inicio automatico solo esta disponible en Windows."
    try:
        import winreg

        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY, 0, winreg.KEY_SET_VALUE) as key:
            winreg.DeleteValue(key, VALUE_NAME)
        log.info("Inicio automatico desactivado")
        return True, "Inicio automatico desactivado."
    except FileNotFoundError:
        return True, "El inicio automatico ya estaba desactivado."
    except OSError as exc:
        log.exception("No se pudo desactivar el inicio automatico")
        return False, f"No se pudo desactivar el inicio automatico: {exc}"
