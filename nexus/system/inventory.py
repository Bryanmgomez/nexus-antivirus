from __future__ import annotations

import ipaddress
import json
import logging
import os
import re
import subprocess
from pathlib import Path
from typing import Any

import psutil

from ..models import (
    NetworkConnection,
    ProcessInfo,
    ScheduledTask,
    ServiceInfo,
    StartupEntry,
    SystemCheck,
)
from ..util import is_within, normalize_path

log = logging.getLogger(__name__)
CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)

SUSPICIOUS_COMMAND_PATTERNS = [
    (re.compile(r"powershell(\.exe)?\b.*(-enc|encodedcommand)", re.I), "PowerShell con comando codificado"),
    (re.compile(r"powershell(\.exe)?\b.*(-windowstyle\s+hidden|-w\s+hidden)", re.I), "PowerShell oculto"),
    (re.compile(r"mshta(\.exe)?\b.*https?://", re.I), "mshta ejecutando contenido remoto"),
    (re.compile(r"regsvr32(\.exe)?\b.*(/i:?https?://|scrobj\.dll)", re.I), "regsvr32 remoto"),
    (re.compile(r"rundll32(\.exe)?\b.*javascript:", re.I), "rundll32 con JavaScript"),
    (re.compile(r"certutil(\.exe)?\b.*-urlcache", re.I), "certutil descargando contenido"),
    (re.compile(r"bitsadmin(\.exe)?\b.*(/transfer|/addfile)", re.I), "bitsadmin descargando contenido"),
    (re.compile(r"wscript(\.exe)?\b.*https?://", re.I), "Windows Script Host remoto"),
    (re.compile(r"cmd(\.exe)?\b.*(/c|/k).*https?://", re.I), "cmd con URL remota"),
    (re.compile(r"(vssadmin|wmic).*(delete\s+shadows|shadowcopy\s+delete)", re.I), "Destruccion de instantaneas"),
    (re.compile(r"set-mppreference.*disable", re.I), "Intento de alterar Defender"),
    (re.compile(r"netsh\s+advfirewall\s+set", re.I), "Alteracion del firewall"),
    (re.compile(r"procdump.*lsass", re.I), "Volcado de LSASS"),
    (re.compile(r"comsvcs\.dll.*minidump", re.I), "Volcado de LSASS"),
    (re.compile(r"\b(nc|ncat|netcat)\b.*(-e|-c|/bin/sh|cmd\.exe)", re.I), "Shell remota con netcat"),
    (re.compile(r"\bpsexec(\.exe)?\b", re.I), "Ejecucion remota con PsExec"),
    (re.compile(r"\bmimikatz\b", re.I), "Herramienta de robo de credenciales"),
    (re.compile(r"\bprocdump(\.exe)?\b.*lsass", re.I), "Volcado de LSASS"),
    (re.compile(r"\blazagne\b", re.I), "Extractor de credenciales"),
    (re.compile(r"\brubeus\b", re.I), "Herramienta de ataque Kerberos"),
    (re.compile(r"\bempire\b", re.I), "Framework de post-explotacion"),
    (re.compile(r"\bcobaltstrike\b", re.I), "Beacon de Cobalt Strike"),
]
SYSTEM_PROCESS_NAMES = {
    "svchost.exe": "system32",
    "lsass.exe": "system32",
    "services.exe": "system32",
    "csrss.exe": "system32",
    "winlogon.exe": "system32",
    "smss.exe": "system32",
    "wininit.exe": "system32",
    "spoolsv.exe": "system32",
}
USER_WRITABLE_TOKENS = (
    "\\appdata\\local\\temp\\",
    "\\downloads\\",
    "\\users\\public\\",
    "\\$recycle.bin\\",
    "\\windows\\temp\\",
)


def _decode_output(data: bytes) -> str:
    if not data:
        return ""
    for encoding in ("utf-8-sig", "utf-8", "cp1252", "latin-1"):
        try:
            return data.decode(encoding)
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", "replace")


def run_powershell_json(script: str, timeout: int = 30) -> Any | None:
    if os.name != "nt":
        return None
    command = [
        "powershell.exe",
        "-NoLogo",
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-Command",
        "$OutputEncoding=[Console]::OutputEncoding=[Text.Encoding]::UTF8; " + script,
    ]
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            timeout=timeout,
            creationflags=CREATE_NO_WINDOW,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        log.warning("PowerShell fallo: %s", exc)
        return None
    output = _decode_output(result.stdout).strip()
    if not output:
        log.debug("PowerShell sin salida: %s", _decode_output(result.stderr)[:500])
        return None
    try:
        return json.loads(output)
    except json.JSONDecodeError:
        log.warning("Salida JSON invalida de PowerShell: %s", output[:300])
        return None


def command_suspicion(command: str) -> str:
    for pattern, description in SUSPICIOUS_COMMAND_PATTERNS:
        if pattern.search(command or ""):
            return description
    lowered = (command or "").lower()
    if any(token in lowered for token in USER_WRITABLE_TOKENS):
        if re.search(r"\.(exe|scr|com|bat|cmd|ps1|vbs|js|hta)\b", lowered):
            return "Ejecutable en ubicacion de usuario"
    return ""


def _is_user_writable(path: str) -> bool:
    lowered = normalize_path(path)
    return any(token in lowered for token in USER_WRITABLE_TOKENS)


def _process_connection_counts() -> dict[int, int]:
    counts: dict[int, int] = {}
    try:
        for connection in psutil.net_connections(kind="inet"):
            if connection.pid:
                counts[connection.pid] = counts.get(connection.pid, 0) + 1
    except (psutil.AccessDenied, OSError):
        pass
    return counts


def list_processes() -> list[ProcessInfo]:
    connection_counts = _process_connection_counts()
    results: list[ProcessInfo] = []
    for process in psutil.process_iter(
        ["pid", "name", "username", "exe", "cmdline", "create_time", "status", "memory_info"]
    ):
        try:
            info = process.info
            exe = info.get("exe") or ""
            cmdline_list = info.get("cmdline") or []
            cmdline = subprocess.list2cmdline(cmdline_list) if cmdline_list else exe
            name = info.get("name") or ""
            suspicion = command_suspicion(cmdline)
            if not suspicion and name.lower() in SYSTEM_PROCESS_NAMES:
                expected = SYSTEM_PROCESS_NAMES[name.lower()]
                if expected not in normalize_path(exe):
                    suspicion = "Nombre de proceso del sistema en ruta inesperada"
            if not suspicion and exe and _is_user_writable(exe):
                suspicion = "Ejecutable en ubicacion de usuario"
            try:
                cpu = process.cpu_percent(interval=None)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                cpu = 0.0
            memory = info.get("memory_info")
            results.append(
                ProcessInfo(
                    pid=process.pid,
                    name=name,
                    username=info.get("username") or "",
                    exe=exe,
                    cmdline=cmdline,
                    cpu_percent=cpu,
                    memory_mb=round((memory.rss / (1024 * 1024)) if memory else 0.0, 1),
                    create_time=float(info.get("create_time") or 0.0),
                    status=info.get("status") or "",
                    connections=connection_counts.get(process.pid, 0),
                    suspicion=suspicion,
                )
            )
        except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
            continue
    results.sort(key=lambda item: (not bool(item.suspicion), -item.memory_mb))
    return results


def _registry_values(root, path: str, view: int) -> list[tuple[str, str]]:
    if os.name != "nt":
        return []
    try:
        import winreg
    except ImportError:
        return []
    values: list[tuple[str, str]] = []
    try:
        with winreg.OpenKey(root, path, 0, winreg.KEY_READ | view) as key:
            index = 0
            while True:
                try:
                    name, value, value_type = winreg.EnumValue(key, index)
                except OSError:
                    break
                index += 1
                if isinstance(value, str):
                    values.append((name, value))
    except OSError:
        pass
    return values


def list_startup_entries() -> list[StartupEntry]:
    if os.name != "nt":
        return []
    import winreg

    entries: list[StartupEntry] = []
    seen: set[tuple[str, str]] = set()

    def add(source: str, name: str, command: str, location: str, user: str = "") -> None:
        key = (name.lower(), normalize_path(location))
        if key in seen:
            return
        seen.add(key)
        entries.append(
            StartupEntry(
                source=source,
                name=name,
                command=command,
                location=location,
                user=user,
                suspicion=command_suspicion(command),
            )
        )

    run_keys = [
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKCU Run", winreg.KEY_WOW64_64KEY),
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKCU Run (32)", winreg.KEY_WOW64_32KEY),
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU RunOnce", winreg.KEY_WOW64_64KEY),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKLM Run", winreg.KEY_WOW64_64KEY),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKLM Run (32)", winreg.KEY_WOW64_32KEY),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM RunOnce", winreg.KEY_WOW64_64KEY),
    ]
    for root, path, source, view in run_keys:
        for name, command in _registry_values(root, path, view):
            add(source, name, command, f"{source}: {name}")

    winlogon = r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
    for name, command in _registry_values(winreg.HKEY_LOCAL_MACHINE, winlogon, winreg.KEY_WOW64_64KEY):
        if name.lower() in {"userinit", "shell", "taskman"}:
            add("Winlogon", name, command, f"HKLM\\{winlogon}\\{name}")
    for name, command in _registry_values(
        winreg.HKEY_LOCAL_MACHINE,
        r"Software\Microsoft\Windows NT\CurrentVersion\Windows",
        winreg.KEY_WOW64_64KEY,
    ):
        if name.lower() == "appinit_dlls" and command.strip():
            add("AppInit_DLLs", name, command, "HKLM\\...\\Windows\\AppInit_DLLs")

    startup_dirs = [
        Path(os.environ.get("APPDATA", "")) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup",
        Path(os.environ.get("ProgramData", "C:\\ProgramData")) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup",
    ]
    for directory in startup_dirs:
        if not directory.is_dir():
            continue
        for file in directory.iterdir():
            if file.name.lower() == "desktop.ini":
                continue
            source = "HKCU Startup" if str(directory).startswith(str(Path.home())) else "Startup (all users)"
            add(source, file.name, str(file), str(file))
    return entries


def list_network_connections() -> list[NetworkConnection]:
    try:
        raw = psutil.net_connections(kind="inet")
    except (psutil.AccessDenied, OSError) as exc:
        log.warning("No se pudieron leer conexiones: %s", exc)
        return []
    process_cache: dict[int, tuple[str, str]] = {}
    rows: list[NetworkConnection] = []
    for connection in raw:
        pid = connection.pid or 0
        if pid not in process_cache:
            process_cache[pid] = ("", "")
            if pid:
                try:
                    process = psutil.Process(pid)
                    process_cache[pid] = (process.name(), process.exe())
                except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
                    pass
        name, exe = process_cache[pid]
        local = f"{connection.laddr.ip}:{connection.laddr.port}" if connection.laddr else ""
        remote = f"{connection.raddr.ip}:{connection.raddr.port}" if connection.raddr else ""
        suspicion = ""
        if exe and _is_user_writable(exe):
            suspicion = "Proceso en ubicacion de usuario con conexion de red"
        if remote:
            host = remote.rsplit(":", 1)[0]
            try:
                address = ipaddress.ip_address(host)
                if not (address.is_private or address.is_loopback or address.is_link_local):
                    if suspicion:
                        suspicion += "; destino publico"
            except ValueError:
                pass
        rows.append(
            NetworkConnection(
                pid=pid,
                process=name or ("PID " + str(pid) if pid else ""),
                local=local,
                remote=remote,
                status=connection.status,
                family="IPv6" if connection.family == 23 else "IPv4",
                suspicion=suspicion,
            )
        )
    rows.sort(key=lambda item: (not bool(item.suspicion), item.process.lower()))
    return rows


def list_services() -> list[ServiceInfo]:
    if os.name != "nt":
        return []
    rows: list[ServiceInfo] = []
    try:
        services = list(psutil.win_service_iter())
    except (AttributeError, OSError):
        return []
    for service in services:
        try:
            info = service.as_dict()
        except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
            continue
        binary = info.get("binpath") or ""
        rows.append(
            ServiceInfo(
                name=info.get("name") or "",
                display_name=info.get("display_name") or "",
                status=info.get("status") or "",
                start_type=info.get("start_type") or "",
                binary_path=binary,
            )
        )
    rows.sort(key=lambda row: row.display_name.lower())
    return rows


def _tasks_script() -> str:
    return (
        "Get-ScheduledTask | ForEach-Object { "
        "$actions = @($_.Actions | ForEach-Object { "
        "[string]$_.Execute + ' ' + [string]$_.Arguments }) -join ' | '; "
        "$triggers = @($_.Triggers | ForEach-Object { $_.CimClass.CimClassName }) -join ', '; "
        "[pscustomobject]@{Name=$_.TaskName;Path=$_.TaskPath;State=[string]$_.State;Action=$actions;Trigger=$triggers}"
        "} | ConvertTo-Json -Depth 4 -Compress"
    )


def list_scheduled_tasks() -> list[ScheduledTask]:
    payload = run_powershell_json(_tasks_script(), timeout=45)
    if payload is None:
        return []
    if isinstance(payload, dict):
        payload = [payload]
    if not isinstance(payload, list):
        return []
    rows: list[ScheduledTask] = []
    for item in payload:
        if not isinstance(item, dict):
            continue
        action = str(item.get("Action") or "")
        rows.append(
            ScheduledTask(
                name=str(item.get("Name") or ""),
                path=str(item.get("Path") or ""),
                state=str(item.get("State") or ""),
                action=action,
                trigger=str(item.get("Trigger") or ""),
                suspicion=command_suspicion(action),
            )
        )
    rows.sort(key=lambda row: (not bool(row.suspicion), row.path.lower(), row.name.lower()))
    return rows


def firewall_status() -> dict[str, bool]:
    script = "Get-NetFirewallProfile | Select-Object Name,Enabled | ConvertTo-Json -Compress"
    payload = run_powershell_json(script, timeout=20)
    result: dict[str, bool] = {}
    if isinstance(payload, dict):
        payload = [payload]
    if isinstance(payload, list):
        for item in payload:
            if isinstance(item, dict) and item.get("Name"):
                result[str(item["Name"])] = bool(item.get("Enabled"))
    return result


def defender_status() -> dict[str, Any]:
    script = (
        "Get-MpComputerStatus | Select-Object AMServiceEnabled,AntivirusEnabled,"
        "RealTimeProtectionEnabled,AntivirusSignatureVersion,AntivirusSignatureLastUpdated,"
        "BehaviorMonitorEnabled,IsTamperProtected | ConvertTo-Json -Compress"
    )
    payload = run_powershell_json(script, timeout=30)
    if not isinstance(payload, dict):
        return {}
    return payload


def system_checks() -> list[SystemCheck]:
    checks: list[SystemCheck] = []
    firewall = firewall_status()
    if firewall:
        disabled = [name for name, enabled in firewall.items() if not enabled]
        checks.append(
            SystemCheck(
                key="firewall",
                title="Firewall de Windows",
                status="ok" if not disabled else "warning",
                detail="Todos los perfiles activos." if not disabled else "Perfiles desactivados: " + ", ".join(disabled),
                severity="info" if not disabled else "high",
            )
        )
    else:
        checks.append(
            SystemCheck(
                key="firewall",
                title="Firewall de Windows",
                status="unknown",
                detail="No se pudo consultar el estado del firewall.",
                severity="medium",
            )
        )
    defender = defender_status()
    if defender:
        realtime = bool(defender.get("RealTimeProtectionEnabled"))
        checks.append(
            SystemCheck(
                key="defender_realtime",
                title="Proteccion en tiempo real de Defender",
                status="ok" if realtime else "warning",
                detail="Activa." if realtime else "Desactivada. NEXUS no la modifica.",
                severity="info" if realtime else "high",
            )
        )
        version = str(defender.get("AntivirusSignatureVersion") or "desconocida")
        checks.append(
            SystemCheck(
                key="defender_signatures",
                title="Firmas de Windows Defender",
                status="ok" if defender.get("AntivirusSignatureLastUpdated") else "unknown",
                detail=f"Version {version}. Ultima: {defender.get('AntivirusSignatureLastUpdated', 'desconocida')}",
                severity="info",
            )
        )
    else:
        checks.append(
            SystemCheck(
                key="defender",
                title="Windows Defender",
                status="unknown",
                detail="No se pudo consultar el estado de Defender.",
                severity="medium",
            )
        )

    try:
        import winreg

        def read_dword(root, path: str, name: str) -> int | None:
            try:
                with winreg.OpenKey(root, path, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as key:
                    value, _ = winreg.QueryValueEx(key, name)
                    return int(value)
            except (OSError, ValueError, TypeError):
                return None

        uac = read_dword(
            winreg.HKEY_LOCAL_MACHINE,
            r"Software\Microsoft\Windows\CurrentVersion\Policies\System",
            "EnableLUA",
        )
        checks.append(
            SystemCheck(
                key="uac",
                title="Control de cuentas de usuario (UAC)",
                status="ok" if uac == 1 else "warning",
                detail="Activo." if uac == 1 else "Desactivado o no se pudo leer.",
                severity="info" if uac == 1 else "high",
            )
        )
        smb1 = read_dword(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters",
            "SMB1",
        )
        checks.append(
            SystemCheck(
                key="smb1",
                title="SMBv1",
                status="ok" if smb1 in (0, None) else "warning",
                detail="Desactivado o no configurado." if smb1 in (0, None) else "SMBv1 podria estar habilitado.",
                severity="info" if smb1 in (0, None) else "high",
            )
        )
        rdp = read_dword(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Control\Terminal Server",
            "fDenyTSConnections",
        )
        checks.append(
            SystemCheck(
                key="rdp",
                title="Escritorio remoto (RDP)",
                status="ok" if rdp == 1 else "warning",
                detail="Deshabilitado." if rdp == 1 else "Habilitado; asegurese de que sea intencional.",
                severity="info" if rdp == 1 else "medium",
            )
        )
        smartscreen = read_dword(
            winreg.HKEY_LOCAL_MACHINE,
            r"Software\Policies\Microsoft\Windows\System",
            "EnableSmartScreen",
        )
        if smartscreen is None:
            smartscreen = read_dword(
                winreg.HKEY_LOCAL_MACHINE,
                r"Software\Microsoft\Windows\CurrentVersion\Explorer",
                "SmartScreenEnabled",
            )
        if smartscreen is not None:
            checks.append(
                SystemCheck(
                    key="smartscreen",
                    title="SmartScreen",
                    status="ok" if bool(smartscreen) else "warning",
                    detail="Activo." if bool(smartscreen) else "Desactivado.",
                    severity="info" if bool(smartscreen) else "medium",
                )
            )
    except ImportError:
        pass
    return checks


def installed_apps() -> list[dict[str, str]]:
    if os.name != "nt":
        return []
    import winreg

    paths = [
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Uninstall", winreg.KEY_WOW64_64KEY),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Uninstall", winreg.KEY_WOW64_32KEY),
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Uninstall", winreg.KEY_WOW64_64KEY),
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Uninstall", winreg.KEY_WOW64_32KEY),
    ]
    apps: dict[tuple[str, str], dict[str, str]] = {}
    for root, base, view in paths:
        try:
            with winreg.OpenKey(root, base, 0, winreg.KEY_READ | view) as key:
                count = winreg.QueryInfoKey(key)[0]
                for index in range(count):
                    try:
                        subname = winreg.EnumKey(key, index)
                        with winreg.OpenKey(key, subname) as subkey:
                            def get(name: str) -> str:
                                try:
                                    value, _ = winreg.QueryValueEx(subkey, name)
                                    return str(value) if value is not None else ""
                                except OSError:
                                    return ""

                            display = get("DisplayName")
                            if not display:
                                continue
                            location = get("InstallLocation")
                            row = {
                                "name": display,
                                "version": get("DisplayVersion"),
                                "publisher": get("Publisher"),
                                "location": location,
                                "uninstall": get("UninstallString"),
                                "source": base + "\\" + subname,
                                "suspicion": "Ubicacion de instalacion en carpeta de usuario"
                                if location and _is_user_writable(location)
                                else "",
                            }
                            apps[(display.lower(), get("DisplayVersion"))] = row
                    except OSError:
                        continue
        except OSError:
            continue
    return sorted(apps.values(), key=lambda item: (not bool(item["suspicion"]), item["name"].lower()))


def authenticode_status(path: str) -> str:
    if os.name != "nt" or not path or not os.path.isfile(path):
        return "No disponible"
    escaped = path.replace("'", "''")
    script = f"(Get-AuthenticodeSignature -LiteralPath '{escaped}').Status"
    try:
        result = subprocess.run(
            [
                "powershell.exe",
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                script,
            ],
            capture_output=True,
            timeout=20,
            creationflags=CREATE_NO_WINDOW,
        )
        output = _decode_output(result.stdout).strip()
        return output or "Desconocido"
    except (OSError, subprocess.SubprocessError) as exc:
        log.warning("No se pudo verificar firma de %s: %s", path, exc)
        return "Error"

def extract_command_target(command: str) -> str:
    """Extrae la ruta ejecutable de un comando de inicio si existe en disco."""
    value = (command or "").strip()
    if not value:
        return ""
    if value.startswith('"'):
        end = value.find('"', 1)
        if end > 1:
            candidate = value[1:end]
            if os.path.isfile(candidate):
                return candidate
    match = re.match(r"^(.+?\.(?:exe|com|bat|cmd|ps1|vbs|js|scr|msi|lnk))(?:\s|$)", value, re.I)
    if match:
        candidate = match.group(1).strip('"')
        if os.path.isfile(candidate):
            return candidate
    candidate = value.strip('"')
    if os.path.isfile(candidate):
        return candidate
    return ""
