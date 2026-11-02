from __future__ import annotations

import logging
import math
import os
import re
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

from ..util import is_probably_text

log = logging.getLogger(__name__)

try:
    import pefile  # type: ignore
except ImportError:  # pragma: no cover
    pefile = None

EXECUTABLE_EXTENSIONS = {
    ".exe", ".dll", ".sys", ".scr", ".com", ".cpl", ".ocx", ".drv", ".efi", ".msi", ".msix",
}
SCRIPT_EXTENSIONS = {
    ".ps1", ".psm1", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".hta",
    ".ahk", ".py", ".sh", ".reg",
}
OFFICE_EXTENSIONS = {".docm", ".xlsm", ".pptm", ".dotm", ".xltm", ".potm", ".doc", ".xls", ".ppt"}
DOUBLE_EXTENSION_RE = re.compile(
    r"\.(pdf|docx?|xlsx?|pptx?|jpe?g|png|gif|txt|rtf|csv|zip|rar|7z|tar|gz|mp3|mp4|avi|mkv|"
    r"jpg|odt|ods|odp)\.(exe|scr|com|bat|cmd|ps1|vbs|vbe|js|jse|wsf|hta|jar|msi|lnk|iso|img|reg)$",
    re.IGNORECASE,
)
RANSOM_NOTE_RE = re.compile(
    r"(readme|read_me|recuperar|recover|decrypt|desencriptar|how_to|leame|help_restore)"
    r".*(txt|html?|hta|rtf)$|"
    r"(ransom|rescate|bitcoin|encrypted|encriptados).*(txt|html?|hta|rtf)$",
    re.IGNORECASE,
)

SCRIPT_PATTERNS: list[tuple[bytes, str, str, int, str]] = [
    (b"-encodedcommand", "PowerShell codificado", "script.powershell_encoded", 35, "high"),
    (b" -enc ", "PowerShell codificado", "script.powershell_encoded", 35, "high"),
    (b"frombase64string", "Decodificacion Base64", "script.base64", 25, "medium"),
    (b"downloadstring", "Descarga y ejecucion de codigo", "script.download_exec", 35, "high"),
    (b"downloaddata", "Descarga de carga util", "script.download", 25, "medium"),
    (b"invoke-expression", "Ejecucion dinamica", "script.iex", 25, "medium"),
    (b"iex(", "Ejecucion dinamica", "script.iex", 25, "medium"),
    (b"windowstyle hidden", "Ejecucion oculta", "script.hidden", 15, "medium"),
    (b"vssadmin delete shadows", "Destruccion de copias de seguridad", "ransom.shadow_delete", 65, "critical"),
    (b"wmic shadowcopy delete", "Destruccion de copias de seguridad", "ransom.shadow_delete", 65, "critical"),
    (b"wbadmin delete catalog", "Destruccion de copias de seguridad", "ransom.shadow_delete", 65, "critical"),
    (b"bcdedit", "Manipulacion de arranque/recuperacion", "ransom.boot_config", 35, "high"),
    (b"certutil -urlcache", "Descarga mediante certutil", "lolbin.certutil", 30, "high"),
    (b"certutil -decode", "Decodificacion mediante certutil", "lolbin.certutil", 30, "high"),
    (b"bitsadmin /transfer", "Descarga mediante bitsadmin", "lolbin.bitsadmin", 30, "high"),
    (b"mshta http", "Ejecucion remota con mshta", "lolbin.mshta", 35, "high"),
    (b"regsvr32 /s /i:http", "Ejecucion remota con regsvr32", "lolbin.regsvr32", 45, "high"),
    (b"rundll32 javascript", "Ejecucion remota con rundll32", "lolbin.rundll32", 40, "high"),
    (b"currentversion\\run", "Persistencia en inicio", "persistence.run_key", 25, "medium"),
    (b"schtasks /create", "Persistencia mediante tarea programada", "persistence.schtasks", 20, "medium"),
    (b"mimikatz", "Herramienta de robo de credenciales", "credential.mimikatz", 60, "critical"),
    (b"sekurlsa::", "Robo de credenciales LSASS", "credential.lsass", 60, "critical"),
    (b"procdump", "Posible volcado de memoria LSASS", "credential.procdump", 25, "high"),
    (b"comsvcs.dll", "Posible volcado de memoria LSASS", "credential.comsvcs", 20, "high"),
    (b"attrib +h", "Ocultamiento de archivos", "evasion.hidden", 10, "low"),
    (b"taskkill /f /im", "Finalizacion forzada de procesos", "impact.taskkill", 10, "low"),
    (b"netsh advfirewall set", "Manipulacion del firewall", "defense.firewall_tamper", 35, "high"),
    (b"set-mppreference -disablerealtimemonitoring", "Intento de desactivar antivirus", "defense.av_tamper", 60, "critical"),
    (b"reverse_tcp", "Payload de acceso remoto", "hack.reverse_tcp", 60, "critical"),
    (b"meterpreter", "Payload Meterpreter", "hack.meterpreter", 60, "critical"),
    (b"cobalt strike", "Beacon Cobalt Strike", "hack.cobaltstrike", 60, "critical"),
    (b"keylogger", "Keylogger", "hack.keylogger", 50, "high"),
    (b"getasynckeystate", "Captura de teclas", "hack.keylogger", 50, "high"),
    (b"bash -i >& /dev/tcp/", "Shell inversa", "hack.reverse_shell", 60, "critical"),
    (b"nc -e /bin/sh", "Shell inversa con netcat", "hack.reverse_shell", 60, "critical"),
    (b"powershell -nop -w hidden -enc", "PowerShell ofuscado", "hack.powershell_hidden", 45, "high"),
]

PDF_PATTERNS = [
    (b"/javascript", "JavaScript embebido en PDF", "pdf.javascript", 25, "medium"),
    (b"/openaction", "Accion automatica en PDF", "pdf.openaction", 25, "medium"),
    (b"/launch", "Ejecucion de archivo desde PDF", "pdf.launch", 35, "high"),
]


@dataclass(slots=True)
class HeuristicFinding:
    code: str
    title: str
    score: int
    severity: str
    detail: str


@dataclass(slots=True)
class HeuristicAnalysis:
    findings: list[HeuristicFinding] = field(default_factory=list)
    score: int = 0
    verdict: str = "clean"

    @property
    def suspicious(self) -> bool:
        return self.verdict == "suspicious"

    @property
    def details(self) -> str:
        return "; ".join(f"{item.title} ({item.code})" for item in self.findings)


class HeuristicAnalyzer:
    """Heuristica conservadora. Marca sospecha, nunca 'malware confirmado'."""

    def __init__(self, threshold: int = 50):
        self.threshold = threshold

    def analyze(self, path: str, size: int) -> HeuristicAnalysis:
        findings: list[HeuristicFinding] = []

        def add(code: str, title: str, score: int, severity: str, detail: str) -> None:
            if any(item.code == code and item.title == title for item in findings):
                return
            findings.append(HeuristicFinding(code, title, score, severity, detail))

        lower_name = os.path.basename(path).lower()
        extension = Path(lower_name).suffix.lower()
        try:
            stat_result = os.stat(path)
        except OSError:
            stat_result = None

        if DOUBLE_EXTENSION_RE.search(lower_name):
            add(
                "file.double_extension",
                "Doble extension ejecutable",
                55,
                "high",
                "El nombre simula un documento pero termina en una extension ejecutable.",
            )

        if stat_result and (getattr(stat_result, "st_file_attributes", 0) & 0x2) and extension in EXECUTABLE_EXTENSIONS:
            add(
                "file.hidden_executable",
                "Ejecutable oculto",
                20,
                "medium",
                "Archivo ejecutable con atributo oculto de Windows.",
            )

        if RANSOM_NOTE_RE.search(lower_name):
            add(
                "ransom.note_name",
                "Posible nota de rescate",
                25,
                "medium",
                "El nombre coincide con patrones usados por ransomware.",
            )

        header = b""
        try:
            with open(path, "rb") as handle:
                header = handle.read(1024 * 1024)
        except OSError as exc:
            log.debug("No se pudo leer cabecera de %s: %s", path, exc)

        if header.startswith(b"MZ") and extension not in EXECUTABLE_EXTENSIONS:
            add(
                "file.executable_masquerade",
                "Ejecutable camuflado",
                55,
                "high",
                "El contenido es un ejecutable PE pero la extension no corresponde.",
            )

        if header.startswith(b"PK\x03\x04") and extension in OFFICE_EXTENSIONS | {".zip", ".jar"}:
            self._inspect_zip(path, extension, add)

        if header.startswith(b"%PDF"):
            haystack = header.lower()
            for pattern, title, code, score, severity in PDF_PATTERNS:
                if pattern in haystack:
                    add(code, title, score, severity, "Patron activo encontrado en el PDF.")

        if header[:4] == b"L\x00\x00\x00":
            haystack = header.lower()
            if any(token in haystack for token in (b"powershell", b"cmd.exe", b"http://", b"https://", b"wscript")):
                add(
                    "file.suspicious_lnk",
                    "Acceso directo sospechoso",
                    35,
                    "high",
                    "El LNK apunta a un interprete de comandos o a un recurso remoto.",
                )

        if lower_name == "autorun.inf":
            haystack = header.lower()
            if b"open=" in haystack or b"shellexecute=" in haystack:
                add(
                    "file.autorun",
                    "Autorun con ejecucion automatica",
                    40,
                    "high",
                    "autorun.inf intenta ejecutar un programa al conectar la unidad.",
                )

        is_text = is_probably_text(header) or extension in SCRIPT_EXTENSIONS or extension in OFFICE_EXTENSIONS
        if is_text:
            self._inspect_text(header, extension, add)

        if header.startswith(b"MZ") and pefile is not None:
            self._inspect_pe(path, add)

        if "\\temp\\" in path.lower() or "\\downloads\\" in path.lower():
            if extension in EXECUTABLE_EXTENSIONS and size < 5 * 1024 * 1024:
                add(
                    "file.user_writable_path",
                    "Ejecutable en carpeta de descargas/temporal",
                    5,
                    "low",
                    "Ubicacion frecuente para cargas maliciosas; por si sola no confirma amenaza.",
                )

        score = sum(item.score for item in findings)
        verdict = "suspicious" if score >= self.threshold else "clean"
        return HeuristicAnalysis(findings=findings, score=score, verdict=verdict)

    # ------------------------------------------------------------------
    def _inspect_text(self, data: bytes, extension: str, add) -> None:
        haystack = data.lower() + b"\n" + data.replace(b"\x00", b"").lower()
        for pattern, title, code, score, severity in SCRIPT_PATTERNS:
            if pattern in haystack:
                add(code, title, score, severity, f"Indicador encontrado: {title}.")

        if extension in OFFICE_EXTENSIONS or extension in {".docm", ".xlsm", ".pptm"}:
            autoexec = sum(
                1
                for token in (b"autoopen", b"document_open", b"workbook_open", b"auto_open")
                if token in haystack
            )
            if autoexec:
                add(
                    "office.autoexec_macro",
                    "Macro de apertura automatica",
                    35,
                    "high",
                    "El documento contiene disparadores de macro al abrirse.",
                )

        if b"your files have been encrypted" in haystack or b"tus archivos han sido cifrados" in haystack:
            add(
                "ransom.note_content",
                "Mensaje de rescate",
                55,
                "critical",
                "El texto contiene una nota tipica de ransomware.",
            )
        if b"bitcoin" in haystack and (b"decrypt" in haystack or b"descifrar" in haystack):
            add(
                "ransom.payment_demand",
                "Demanda de pago",
                45,
                "high",
                "El texto combina criptomoneda con instrucciones de descifrado.",
            )

    def _inspect_zip(self, path: str, extension: str, add) -> None:
        try:
            with zipfile.ZipFile(path) as archive:
                names = [name.lower() for name in archive.namelist()[:5000]]
        except (OSError, zipfile.BadZipFile):
            return
        has_macro = any(name.endswith("vbaproject.bin") for name in names)
        if has_macro:
            add(
                "office.vba_project",
                "Proyecto VBA embebido",
                35,
                "high",
                "El documento contiene macros VBA.",
            )
        embedded = [
            name
            for name in names
            if Path(name).suffix.lower() in {".exe", ".scr", ".dll", ".js", ".vbs", ".ps1", ".bat", ".cmd"}
        ]
        if embedded:
            add(
                "archive.embedded_executable",
                "Ejecutable dentro de archivo comprimido",
                20,
                "medium",
                "El archivo contiene elementos ejecutables: " + ", ".join(embedded[:5]),
            )

    def _inspect_pe(self, path: str, add) -> None:
        if pefile is None:
            return
        try:
            pe = pefile.PE(path, fast_load=True)
            pe.parse_data_directories(
                directories=[
                    pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
                    pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"],
                ]
            )
        except Exception as exc:
            log.debug("PE invalido %s: %s", path, exc)
            return

        try:
            sections = list(pe.sections)
            if not sections:
                return
            writable_executable = False
            high_entropy = False
            upx = False
            for section in sections:
                try:
                    characteristics = int(section.Characteristics)
                    writable = bool(characteristics & 0x80000000)
                    executable = bool(characteristics & 0x20000000)
                    if writable and executable:
                        writable_executable = True
                    entropy = section.get_entropy()
                    if executable and entropy > 7.2 and section.SizeOfRawData > 4096:
                        high_entropy = True
                except Exception:
                    continue
                name = section.Name.rstrip(b"\x00").upper()
                if name.startswith(b"UPX") or name in {b".UPX0", b".UPX1", b".UPX2"}:
                    upx = True

            if writable_executable:
                add(
                    "pe.wx_section",
                    "Seccion escribible y ejecutable",
                    35,
                    "high",
                    "El PE contiene al menos una seccion W+X, tecnica habitual de inyeccion.",
                )
            if high_entropy:
                add(
                    "pe.high_entropy",
                    "Seccion ejecutable de alta entropia",
                    20,
                    "medium",
                    "El contenido parece cifrado o empaquetado.",
                )
            if upx:
                add(
                    "pe.upx",
                    "Empaquetado UPX",
                    15,
                    "medium",
                    "El binario esta comprimido con UPX.",
                )

            categories: dict[str, list[str]] = {}
            imports: set[str] = set()
            if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    for imported in entry.imports:
                        if imported.name:
                            imports.add(imported.name.decode("ascii", "ignore"))
            injection = {
                "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "NtUnmapViewOfSection",
                "QueueUserAPC", "SetThreadContext", "RtlCreateUserThread", "NtWriteVirtualMemory",
            }
            credential = {
                "GetAsyncKeyState", "SetWindowsHookExA", "SetWindowsHookExW", "GetKeyboardState",
                "OpenProcessToken", "AdjustTokenPrivileges", "LsaEnumerateLogonSessions",
            }
            crypto = {"CryptEncrypt", "CryptGenKey", "CryptAcquireContextW", "BCryptEncrypt"}
            for name in imports:
                if name in injection:
                    categories.setdefault("inyeccion de procesos", []).append(name)
                elif name in credential:
                    categories.setdefault("captura de credenciales/entrada", []).append(name)
                elif name in crypto:
                    categories.setdefault("criptografia", []).append(name)
            for category, names in categories.items():
                add(
                    "pe.suspicious_imports",
                    f"APIs de {category}",
                    20 if category != "criptografia" else 10,
                    "medium",
                    f"Importa: {', '.join(sorted(set(names))[:8])}",
                )

            if not imports:
                add(
                    "pe.no_imports",
                    "PE sin tabla de importaciones",
                    10,
                    "low",
                    "Puede indicar empaquetado o carga dinamica de APIs.",
                )

            has_signature = False
            security = getattr(pe, "OPTIONAL_HEADER", None)
            if security is not None:
                has_signature = getattr(security, "DATA_DIRECTORY", None) is not None and any(
                    directory.name == "IMAGE_DIRECTORY_ENTRY_SECURITY" and directory.Size > 0
                    for directory in security.DATA_DIRECTORY
                )
            if not has_signature and (writable_executable or upx or len(categories) >= 2):
                add(
                    "pe.unsigned",
                    "Binario sin firma Authenticode",
                    10,
                    "low",
                    "No se encontro firma digital embebida.",
                )
        finally:
            try:
                pe.close()
            except Exception:
                pass


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    length = len(data)
    return -sum((count / length) * math.log2(count / length) for count in counts if count)
