from __future__ import annotations

import logging
import os
import re
import shutil
import subprocess
from pathlib import Path

log = logging.getLogger(__name__)
FOUND_RE = re.compile(r"^(.*):\s+(.+?)\s+FOUND\s*$")


class ClamAVEngine:
    """Adaptador para el motor externo ClamAV. No simula resultados."""

    def __init__(self, configured_path: str = ""):
        self.scan_binary = self._locate(configured_path)
        self.update_binary = self._locate_update(configured_path)
        self.last_error = ""

    @staticmethod
    def _candidates(configured_path: str, executable: str) -> list[Path]:
        candidates: list[Path] = []
        if configured_path:
            base = Path(configured_path)
            if base.is_file():
                candidates.append(base)
            else:
                candidates.append(base / executable)
        found = shutil.which(executable)
        if found:
            candidates.append(Path(found))
        for base in (
            Path(os.environ.get("ProgramFiles", "C:\\Program Files")) / "ClamAV",
            Path(os.environ.get("ProgramFiles(x86)", "C:\\Program Files (x86)")) / "ClamAV",
        ):
            candidates.append(base / executable)
        return candidates

    def _locate(self, configured_path: str) -> str:
        for candidate in self._candidates(configured_path, "clamscan.exe"):
            if candidate.is_file():
                return str(candidate)
        for candidate in self._candidates(configured_path, "clamscan"):
            if candidate.is_file():
                return str(candidate)
        return ""

    def _locate_update(self, configured_path: str) -> str:
        for candidate in self._candidates(configured_path, "freshclam.exe"):
            if candidate.is_file():
                return str(candidate)
        for candidate in self._candidates(configured_path, "freshclam"):
            if candidate.is_file():
                return str(candidate)
        return ""

    @property
    def available(self) -> bool:
        return bool(self.scan_binary)

    @property
    def version(self) -> str:
        if not self.available:
            return "No disponible"
        try:
            result = subprocess.run(
                [self.scan_binary, "--version"],
                capture_output=True,
                text=True,
                timeout=10,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            text = (result.stdout or result.stderr).strip()
            return text.splitlines()[0][:100] if text else "ClamAV"
        except (OSError, subprocess.SubprocessError) as exc:
            self.last_error = str(exc)
            return "Error de version"

    def scan_file(self, path: str) -> tuple[str, str] | None:
        if not self.available:
            return None
        return self.scan_files([path]).get(os.path.normcase(path))

    def scan_files(self, paths: list[str]) -> dict[str, tuple[str, str]]:
        """Devuelve {ruta_normalizada: (nombre_firma, salida)} para archivos infectados."""
        infected: dict[str, tuple[str, str]] = {}
        if not self.available or not paths:
            return infected
        chunk_size = 64
        for offset in range(0, len(paths), chunk_size):
            chunk = paths[offset : offset + chunk_size]
            command = [
                self.scan_binary,
                "--no-summary",
                "--infected",
                "--stdout",
                "--",
                *chunk,
            ]
            try:
                result = subprocess.run(
                    command,
                    capture_output=True,
                    text=True,
                    errors="replace",
                    timeout=max(120, 20 * len(chunk)),
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                )
            except (OSError, subprocess.SubprocessError) as exc:
                self.last_error = f"ClamAV fallo: {exc}"
                log.warning(self.last_error)
                continue
            output = "\n".join(part for part in (result.stdout, result.stderr) if part)
            for line in output.splitlines():
                match = FOUND_RE.match(line.strip())
                if not match:
                    continue
                found_path, signature = match.groups()
                infected[os.path.normcase(os.path.abspath(found_path))] = (
                    signature.strip(),
                    line.strip(),
                )
        return infected

    def update_definitions(self, timeout: int = 900) -> tuple[bool, str]:
        if not self.update_binary:
            return False, "freshclam no esta instalado o no se encontro."
        try:
            result = subprocess.run(
                [self.update_binary, "--stdout"],
                capture_output=True,
                text=True,
                errors="replace",
                timeout=timeout,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            output = "\n".join(part for part in (result.stdout, result.stderr) if part).strip()
            if result.returncode == 0:
                return True, output[-4000:] or "Definiciones de ClamAV actualizadas."
            return False, output[-4000:] or f"freshclam termino con codigo {result.returncode}."
        except (OSError, subprocess.SubprocessError) as exc:
            return False, f"No se pudo ejecutar freshclam: {exc}"
