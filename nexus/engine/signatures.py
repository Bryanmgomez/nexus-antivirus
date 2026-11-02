from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from .. import paths
from ..util import utc_now

log = logging.getLogger(__name__)
SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")


@dataclass(frozen=True, slots=True)
class Signature:
    sha256: str
    name: str
    severity: str = "high"
    source: str = "nexus"


class SignatureDatabase:
    """Base de firmas por SHA-256. No genera hashes ni resultados ficticios."""

    def __init__(self, signature_file: Path | str | None = None):
        self.signature_file = Path(signature_file) if signature_file else (
            paths.active_definitions_dir() / "signatures.json"
        )
        self.version = "desconocida"
        self.updated_at = ""
        self._entries: dict[str, Signature] = {}
        self.last_error = ""
        self.load()

    def load(self) -> None:
        entries: dict[str, Signature] = {}
        self.last_error = ""
        self.version = "desconocida"
        self.updated_at = ""
        try:
            with open(self.signature_file, "r", encoding="utf-8") as handle:
                payload = json.load(handle)
            if not isinstance(payload, dict):
                raise ValueError("El archivo de firmas no contiene un objeto JSON")
            self.version = str(payload.get("version", "sin-version"))
            self.updated_at = str(payload.get("updated_at", ""))
            raw_entries = payload.get("signatures", [])
            if not isinstance(raw_entries, list):
                raise ValueError("'signatures' debe ser una lista")
            for item in raw_entries:
                if not isinstance(item, dict):
                    continue
                digest = str(item.get("sha256", "")).strip().lower()
                if not SHA256_RE.match(digest):
                    log.warning("Firma SHA-256 ignorada por formato invalido: %r", digest)
                    continue
                entries[digest] = Signature(
                    sha256=digest,
                    name=str(item.get("name", "Malware.SinNombre")),
                    severity=str(item.get("severity", "high")).lower(),
                    source=str(item.get("source", "nexus")),
                )
            self._entries = entries
            log.info("Firmas cargadas: %d (version %s)", len(entries), self.version)
        except FileNotFoundError:
            self.last_error = f"No existe la base de firmas: {self.signature_file}"
            self._entries = {}
            log.error(self.last_error)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            self.last_error = f"No se pudo cargar la base de firmas: {exc}"
            self._entries = {}
            log.exception("Error cargando firmas")
        if not self.updated_at:
            try:
                self.updated_at = self.signature_file.stat().st_mtime_ns and utc_now()
            except OSError:
                self.updated_at = ""

    def reload(self) -> None:
        self.load()

    @property
    def count(self) -> int:
        return len(self._entries)

    @property
    def entries(self) -> list[Signature]:
        return list(self._entries.values())

    def lookup(self, sha256: str) -> Signature | None:
        return self._entries.get(sha256.lower())

    def add_many(self, signatures: Iterable[Signature]) -> int:
        added = 0
        for signature in signatures:
            digest = signature.sha256.lower()
            if SHA256_RE.match(digest) and digest not in self._entries:
                self._entries[digest] = Signature(
                    sha256=digest,
                    name=signature.name,
                    severity=signature.severity,
                    source=signature.source,
                )
                added += 1
        return added
