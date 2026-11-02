from __future__ import annotations

import base64
import hashlib
import io
import json
import logging
import os
import shutil
import tempfile
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import load_pem_public_key

from . import paths
from .config import Settings
from .database import Database
from .util import parse_semver, utc_now

log = logging.getLogger(__name__)
MAX_MANIFEST = 1024 * 1024
MAX_ARCHIVE = 200 * 1024 * 1024
MAX_EXTRACTED = 60 * 1024 * 1024
USER_AGENT = "NexusAntivirus/1.0 (+local-update-client)"


class UpdateError(RuntimeError):
    pass


@dataclass(slots=True)
class UpdateInfo:
    version: str
    published_at: str
    notes: str
    archive_url: str
    archive_sha256: str
    archive_size: int
    manifest_url: str
    manifest_bytes: bytes


class UpdateManager:
    def __init__(self, settings: Settings, db: Database, definitions_target: Path | None = None):
        self.settings = settings
        self.db = db
        self.definitions_target = definitions_target or paths.definitions_dir()

    # ------------------------------------------------------------------
    def _public_key(self) -> Ed25519PublicKey:
        configured = self.settings.get("update_public_key", "").strip()
        path = Path(configured) if configured else paths.public_key_path()
        if not path.is_file():
            raise UpdateError(
                "No hay clave publica de actualizaciones configurada. "
                "Genere una con tools/generate_update_key.py y configure su ruta."
            )
        try:
            key = load_pem_public_key(path.read_bytes())
        except (ValueError, OSError) as exc:
            raise UpdateError(f"Clave publica invalida: {exc}") from exc
        if not isinstance(key, Ed25519PublicKey):
            raise UpdateError("La clave publica debe ser Ed25519.")
        return key

    @staticmethod
    def _validate_url(url: str) -> None:
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme == "file":
            return
        if parsed.scheme == "https":
            return
        if parsed.scheme == "http" and parsed.hostname in {"localhost", "127.0.0.1", "::1"}:
            return
        raise UpdateError("Las actualizaciones deben usar HTTPS, file:// o localhost.")

    def _fetch(self, url: str, max_size: int, timeout: int = 30) -> bytes:
        self._validate_url(url)
        request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                data = response.read(max_size + 1)
        except (urllib.error.URLError, OSError, ValueError) as exc:
            raise UpdateError(f"No se pudo descargar {url}: {exc}") from exc
        if len(data) > max_size:
            raise UpdateError(f"El recurso excede el limite permitido: {url}")
        return data

    # ------------------------------------------------------------------
    def check(self, update_url: str | None = None) -> UpdateInfo:
        base_url = (update_url if update_url is not None else self.settings.get("update_url", "")).strip()
        if not base_url:
            raise UpdateError("Configure la URL del repositorio de actualizaciones.")
        if base_url.endswith("manifest.json"):
            manifest_url = base_url
        else:
            manifest_url = base_url.rstrip("/") + "/manifest.json"
        signature_url = manifest_url + ".sig"
        manifest_bytes = self._fetch(manifest_url, MAX_MANIFEST)
        signature_raw = self._fetch(signature_url, 64 * 1024).strip()
        signature = self._decode_signature(signature_raw)
        try:
            self._public_key().verify(signature, manifest_bytes)
        except InvalidSignature as exc:
            raise UpdateError("Firma Ed25519 invalida. Actualizacion rechazada.") from exc
        try:
            payload = json.loads(manifest_bytes.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise UpdateError(f"Manifiesto invalido: {exc}") from exc
        return self._parse_manifest(payload, manifest_url, manifest_bytes)

    @staticmethod
    def _decode_signature(raw: bytes) -> bytes:
        try:
            if raw.startswith(b"-----BEGIN"):
                raise ValueError
            text = raw.decode("ascii", "ignore").strip()
            if len(text) in {88, 89}:
                decoded = base64.b64decode(text, validate=True)
                if len(decoded) == 64:
                    return decoded
        except (ValueError, UnicodeDecodeError):
            pass
        if len(raw) != 64:
            raise UpdateError("La firma debe ser Ed25519 de 64 bytes o Base64 valido.")
        return raw

    def _parse_manifest(self, payload: dict, manifest_url: str, raw: bytes) -> UpdateInfo:
        if not isinstance(payload, dict):
            raise UpdateError("El manifiesto no es un objeto JSON.")
        if int(payload.get("format", 0)) != 1:
            raise UpdateError("Formato de manifiesto no soportado.")
        version = str(payload.get("version", "")).strip()
        archive = payload.get("archive")
        if not version or not isinstance(archive, dict):
            raise UpdateError("El manifiesto no incluye version o archivo.")
        archive_url = urllib.parse.urljoin(manifest_url, str(archive.get("url", "")))
        digest = str(archive.get("sha256", "")).lower()
        size = int(archive.get("size", 0))
        if not archive_url or len(digest) != 64 or size <= 0 or size > MAX_ARCHIVE:
            raise UpdateError("Metadatos del archivo de actualizacion invalidos.")
        return UpdateInfo(
            version=version,
            published_at=str(payload.get("published_at", "")),
            notes=str(payload.get("notes", "")),
            archive_url=archive_url,
            archive_sha256=digest,
            archive_size=size,
            manifest_url=manifest_url,
            manifest_bytes=raw,
        )

    # ------------------------------------------------------------------
    def download_and_apply(self, info: UpdateInfo, allow_downgrade: bool = False) -> str:
        current_path = paths.active_definitions_dir() / "signatures.json"
        current_version = "0"
        try:
            current_version = str(json.loads(current_path.read_text(encoding="utf-8")).get("version", "0"))
        except (OSError, json.JSONDecodeError):
            pass
        if not allow_downgrade and parse_semver(info.version) < parse_semver(current_version):
            raise UpdateError(
                f"La actualizacion {info.version} es anterior a la version instalada {current_version}."
            )
        archive = self._fetch(info.archive_url, info.archive_size + 1, timeout=120)
        if len(archive) != info.archive_size:
            raise UpdateError("El tamano del archivo no coincide con el manifiesto.")
        digest = hashlib.sha256(archive).hexdigest()
        if digest != info.archive_sha256:
            raise UpdateError("El SHA-256 del archivo no coincide con el manifiesto firmado.")
        with tempfile.TemporaryDirectory(prefix="nexus-update-") as temp_name:
            temp_dir = Path(temp_name)
            signatures_path, yara_path = self._extract_verified(archive, temp_dir)
            self._validate_definitions(signatures_path, yara_path)
            self._install(signatures_path, yara_path, current_version, info)
        self.settings.set("last_update", utc_now())
        self.db.add_update_record(
            info.version,
            info.manifest_url,
            "success",
            f"Actualizacion instalada. {info.notes}"[:2000],
        )
        log.info("Actualizacion %s instalada", info.version)
        return info.version

    def _extract_verified(self, archive: bytes, temp_dir: Path) -> tuple[Path, Path]:
        try:
            with zipfile.ZipFile(io.BytesIO(archive)) as bundle:
                infos = bundle.infolist()
                total = sum(item.file_size for item in infos)
                if total > MAX_EXTRACTED:
                    raise UpdateError("El contenido descomprimido excede el limite de seguridad.")
                for item in infos:
                    raw_name = item.filename.replace("\\", "/")
                    if raw_name.startswith("/") or ".." in Path(raw_name).parts:
                        raise UpdateError(f"Ruta no segura dentro del paquete: {item.filename}")
                    if item.is_dir():
                        continue
                    if raw_name not in {"signatures.json", "yara/nexus_rules.yar"}:
                        raise UpdateError(f"Archivo no permitido en el paquete: {item.filename}")
                    target = temp_dir / raw_name
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with bundle.open(item) as source, open(target, "wb") as destination:
                        shutil.copyfileobj(source, destination, length=1024 * 1024)
        except (zipfile.BadZipFile, OSError) as exc:
            raise UpdateError(f"Paquete de actualizacion invalido: {exc}") from exc
        signatures_path = temp_dir / "signatures.json"
        yara_path = temp_dir / "yara" / "nexus_rules.yar"
        if not signatures_path.is_file() or not yara_path.is_file():
            raise UpdateError("El paquete debe incluir signatures.json y yara/nexus_rules.yar.")
        return signatures_path, yara_path

    def _validate_definitions(self, signatures_path: Path, yara_path: Path) -> None:
        try:
            payload = json.loads(signatures_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise UpdateError(f"signatures.json invalido: {exc}") from exc
        entries = payload.get("signatures") if isinstance(payload, dict) else None
        if not isinstance(entries, list) or not entries:
            raise UpdateError("La base de firmas esta vacia o mal formada.")
        for entry in entries:
            digest = str(entry.get("sha256", "")) if isinstance(entry, dict) else ""
            if len(digest) != 64 or any(char not in "0123456789abcdefABCDEF" for char in digest):
                raise UpdateError("La base de firmas contiene un SHA-256 invalido.")
        try:
            import yara  # type: ignore

            yara.compile(filepath=str(yara_path))
        except ImportError:
            if not yara_path.read_text(encoding="utf-8", errors="ignore").strip():
                raise UpdateError("El archivo YARA esta vacio.")
        except Exception as exc:
            raise UpdateError(f"Las reglas YARA no compilan: {exc}") from exc

    def _install(
        self,
        signatures_path: Path,
        yara_path: Path,
        old_version: str,
        info: UpdateInfo,
    ) -> None:
        target = self.definitions_target
        target.mkdir(parents=True, exist_ok=True)
        yara_target = target / "yara"
        yara_target.mkdir(parents=True, exist_ok=True)
        backup = target / f".backup-{old_version.replace('/', '_')}-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"
        backup.mkdir(parents=True, exist_ok=True)
        old_signatures = target / "signatures.json"
        old_yara = yara_target / "nexus_rules.yar"
        if old_signatures.exists():
            shutil.copy2(old_signatures, backup / "signatures.json")
        if old_yara.exists():
            shutil.copy2(old_yara, backup / "nexus_rules.yar")
        try:
            shutil.copy2(signatures_path, old_signatures)
            shutil.copy2(yara_path, old_yara)
            os.utime(old_signatures, None)
        except OSError as exc:
            try:
                if (backup / "signatures.json").exists():
                    shutil.copy2(backup / "signatures.json", old_signatures)
                if (backup / "yara" / "nexus_rules.yar").exists() if (backup / "yara").exists() else False:
                    pass
                if (backup / "nexus_rules.yar").exists():
                    shutil.copy2(backup / "nexus_rules.yar", old_yara)
            except OSError:
                log.exception("No se pudo revertir la actualizacion")
            raise UpdateError(f"No se pudieron instalar las definiciones: {exc}") from exc
