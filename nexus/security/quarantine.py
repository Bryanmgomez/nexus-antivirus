from __future__ import annotations

import hashlib
import hmac
import logging
import os
import secrets
import uuid
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from ..database import Database
from ..models import QuarantineEntry
from ..paths import quarantine_dir
from ..util import hash_file, unique_path
from . import dpapi

log = logging.getLogger(__name__)

MAGIC = b"NXQ1"
SALT_SIZE = 16
NONCE_SIZE = 16
MAC_SIZE = 32
HEADER_SIZE = len(MAGIC) + SALT_SIZE + NONCE_SIZE


class QuarantineError(RuntimeError):
    pass


class QuarantineManager:
    """Cuarentena cifrada con AES-256-CBC + HMAC-SHA256 y clave protegida por DPAPI."""

    def __init__(self, db: Database, storage_dir: Path | str | None = None, key_path: Path | str | None = None):
        self.db = db
        self.storage_dir = Path(storage_dir) if storage_dir else quarantine_dir()
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        self.key_path = Path(key_path) if key_path else self.storage_dir / "quarantine.key"
        self._master_key = self._load_or_create_key()

    # ------------------------------------------------------------------
    # Clave
    # ------------------------------------------------------------------
    def _load_or_create_key(self) -> bytes:
        if self.key_path.exists():
            raw = self.key_path.read_bytes()
            if not raw:
                raise QuarantineError("La clave de cuarentena esta vacia")
            if os.name == "nt":
                try:
                    key = dpapi.unprotect(raw)
                except dpapi.DpapiError as exc:
                    raise QuarantineError(
                        "No se pudo desproteger la clave de cuarentena con DPAPI. "
                        "La cuarentena no se puede abrir con otra cuenta de Windows."
                    ) from exc
            else:
                key = raw
            if len(key) != 32:
                raise QuarantineError("La clave de cuarentena tiene un tamano invalido")
            return key
        key = secrets.token_bytes(32)
        if os.name == "nt":
            payload = dpapi.protect(key)
        else:
            payload = key
        self.key_path.write_bytes(payload)
        try:
            os.chmod(self.key_path, 0o600)
        except OSError:
            pass
        log.info("Clave de cuarentena creada")
        return key

    def _derive(self, salt: bytes) -> tuple[bytes, bytes]:
        material = HKDF(
            algorithm=hashes.SHA256(),
            length=64,
            salt=salt,
            info=b"NEXUS quarantine payload v1",
        ).derive(self._master_key)
        return material[:32], material[32:]

    # ------------------------------------------------------------------
    # Aislamiento
    # ------------------------------------------------------------------
    def quarantine_file(
        self,
        source: str,
        detection_name: str,
        engine: str,
        expected_sha256: str = "",
        details: str = "",
    ) -> QuarantineEntry:
        source_path = Path(source)
        if not source_path.is_file():
            raise QuarantineError(f"El archivo ya no existe o no es regular: {source}")
        if source_path.stat().st_size == 0 and expected_sha256:
            pass
        stored_name = f"{uuid.uuid4().hex}.nxq"
        target = self.storage_dir / stored_name
        temp_target = self.storage_dir / f".{stored_name}.tmp"
        salt = secrets.token_bytes(SALT_SIZE)
        nonce = secrets.token_bytes(NONCE_SIZE)
        enc_key, mac_key = self._derive(salt)
        header = MAGIC + salt + nonce
        digest = hashlib.sha256()
        size = 0
        entry_id: int | None = None
        try:
            encryptor = Cipher(algorithms.AES(enc_key), modes.CTR(nonce)).encryptor()
            mac = hmac.new(mac_key, digestmod=hashlib.sha256)
            mac.update(header)
            with open(source_path, "rb") as source_handle, open(temp_target, "wb") as target_handle:
                target_handle.write(header)
                while True:
                    chunk = source_handle.read(1024 * 1024)
                    if not chunk:
                        break
                    digest.update(chunk)
                    size += len(chunk)
                    encrypted = encryptor.update(chunk)
                    if encrypted:
                        target_handle.write(encrypted)
                        mac.update(encrypted)
                final_cipher = encryptor.finalize()
                if final_cipher:
                    target_handle.write(final_cipher)
                    mac.update(final_cipher)
                target_handle.write(mac.digest())
                target_handle.flush()
                os.fsync(target_handle.fileno())
            actual_sha256 = digest.hexdigest()
            if expected_sha256 and not hmac.compare_digest(actual_sha256.lower(), expected_sha256.lower()):
                raise QuarantineError(
                    "El archivo cambio mientras se analizaba; no se movio para evitar aislar datos equivocados."
                )
            os.replace(temp_target, target)
            entry_id = self.db.add_quarantine(
                original_path=str(source_path),
                stored_name=stored_name,
                sha256=actual_sha256,
                size=size,
                detection_name=detection_name,
                engine=engine,
                details=details,
            )
            try:
                os.unlink(source_path)
            except OSError as exc:
                self._rollback(entry_id, target)
                raise QuarantineError(
                    f"No se pudo retirar el archivo original (posiblemente esta en uso): {exc}"
                ) from exc
            entry = self.db.get_quarantine(entry_id)
            if entry is None:
                raise QuarantineError("No se pudo leer el registro de cuarentena recien creado")
            self.db.add_event(
                "warning",
                "quarantine",
                f"Archivo aislado: {source_path.name}",
                {"detection": detection_name, "sha256": actual_sha256, "engine": engine},
            )
            log.warning("Archivo aislado: %s (%s)", source_path, detection_name)
            return entry
        except BaseException:
            for path in (temp_target, target):
                try:
                    if path.exists() and entry_id is None:
                        path.unlink()
                except OSError:
                    pass
            raise
        finally:
            try:
                if temp_target.exists():
                    temp_target.unlink()
            except OSError:
                pass

    def _rollback(self, entry_id: int, target: Path) -> None:
        try:
            self.db.delete_quarantine_record(entry_id)
        except Exception:
            log.exception("No se pudo eliminar el registro de cuarentena durante rollback")
        try:
            if target.exists():
                target.unlink()
        except OSError:
            log.exception("No se pudo eliminar el archivo cifrado durante rollback")

    # ------------------------------------------------------------------
    # Restauracion
    # ------------------------------------------------------------------
    def restore(self, entry_id: int, destination: str | Path | None = None) -> Path:
        entry = self.db.get_quarantine(entry_id)
        if entry is None or entry.status != "quarantined":
            raise QuarantineError("La entrada de cuarentena no existe o no esta activa")
        source = self.storage_dir / entry.stored_name
        if not source.is_file():
            raise QuarantineError("El archivo cifrado de cuarentena no esta disponible")
        if destination:
            destination_path = Path(destination)
            target = destination_path if destination_path.suffix else destination_path / Path(entry.original_path).name
        else:
            target = Path(entry.original_path)
        if target.exists():
            target = unique_path(target)
        target.parent.mkdir(parents=True, exist_ok=True)
        temp_path = target.parent / f".{target.name}.{uuid.uuid4().hex}.restore"
        try:
            self._decrypt_to(entry, source, temp_path)
            if temp_path.stat().st_size != entry.size:
                raise QuarantineError("El tamano restaurado no coincide con el registrado")
            os.replace(temp_path, target)
            os.unlink(source)
        except BaseException:
            try:
                if temp_path.exists():
                    temp_path.unlink()
            except OSError:
                pass
            raise
        self.db.set_quarantine_status(entry_id, "restored")
        self.db.resolve_threats_for_path(entry.original_path, "restored")
        self.db.add_event(
            "info",
            "quarantine",
            f"Archivo restaurado: {target}",
            {"entry_id": entry_id, "sha256": entry.sha256},
        )
        return target

    def _decrypt_to(self, entry: QuarantineEntry, source: Path, target: Path) -> None:
        with open(source, "rb") as handle:
            header = handle.read(HEADER_SIZE)
            if len(header) != HEADER_SIZE or not header.startswith(MAGIC):
                raise QuarantineError("Formato de cuarentena desconocido")
            salt = header[len(MAGIC) : len(MAGIC) + SALT_SIZE]
            nonce = header[len(MAGIC) + SALT_SIZE : HEADER_SIZE]
            enc_key, mac_key = self._derive(salt)
            file_size = source.stat().st_size
            if file_size < HEADER_SIZE + MAC_SIZE:
                raise QuarantineError("Archivo de cuarentena truncado")
            ciphertext_size = file_size - HEADER_SIZE - MAC_SIZE
            remaining = ciphertext_size
            decryptor = Cipher(algorithms.AES(enc_key), modes.CTR(nonce)).decryptor()
            mac = hmac.new(mac_key, digestmod=hashlib.sha256)
            mac.update(header)
            with open(target, "wb") as output:
                while remaining > 0:
                    chunk = handle.read(min(1024 * 1024, remaining))
                    if not chunk:
                        raise QuarantineError("Archivo de cuarentena truncado durante la lectura")
                    remaining -= len(chunk)
                    mac.update(chunk)
                    output.write(decryptor.update(chunk))
                stored_mac = handle.read(MAC_SIZE)
                expected_mac = mac.digest()
                if not hmac.compare_digest(stored_mac, expected_mac):
                    raise QuarantineError("La firma HMAC de cuarentena no es valida; archivo alterado")
                output.write(decryptor.finalize())
                output.flush()
                os.fsync(output.fileno())
        actual_sha = hash_file(target).get("sha256", "")
        if not hmac.compare_digest(actual_sha, entry.sha256):
            raise QuarantineError("El SHA-256 restaurado no coincide con el original")

    # ------------------------------------------------------------------
    # Eliminacion definitiva
    # ------------------------------------------------------------------
    def delete_forever(self, entry_id: int) -> None:
        entry = self.db.get_quarantine(entry_id)
        if entry is None or entry.status != "quarantined":
            raise QuarantineError("La entrada de cuarentena no existe o no esta activa")
        stored = self.storage_dir / entry.stored_name
        try:
            if stored.exists():
                stored.unlink()
        except OSError as exc:
            raise QuarantineError(f"No se pudo eliminar el archivo cifrado: {exc}") from exc
        self.db.set_quarantine_status(entry_id, "deleted")
        self.db.resolve_threats_for_path(entry.original_path, "deleted")
        self.db.add_event(
            "warning",
            "quarantine",
            f"Amenaza eliminada definitivamente: {entry.detection_name}",
            {"entry_id": entry_id, "original_path": entry.original_path},
        )

    def list_entries(self) -> list[QuarantineEntry]:
        return self.db.list_quarantine()

    def storage_usage(self) -> int:
        total = 0
        for entry in self.list_entries():
            total += entry.size
        return total
