from __future__ import annotations

import json
import logging
import sqlite3
import threading
from pathlib import Path
from typing import Any

from .models import Detection, QuarantineEntry
from .paths import database_path
from .util import utc_now

log = logging.getLogger(__name__)

SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY,
    scan_type TEXT NOT NULL,
    roots TEXT NOT NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    files_scanned INTEGER NOT NULL DEFAULT 0,
    bytes_scanned INTEGER NOT NULL DEFAULT 0,
    threats_found INTEGER NOT NULL DEFAULT 0,
    errors INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL,
    error_details TEXT
);

CREATE TABLE IF NOT EXISTS threats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT,
    discovered_at TEXT NOT NULL,
    path TEXT NOT NULL,
    sha256 TEXT,
    name TEXT NOT NULL,
    verdict TEXT NOT NULL,
    severity TEXT NOT NULL,
    engine TEXT NOT NULL,
    size INTEGER NOT NULL DEFAULT 0,
    details TEXT,
    action TEXT NOT NULL DEFAULT 'detected'
);

CREATE TABLE IF NOT EXISTS quarantine (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    original_path TEXT NOT NULL,
    stored_name TEXT NOT NULL UNIQUE,
    sha256 TEXT NOT NULL,
    size INTEGER NOT NULL,
    detection_name TEXT NOT NULL,
    engine TEXT NOT NULL,
    created_at TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'quarantined',
    details TEXT
);

CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL,
    level TEXT NOT NULL,
    module TEXT NOT NULL,
    message TEXT NOT NULL,
    metadata TEXT
);

CREATE TABLE IF NOT EXISTS update_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL,
    version TEXT NOT NULL,
    source TEXT NOT NULL,
    status TEXT NOT NULL,
    message TEXT
);

CREATE INDEX IF NOT EXISTS idx_threats_date ON threats(discovered_at DESC);
CREATE INDEX IF NOT EXISTS idx_events_date ON events(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_scans_date ON scans(started_at DESC);
"""


class Database:
    def __init__(self, path: str | Path | None = None):
        self.path = Path(path) if path else database_path()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(str(self.path), check_same_thread=False, timeout=30)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.executescript(SCHEMA)
            self._conn.commit()

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    # ------------------------------------------------------------------
    # Configuracion
    # ------------------------------------------------------------------
    def get_setting(self, key: str) -> str | None:
        with self._lock:
            row = self._conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
        return row["value"] if row else None

    def set_setting(self, key: str, value: str) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO settings(key, value) VALUES(?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (key, value),
            )
            self._conn.commit()

    # ------------------------------------------------------------------
    # Eventos
    # ------------------------------------------------------------------
    def add_event(
        self,
        level: str,
        module: str,
        message: str,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO events(created_at, level, module, message, metadata) VALUES(?, ?, ?, ?, ?)",
                (utc_now(), level, module, message, json.dumps(metadata or {}, ensure_ascii=False)),
            )
            self._conn.commit()

    def list_events(self, limit: int = 50) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        return [dict(row) for row in rows]

    # ------------------------------------------------------------------
    # Analisis
    # ------------------------------------------------------------------
    def create_scan(self, scan_id: str, scan_type: str, roots: list[str], started_at: str) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO scans(id, scan_type, roots, started_at, status) VALUES(?, ?, ?, ?, 'running')",
                (scan_id, scan_type, json.dumps(roots, ensure_ascii=False), started_at),
            )
            self._conn.commit()

    def finish_scan(
        self,
        scan_id: str,
        finished_at: str,
        files_scanned: int,
        bytes_scanned: int,
        threats_found: int,
        errors: int,
        status: str,
        error_details: str = "",
    ) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE scans SET finished_at=?, files_scanned=?, bytes_scanned=?, threats_found=?, "
                "errors=?, status=?, error_details=? WHERE id=?",
                (
                    finished_at,
                    files_scanned,
                    bytes_scanned,
                    threats_found,
                    errors,
                    status,
                    error_details,
                    scan_id,
                ),
            )
            self._conn.commit()

    def list_scans(self, limit: int = 50) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM scans ORDER BY started_at DESC LIMIT ?", (limit,)
            ).fetchall()
        return [dict(row) for row in rows]

    def last_completed_scan(self) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM scans WHERE status = 'completed' ORDER BY finished_at DESC LIMIT 1"
            ).fetchone()
        return dict(row) if row else None

    # ------------------------------------------------------------------
    # Amenazas
    # ------------------------------------------------------------------
    def add_threat(self, detection: Detection, scan_id: str | None = None) -> int:
        with self._lock:
            cursor = self._conn.execute(
                "INSERT INTO threats(scan_id, discovered_at, path, sha256, name, verdict, severity, "
                "engine, size, details, action) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    scan_id,
                    detection.timestamp or utc_now(),
                    detection.path,
                    detection.sha256,
                    detection.name,
                    detection.verdict,
                    detection.severity,
                    detection.engine,
                    detection.size,
                    detection.details,
                    detection.action,
                ),
            )
            self._conn.commit()
            return int(cursor.lastrowid)

    def update_threat_action(self, threat_id: int, action: str) -> None:
        with self._lock:
            self._conn.execute("UPDATE threats SET action=? WHERE id=?", (action, threat_id))
            self._conn.commit()

    def list_threats(self, limit: int = 500) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM threats ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        return [dict(row) for row in rows]

    def get_threat(self, threat_id: int) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute("SELECT * FROM threats WHERE id=?", (threat_id,)).fetchone()
        return dict(row) if row else None

    # ------------------------------------------------------------------
    # Cuarentena
    # ------------------------------------------------------------------
    def add_quarantine(
        self,
        original_path: str,
        stored_name: str,
        sha256: str,
        size: int,
        detection_name: str,
        engine: str,
        details: str = "",
    ) -> int:
        with self._lock:
            cursor = self._conn.execute(
                "INSERT INTO quarantine(original_path, stored_name, sha256, size, detection_name, "
                "engine, created_at, details) VALUES(?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    original_path,
                    stored_name,
                    sha256,
                    size,
                    detection_name,
                    engine,
                    utc_now(),
                    details,
                ),
            )
            self._conn.commit()
            return int(cursor.lastrowid)

    def list_quarantine(self, status: str = "quarantined") -> list[QuarantineEntry]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM quarantine WHERE status=? ORDER BY id DESC", (status,)
            ).fetchall()
        return [
            QuarantineEntry(
                id=row["id"],
                original_path=row["original_path"],
                stored_name=row["stored_name"],
                sha256=row["sha256"],
                size=row["size"],
                detection_name=row["detection_name"],
                engine=row["engine"],
                created_at=row["created_at"],
                status=row["status"],
                details=row["details"] or "",
            )
            for row in rows
        ]

    def list_quarantine_history(self, limit: int = 500) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM quarantine ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        return [dict(row) for row in rows]

    def get_quarantine(self, entry_id: int) -> QuarantineEntry | None:
        with self._lock:
            row = self._conn.execute("SELECT * FROM quarantine WHERE id=?", (entry_id,)).fetchone()
        if not row:
            return None
        return QuarantineEntry(
            id=row["id"],
            original_path=row["original_path"],
            stored_name=row["stored_name"],
            sha256=row["sha256"],
            size=row["size"],
            detection_name=row["detection_name"],
            engine=row["engine"],
            created_at=row["created_at"],
            status=row["status"],
            details=row["details"] or "",
        )

    def set_quarantine_status(self, entry_id: int, status: str) -> None:
        with self._lock:
            self._conn.execute("UPDATE quarantine SET status=? WHERE id=?", (status, entry_id))
            self._conn.commit()

    def delete_quarantine_record(self, entry_id: int) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM quarantine WHERE id=?", (entry_id,))
            self._conn.commit()

    def resolve_threats_for_path(self, original_path: str, action: str) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE threats SET action=? WHERE path=? AND action NOT IN ('dismissed','deleted')",
                (action, original_path),
            )
            self._conn.commit()

    # ------------------------------------------------------------------
    # Actualizaciones
    # ------------------------------------------------------------------
    def add_update_record(
        self, version: str, source: str, status: str, message: str = ""
    ) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO update_history(created_at, version, source, status, message) "
                "VALUES(?, ?, ?, ?, ?)",
                (utc_now(), version, source, status, message),
            )
            self._conn.commit()

    def list_updates(self, limit: int = 20) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM update_history ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        return [dict(row) for row in rows]

    # ------------------------------------------------------------------
    # Estadisticas
    # ------------------------------------------------------------------
    def daily_stats(self, days: int = 7) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT substr(started_at, 1, 10) AS day, COUNT(*) AS scans, "
                "COALESCE(SUM(files_scanned), 0) AS files, "
                "COALESCE(SUM(threats_found), 0) AS threats "
                "FROM scans WHERE started_at >= date('now', ?) "
                "GROUP BY substr(started_at, 1, 10)",
                (f"-{max(1, days - 1)} days",),
            ).fetchall()
        found = {row["day"]: dict(row) for row in rows}
        from datetime import date, timedelta, datetime, timezone

        today = datetime.now(timezone.utc).date()
        result: list[dict[str, Any]] = []
        for offset in range(days - 1, -1, -1):
            day = (today - timedelta(days=offset)).isoformat()
            row = found.get(day, {"day": day, "scans": 0, "files": 0, "threats": 0})
            result.append(row)
        return result

    def statistics(self) -> dict[str, int]:
        with self._lock:
            threats = self._conn.execute(
                "SELECT COUNT(*) AS n FROM threats WHERE action NOT IN ('restored','deleted','dismissed')"
            ).fetchone()["n"]
            quarantine = self._conn.execute(
                "SELECT COUNT(*) AS n FROM quarantine WHERE status='quarantined'"
            ).fetchone()["n"]
            files = self._conn.execute(
                "SELECT COALESCE(SUM(files_scanned), 0) AS n FROM scans"
            ).fetchone()["n"]
            scans = self._conn.execute("SELECT COUNT(*) AS n FROM scans").fetchone()["n"]
            suspicious = self._conn.execute(
                "SELECT COUNT(*) AS n FROM threats WHERE verdict='suspicious' "
                "AND action NOT IN ('restored','deleted','dismissed')"
            ).fetchone()["n"]
        return {
            "threats": int(threats),
            "quarantine": int(quarantine),
            "files_scanned": int(files),
            "scans": int(scans),
            "suspicious": int(suspicious),
        }
