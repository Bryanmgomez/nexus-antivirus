from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class Detection:
    path: str
    sha256: str
    name: str
    verdict: str
    severity: str
    engine: str
    details: str = ""
    size: int = 0
    timestamp: str = ""
    action: str = "detected"
    id: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "path": self.path,
            "sha256": self.sha256,
            "name": self.name,
            "verdict": self.verdict,
            "severity": self.severity,
            "engine": self.engine,
            "details": self.details,
            "size": self.size,
            "timestamp": self.timestamp,
            "action": self.action,
        }


@dataclass(slots=True)
class ScanOptions:
    scan_type: str = "custom"
    roots: list[str] = field(default_factory=list)
    auto_quarantine: bool = False
    use_clamav: bool = True
    use_yara: bool = True
    use_heuristics: bool = True
    max_file_size: int = 256 * 1024 * 1024
    excluded: list[str] = field(default_factory=list)


@dataclass(slots=True)
class ScanProgress:
    phase: str = "preparing"
    percent: float = 0.0
    current_path: str = ""
    files_scanned: int = 0
    total_files: int = 0
    bytes_scanned: int = 0
    threats_found: int = 0
    elapsed_seconds: float = 0.0
    message: str = ""


@dataclass(slots=True)
class ScanSummary:
    scan_id: str
    scan_type: str
    roots: list[str]
    started_at: str
    finished_at: str
    files_scanned: int
    bytes_scanned: int
    threats_found: int
    errors: int
    cancelled: bool = False
    detections: list[Detection] = field(default_factory=list)
    status: str = "completed"


@dataclass(slots=True)
class QuarantineEntry:
    id: int
    original_path: str
    stored_name: str
    sha256: str
    size: int
    detection_name: str
    engine: str
    created_at: str
    status: str
    details: str = ""


@dataclass(slots=True)
class ProcessInfo:
    pid: int
    name: str
    username: str
    exe: str
    cmdline: str
    cpu_percent: float
    memory_mb: float
    create_time: float
    status: str
    connections: int = 0
    suspicion: str = ""


@dataclass(slots=True)
class StartupEntry:
    source: str
    name: str
    command: str
    location: str
    user: str = ""
    suspicion: str = ""


@dataclass(slots=True)
class NetworkConnection:
    pid: int
    process: str
    local: str
    remote: str
    status: str
    family: str
    suspicion: str = ""


@dataclass(slots=True)
class ServiceInfo:
    name: str
    display_name: str
    status: str
    start_type: str
    binary_path: str


@dataclass(slots=True)
class ScheduledTask:
    name: str
    path: str
    state: str
    action: str
    trigger: str
    suspicion: str = ""


@dataclass(slots=True)
class SystemCheck:
    key: str
    title: str
    status: str
    detail: str
    severity: str = "info"
