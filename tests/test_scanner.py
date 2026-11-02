import os
from pathlib import Path

os.environ.setdefault("NEXUS_DATA_DIR", str(Path(__file__).resolve().parents[1] / ".test-data"))

from nexus.config import Settings
from nexus.database import Database
from nexus.engine.clamav import ClamAVEngine
from nexus.engine.heuristics import HeuristicAnalyzer
from nexus.engine.scanner import AntivirusScanner
from nexus.engine.signatures import SignatureDatabase
from nexus.engine.yara_engine import YaraEngine
from nexus.models import ScanOptions


def test_scanner_heuristic_detection(tmp_path):
    data_dir = Path(os.environ["NEXUS_DATA_DIR"])
    data_dir.mkdir(parents=True, exist_ok=True)
    db = Database(data_dir / "scanner.db")
    settings = Settings(db)
    signatures = SignatureDatabase()
    yara = YaraEngine()
    clamav = ClamAVEngine("")
    heuristics = HeuristicAnalyzer(threshold=50)
    scanner = AntivirusScanner(settings, db, signatures, yara, clamav, heuristics)
    target = tmp_path / "bad.ps1"
    target.write_text("vssadmin delete shadows\n", encoding="utf-8")
    options = ScanOptions(scan_type="custom", roots=[str(target)], use_heuristics=True, use_yara=False, use_clamav=False)
    summary = scanner.scan(options)
    assert summary.files_scanned == 1
    assert summary.threats_found >= 1
    assert any(d.engine == "heuristica" for d in summary.detections)
