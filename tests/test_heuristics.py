import os
from pathlib import Path

os.environ.setdefault("NEXUS_DATA_DIR", str(Path(__file__).resolve().parents[1] / ".test-data"))

from nexus.engine.heuristics import HeuristicAnalyzer


def test_heuristic_detects_ransom_command():
    analyzer = HeuristicAnalyzer(threshold=50)
    path = Path(__file__).resolve().parents[1] / ".test-data" / "suspicious.ps1"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("vssadmin delete shadows\nwmic shadowcopy delete\n", encoding="utf-8")
    result = analyzer.analyze(str(path), path.stat().st_size)
    assert result.suspicious
    assert any("shadow" in f.code.lower() or "shadow" in f.title.lower() for f in result.findings)


def test_heuristic_clean_text():
    analyzer = HeuristicAnalyzer(threshold=50)
    path = Path(__file__).resolve().parents[1] / ".test-data" / "clean.txt"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("hello world\n", encoding="utf-8")
    result = analyzer.analyze(str(path), path.stat().st_size)
    assert not result.suspicious
    assert result.findings == []
