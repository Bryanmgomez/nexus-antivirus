import os
from pathlib import Path

os.environ.setdefault("NEXUS_DATA_DIR", str(Path(__file__).resolve().parents[1] / ".test-data"))

from nexus.database import Database
from nexus.security.quarantine import QuarantineManager


def test_quarantine_roundtrip(tmp_path):
    data_dir = Path(os.environ["NEXUS_DATA_DIR"])
    data_dir.mkdir(parents=True, exist_ok=True)
    db = Database(data_dir / "test.db")
    # ensure schema
    qm = QuarantineManager(db, storage_dir=tmp_path / "q")
    source = tmp_path / "sample.txt"
    content = b"hello quarantine world"
    source.write_bytes(content)
    import hashlib
    expected = hashlib.sha256(content).hexdigest()
    entry = qm.quarantine_file(str(source), "Test", "test", expected, "details")
    assert entry.id is not None
    assert not source.exists()
    restored = qm.restore(entry.id)
    assert restored.exists()
    assert restored.read_bytes() == content
    assert qm.list_entries() == []
