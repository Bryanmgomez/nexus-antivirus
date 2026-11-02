from pathlib import Path
import os

os.environ.setdefault("NEXUS_DATA_DIR", str(Path(__file__).resolve().parents[1] / ".test-data"))

from nexus.engine.signatures import SignatureDatabase, SHA256_RE


def test_bundled_signatures_load():
    db = SignatureDatabase()
    assert db.count >= 1
    assert SHA256_RE.match("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f")
    sig = db.lookup("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f")
    assert sig is not None
    assert sig.name == "EICAR-Test-File"
