"""Tests for exfil evasion resistance (item 8) and bounded scanning (item 7)."""

from pathlib import Path

from purser.scanners import exfil as exfil_mod
from purser.scanners.exfil import ExfilScanner


def rules(findings):
    return {f.rule_id for f in findings}


# -- item 8: UTF-16 (wide) string extraction ---------------------------------

def test_utf16_url_detected():
    data = b"\x00\x00" + "http://evil.example.invalid/x".encode("utf-16-le") + b"\x00\x00"
    findings = ExfilScanner().scan_bytes(data)
    assert "EXFIL_URL" in rules(findings)


def test_utf16_be_ip_endpoint_detected():
    data = "203.0.113.7:4444".encode("utf-16-be")
    findings = ExfilScanner().scan_bytes(data)
    assert "EXFIL_IP_ENDPOINT" in rules(findings)


# -- item 8: hex-encoded payloads --------------------------------------------

def test_hex_encoded_payload_detected():
    script = b"import socket\ns=socket.socket()\ns.connect(('10.0.0.1',9001))\n"
    data = b"\x00" * 8 + script.hex().encode() + b"\x00" * 8
    findings = [f for f in ExfilScanner().scan_bytes(data)
                if f.rule_id == "EXFIL_ENCODED_PAYLOAD"]
    assert findings and any(f.severity == exfil_mod.Severity.CRITICAL for f in findings)


def test_sha256_hash_not_flagged_as_hex_payload():
    # A bare 64-char hex hash decodes to 32 random bytes, not text -> ignored.
    data = b"checkpoint sha256: " + (b"ab12cd34" * 8) + b" done"
    findings = [f for f in ExfilScanner().scan_bytes(data)
                if f.rule_id == "EXFIL_ENCODED_PAYLOAD"]
    assert not findings


# -- item 8: configurable / strict host allowlist ----------------------------

def test_allowlisted_host_ignored_by_default():
    data = b"see https://huggingface.co/model for details........"
    assert "EXFIL_URL" not in rules(ExfilScanner().scan_bytes(data))


def test_strict_mode_flags_allowlisted_host(monkeypatch):
    monkeypatch.setenv("PURSER_EXFIL_STRICT", "1")
    data = b"see https://huggingface.co/model for details........"
    assert "EXFIL_URL" in rules(ExfilScanner().scan_bytes(data))


def test_allowlist_override_replaces_builtin(monkeypatch):
    monkeypatch.setenv("PURSER_EXFIL_ALLOWLIST", "internal.corp")
    data = b"fetch https://github.com/org/repo now..............."
    # github.com no longer allowlisted -> flagged
    assert "EXFIL_URL" in rules(ExfilScanner().scan_bytes(data))
    data2 = b"fetch https://internal.corp/model now..............."
    assert "EXFIL_URL" not in rules(ExfilScanner().scan_bytes(data2))


def test_allowlist_add_extends_builtin(monkeypatch):
    monkeypatch.setenv("PURSER_EXFIL_ALLOWLIST_ADD", "mycdn.example")
    data = b"weights at https://mycdn.example/w.bin here.........."
    assert "EXFIL_URL" not in rules(ExfilScanner().scan_bytes(data))
    # built-in still active
    data2 = b"docs at https://huggingface.co/x ...................."
    assert "EXFIL_URL" not in rules(ExfilScanner().scan_bytes(data2))


# -- item 7: bounded findings ------------------------------------------------

def test_findings_capped(monkeypatch):
    monkeypatch.setattr(exfil_mod, "MAX_FINDINGS", 5)
    urls = " ".join(f"http://evil{i}.invalid/x" for i in range(50))
    findings = ExfilScanner().scan_bytes(urls.encode())
    assert len(findings) <= 5


def test_iter_strings_is_lazy():
    import types
    gen = exfil_mod.iter_strings(b"hello world this is a string")
    assert isinstance(gen, types.GeneratorType)


# -- regression: no false positives on random weights, wide+hex enabled ------

def test_random_weights_still_clean(tmp_path: Path):
    import random
    rng = random.Random(1234)
    p = tmp_path / "w.bin"
    p.write_bytes(bytes(rng.randrange(256) for _ in range(512 * 1024)))
    findings = [f for f in ExfilScanner().scan(p)
                if f.severity >= exfil_mod.Severity.MEDIUM]
    assert not findings, [f.rule_id for f in findings]
