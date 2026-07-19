"""Tests for the purser-deep companion: gadget-chain + weight analyzers,
core integration, and the standalone service."""

import json
import random
import struct
from pathlib import Path

from fastapi.testclient import TestClient

from purser.core.findings import Verdict
from purser.core.scanner import scan_target
from purser_deep.analyzers import gadget, weights
from purser_deep.scan import deep_scan_file


def rules(fs):
    return {f.rule_id for f in fs}


# -- helpers -----------------------------------------------------------------

def make_safetensors(tensors: dict) -> bytes:
    """tensors: name -> (dtype, shape, raw_bytes)."""
    header, data, off = {}, b"", 0
    for name, (dtype, shape, raw) in tensors.items():
        header[name] = {"dtype": dtype, "shape": shape, "data_offsets": [off, off + len(raw)]}
        data += raw
        off += len(raw)
    hj = json.dumps(header).encode()
    return struct.pack("<Q", len(hj)) + hj + data


def f32_lowbyte_message(msg: bytes) -> bytes:
    """One float32 per byte, with that byte as the little-endian low byte."""
    return b"".join(bytes([c, 0x00, 0x00, 0x3e]) for c in msg)  # ~0.12, finite


# -- gadget analyzer ---------------------------------------------------------

def test_gadget_pivot_detected():
    # PROTO 4; 'builtins'; 'getattr'; STACK_GLOBAL; EMPTY_TUPLE; REDUCE; STOP
    data = b"\x80\x04\x8c\x08builtins\x8c\x07getattr\x93)R."
    fs = gadget.analyze(data)
    assert "DEEP_GADGET_PIVOT" in rules(fs)


def test_gadget_deep_attribute_import():
    # a.b.c.d.e via STACK_GLOBAL (module 'a.b.c.d', name 'e')
    data = b"\x80\x04\x8c\x07a.b.c.d\x8c\x01e\x93."
    fs = gadget.analyze(data)
    assert "DEEP_GADGET_DEEP_IMPORT" in rules(fs)


def test_gadget_benign_pickle_quiet():
    import pickle
    fs = gadget.analyze(pickle.dumps({"w": [1.0, 2.0], "layers": ("a", "b")}))
    assert not [f for f in fs if f.severity.name in ("HIGH", "CRITICAL")]


# -- weight stego / tamper ---------------------------------------------------

def test_weights_stego_detected(tmp_path: Path):
    msg = b"https://evil.exfil.invalid/steal-me-now-please"
    blob = make_safetensors({"emb": ("F32", [len(msg)], f32_lowbyte_message(msg))})
    p = tmp_path / "m.safetensors"
    p.write_bytes(blob)
    fs = weights.analyze_file(p)
    assert "DEEP_WEIGHTS_STEGO" in rules(fs)


def test_weights_clean_no_stego(tmp_path: Path):
    rng = random.Random(7)
    n = 4096
    raw = bytes(rng.randrange(256) for _ in range(4 * n))
    blob = make_safetensors({"w": ("F32", [n], raw)})
    p = tmp_path / "clean.safetensors"
    p.write_bytes(blob)
    fs = [f for f in weights.analyze_file(p) if f.rule_id == "DEEP_WEIGHTS_STEGO"]
    assert not fs


def test_weights_malformed_size(tmp_path: Path):
    # declare shape [10] F32 (40 bytes) but provide 8 bytes
    blob = make_safetensors({"w": ("F32", [10], b"\x00" * 8)})
    p = tmp_path / "bad.safetensors"
    p.write_bytes(blob)
    assert "DEEP_WEIGHTS_MALFORMED" in rules(weights.analyze_file(p))


def test_deep_scan_dispatch(tmp_path: Path):
    msg = b"http://10.0.0.9/beacon-callback-endpoint"
    p = tmp_path / "m.safetensors"
    p.write_bytes(make_safetensors({"t": ("F32", [len(msg)], f32_lowbyte_message(msg))}))
    assert "DEEP_WEIGHTS_STEGO" in rules(deep_scan_file(p))


# -- core integration --------------------------------------------------------

def test_disabled_by_default(tmp_path: Path):
    p = tmp_path / "m.safetensors"
    msg = b"https://evil.exfil.invalid/steal-me-now-please"
    p.write_bytes(make_safetensors({"t": ("F32", [len(msg)], f32_lowbyte_message(msg))}))
    report = scan_target(p)
    assert report.deep_findings == []


def test_enabled_inprocess_flags_stego(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("PURSER_ENABLE_DEEP", "1")
    monkeypatch.delenv("PURSER_DEEP_URL", raising=False)
    p = tmp_path / "m.safetensors"
    msg = b"https://evil.exfil.invalid/steal-me-now-please"
    p.write_bytes(make_safetensors({"t": ("F32", [len(msg)], f32_lowbyte_message(msg))}))
    report = scan_target(p)
    assert "DEEP_WEIGHTS_STEGO" in {f.rule_id for f in report.deep_findings}
    assert report.verdict == Verdict.FAIL          # HIGH finding fails default policy


def test_deep_findings_in_report_dict(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("PURSER_ENABLE_DEEP", "1")
    monkeypatch.delenv("PURSER_DEEP_URL", raising=False)
    p = tmp_path / "m.safetensors"
    msg = b"https://evil.exfil.invalid/steal-me-now-please"
    p.write_bytes(make_safetensors({"t": ("F32", [len(msg)], f32_lowbyte_message(msg))}))
    d = scan_target(p).to_dict()
    assert d["metadata"].get("deep_analysis") is True
    assert any(f["rule_id"] == "DEEP_WEIGHTS_STEGO" for f in d["deep_findings"])


# -- standalone service ------------------------------------------------------

def test_deep_service(tmp_path: Path, monkeypatch):
    monkeypatch.delenv("PURSER_API_KEY", raising=False)
    from purser_deep.api import app
    client = TestClient(app)
    assert client.get("/healthz").json()["service"] == "purser-deep"
    msg = b"https://evil.exfil.invalid/steal-me-now-please"
    blob = make_safetensors({"t": ("F32", [len(msg)], f32_lowbyte_message(msg))})
    r = client.post("/v1/deep-scan", content=blob,
                    headers={"X-Filename": "m.safetensors"})
    assert r.status_code == 200
    assert any(f["rule_id"] == "DEEP_WEIGHTS_STEGO" for f in r.json()["findings"])
