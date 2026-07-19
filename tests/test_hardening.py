"""Tests for the security-hardening fixes: full-file hash, scan truncation,
ONNX absolute-path traversal, zip-bomb band, and API auth/gating/concurrency."""

import hashlib
import zipfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from purser.core.scanner import _sha256
from purser.scanners import archive as archive_mod
from purser.scanners import exfil as exfil_mod
from purser.scanners.exfil import ExfilScanner
from purser.scanners.formats import ONNXScanner, _path_escapes


# -- item 6: full-file hash --------------------------------------------------

def test_sha256_hashes_whole_file(tmp_path: Path):
    data = b"abcdefgh" * 100_000
    p = tmp_path / "m.bin"
    p.write_bytes(data)
    assert _sha256(p) == hashlib.sha256(data).hexdigest()


def test_sha256_tail_change_changes_hash(tmp_path: Path):
    a = tmp_path / "a.bin"
    b = tmp_path / "b.bin"
    a.write_bytes(b"\x00" * 4096 + b"A")
    b.write_bytes(b"\x00" * 4096 + b"B")
    assert _sha256(a) != _sha256(b)


# -- item 5: truncation-aware windowed exfil scan ----------------------------

def test_scan_truncated_emitted(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(exfil_mod, "MAX_SCAN_BYTES", 1024)
    monkeypatch.setattr(exfil_mod, "WINDOW_BYTES", 512)
    p = tmp_path / "big.bin"
    p.write_bytes(b"\x00" * 4096)
    findings = ExfilScanner().scan(p)
    trunc = [f for f in findings if f.rule_id == "SCAN_TRUNCATED"]
    assert trunc and trunc[0].evidence["file_bytes"] == 4096
    assert trunc[0].evidence["scanned_bytes"] <= 1024


def test_no_truncation_under_limit(tmp_path: Path):
    p = tmp_path / "small.bin"
    p.write_bytes(b"\x00" * 4096)
    assert not [f for f in ExfilScanner().scan(p) if f.rule_id == "SCAN_TRUNCATED"]


def test_indicator_found_across_window_seam(tmp_path: Path, monkeypatch):
    # Place a webhook so it straddles the window boundary; overlap must catch it.
    monkeypatch.setattr(exfil_mod, "MAX_SCAN_BYTES", 100 * 1024 * 1024)
    monkeypatch.setattr(exfil_mod, "WINDOW_BYTES", 1024)
    hook = b"https://hooks.slack.com/services/T0001111/B0002222/XXXXXXXXXXXXXXXXXXXXXXXX"
    data = b"\x00" * (1024 - 20) + hook + b"\x00" * 1024
    p = tmp_path / "seam.bin"
    p.write_bytes(data)
    findings = ExfilScanner().scan(p)
    assert any(f.rule_id == "EXFIL_WEBHOOK" for f in findings)


# -- item 10a: ONNX absolute-path / traversal --------------------------------

def _loc(path: bytes) -> bytes:
    return b"location\x12" + bytes([len(path)]) + path


def test_onnx_absolute_location_flagged(tmp_path: Path):
    p = tmp_path / "m.onnx"
    p.write_bytes(b"\x08\x01" + _loc(b"/etc/shadow") + b"\x00" * 8)
    findings = ONNXScanner().scan(p)
    assert any(f.rule_id == "ONNX_EXTERNAL_DATA_TRAVERSAL" for f in findings)


def test_onnx_parent_traversal_flagged(tmp_path: Path):
    p = tmp_path / "m.onnx"
    p.write_bytes(_loc(b"../../secrets.bin"))
    findings = ONNXScanner().scan(p)
    assert any(f.rule_id == "ONNX_EXTERNAL_DATA_TRAVERSAL" for f in findings)


def test_onnx_relative_location_clean(tmp_path: Path):
    p = tmp_path / "m.onnx"
    p.write_bytes(_loc(b"weights.bin"))
    assert not ONNXScanner().scan(p)


def test_onnx_slash_prefixed_node_names_no_false_positive(tmp_path: Path):
    # ONNX node names are legitimately slash-prefixed; must NOT be flagged
    # because they are not anchored on a `location` key.
    p = tmp_path / "m.onnx"
    p.write_bytes(b"/encoder/layer.0/attention/MatMul" * 50)
    assert not [f for f in ONNXScanner().scan(p)
                if f.rule_id == "ONNX_EXTERNAL_DATA_TRAVERSAL"]


@pytest.mark.parametrize("path,escapes", [
    ("weights.bin", False),
    ("sub/dir/weights.bin", False),
    ("../weights.bin", True),
    ("a/../../b", True),
    ("/etc/passwd", True),
    ("C:\\Windows\\x", True),
    ("\\\\host\\share", True),
    ("https://evil.example/x", True),
])
def test_path_escapes(path, escapes):
    assert _path_escapes(path) is escapes


# -- item 10b: zip-bomb band -------------------------------------------------

def test_zip_bomb_high_ratio_mid_size(tmp_path: Path, monkeypatch):
    # A highly compressible ~1 MiB payload: previously passed (under 4 GiB),
    # now trips the ratio trigger once the min-size floor is lowered.
    monkeypatch.setattr(archive_mod, "BOMB_RATIO_MIN_SIZE", 256 * 1024)
    monkeypatch.setattr(archive_mod, "BOMB_RATIO", 50)
    p = tmp_path / "bomb.zip"
    with zipfile.ZipFile(p, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("z", b"\x00" * (1024 * 1024))
    findings = archive_mod.ArchiveScanner().scan(p)
    assert any(f.rule_id == "ARCHIVE_ZIP_BOMB" for f in findings)


def test_normal_zip_not_flagged_as_bomb(tmp_path: Path):
    p = tmp_path / "ok.zip"
    with zipfile.ZipFile(p, "w") as zf:
        zf.writestr("a.txt", "hello world")
    assert not [f for f in archive_mod.ArchiveScanner().scan(p)
                if f.rule_id == "ARCHIVE_ZIP_BOMB"]


# -- item 1: API auth, HF gating, concurrency --------------------------------

def _client(monkeypatch, tmp_path, **env):
    monkeypatch.delenv("PURSER_POLICY", raising=False)
    monkeypatch.setenv("PURSER_SCAN_ROOT", str(tmp_path))
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    from purser.api import app
    return TestClient(app)


def test_auth_required_when_key_set(monkeypatch, tmp_path):
    client = _client(monkeypatch, tmp_path, PURSER_API_KEY="s3cr3t")
    assert client.get("/v1/policy").status_code == 401
    assert client.get("/v1/policy", headers={"X-API-Key": "wrong"}).status_code == 401
    assert client.get("/v1/policy", headers={"X-API-Key": "s3cr3t"}).status_code == 200
    assert client.get(
        "/v1/policy", headers={"Authorization": "Bearer s3cr3t"}
    ).status_code == 200


def test_healthz_never_authenticated(monkeypatch, tmp_path):
    client = _client(monkeypatch, tmp_path, PURSER_API_KEY="s3cr3t")
    assert client.get("/healthz").status_code == 200


def test_open_when_no_key(monkeypatch, tmp_path):
    client = _client(monkeypatch, tmp_path)
    assert client.get("/v1/policy").status_code == 200


def test_hf_disabled_by_default(monkeypatch, tmp_path):
    client = _client(monkeypatch, tmp_path)
    r = client.post("/v1/scan/huggingface", json={"repo_id": "someorg/model"})
    assert r.status_code == 403


def test_hf_allowlist(monkeypatch, tmp_path):
    from purser import api
    assert api._hf_repo_allowed("openai-community/gpt2") is True  # empty allowlist
    monkeypatch.setenv("PURSER_HF_ALLOWLIST", "meta-llama/,google/")
    assert api._hf_repo_allowed("meta-llama/Llama-3") is True
    assert api._hf_repo_allowed("evilcorp/x") is False


def test_concurrency_slot_rejects_when_full():
    from purser.api import _ScanSlot, _scan_slots
    held = []
    try:
        while _scan_slots.acquire(blocking=False):
            held.append(1)
        with pytest.raises(Exception) as ei:
            with _ScanSlot():
                pass
        assert getattr(ei.value, "status_code", None) == 429
    finally:
        for _ in held:
            _scan_slots.release()
