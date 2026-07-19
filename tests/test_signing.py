"""Tests for model signing / verified provenance (item 2)."""

import pickle
from pathlib import Path

import pytest

from purser.core.findings import Verdict
from purser.core.policy import Policy
from purser.core.scanner import scan_target
from purser.core.signing import (
    generate_keypair,
    verify_target,
    write_signature,
)

pytest.importorskip("cryptography")


@pytest.fixture
def keypair():
    return generate_keypair()  # (private_pem, public_pem)


@pytest.fixture
def trust_store(keypair):
    _, pub = keypair
    return {"acme-2026": {"publisher": "acme-labs", "origin": "US",
                          "public_key": pub.decode()}}


@pytest.fixture
def signed_model(tmp_path: Path, keypair):
    priv, _ = keypair
    p = tmp_path / "model.pkl"
    p.write_bytes(pickle.dumps({"weights": [1.0, 2.0]}))
    write_signature(p, priv, "acme-2026")
    return p


# -- round trip --------------------------------------------------------------

def test_sign_and_verify(signed_model, trust_store):
    result = verify_target(signed_model, trust_store)
    assert result.verified
    assert result.publisher == "acme-labs"
    assert result.origin == "US"


def test_verify_directory(tmp_path: Path, keypair, trust_store):
    priv, _ = keypair
    d = tmp_path / "repo"
    d.mkdir()
    (d / "a.bin").write_bytes(b"\x00" * 100)
    (d / "sub").mkdir()
    (d / "sub" / "b.bin").write_bytes(b"\x01" * 100)
    write_signature(d, priv, "acme-2026")
    assert verify_target(d, trust_store).verified


# -- tamper / trust failures -------------------------------------------------

def test_tamper_detected(signed_model, trust_store):
    signed_model.write_bytes(b"tampered")
    result = verify_target(signed_model, trust_store)
    assert result.status == "invalid"


def test_added_file_detected(tmp_path: Path, keypair, trust_store):
    priv, _ = keypair
    d = tmp_path / "repo"
    d.mkdir()
    (d / "a.bin").write_bytes(b"\x00" * 100)
    write_signature(d, priv, "acme-2026")
    (d / "evil.pkl").write_bytes(b"\x80\x04}")  # unsigned smuggled file
    assert verify_target(d, trust_store).status == "invalid"


def test_untrusted_key(signed_model):
    result = verify_target(signed_model, {})  # empty trust store
    assert result.status == "untrusted"


def test_wrong_public_key(signed_model):
    _, other_pub = generate_keypair()
    bad_store = {"acme-2026": {"publisher": "acme-labs", "origin": "US",
                               "public_key": other_pub.decode()}}
    assert verify_target(signed_model, bad_store).status == "invalid"


def test_unsigned(tmp_path: Path, trust_store):
    p = tmp_path / "model.pkl"
    p.write_bytes(pickle.dumps({"w": [1]}))
    assert verify_target(p, trust_store).status == "unsigned"


# -- integration with scan + policy ------------------------------------------

def test_scan_reports_verified_provenance(signed_model, trust_store, monkeypatch):
    monkeypatch.setattr("purser.core.scanner.verify_target",
                        lambda t: verify_target(t, trust_store))
    report = scan_target(signed_model)
    assert report.provenance_verified is True
    assert report.origin == "US"
    assert report.publisher == "acme-labs"


def test_require_signed_blocks_unsigned(tmp_path: Path):
    p = tmp_path / "model.pkl"
    p.write_bytes(pickle.dumps({"w": [1]}))
    policy = Policy.from_dict({
        "name": "signed-only",
        "origin": {"require_signed": True},
    })
    report = scan_target(p, policy=policy)
    assert report.verdict == Verdict.BLOCKED
    assert any(f.rule_id == "POLICY_SIGNATURE_REQUIRED" for f in report.policy_findings)


def test_require_signed_allows_verified(signed_model, trust_store, monkeypatch):
    monkeypatch.setattr("purser.core.scanner.verify_target",
                        lambda t: verify_target(t, trust_store))
    policy = Policy.from_dict({
        "name": "signed-only",
        "fail_on": {"severity": "HIGH"},
        "origin": {"mode": "allowlist", "countries": ["US"],
                   "unknown_origin": "deny", "require_signed": True},
    })
    report = scan_target(signed_model, policy=policy)
    assert report.verdict in (Verdict.PASS, Verdict.WARN)
    assert report.provenance_verified


def test_invalid_signature_is_a_finding(signed_model, trust_store, monkeypatch):
    signed_model.write_bytes(b"tampered content")
    monkeypatch.setattr("purser.core.scanner.verify_target",
                        lambda t: verify_target(t, trust_store))
    report = scan_target(signed_model)
    assert any(f.rule_id == "SIGNATURE_INVALID" for f in report.signature_findings)


def test_verified_origin_overrides_claimed(signed_model, trust_store, monkeypatch):
    # Attacker passes --origin US but signature binds a different (blocked) origin.
    store = dict(trust_store)
    store["acme-2026"] = {**store["acme-2026"], "origin": "CN"}
    monkeypatch.setattr("purser.core.scanner.verify_target",
                        lambda t: verify_target(t, store))
    policy = Policy.from_dict({"origin": {"mode": "blocklist", "countries": ["CN"]}})
    report = scan_target(signed_model, policy=policy, origin="US")
    # verified CN wins over claimed US -> blocked
    assert report.origin == "CN"
    assert report.verdict == Verdict.BLOCKED
