"""Sigstore verified-identity provenance (roadmap item 2).

Purser's own logic (scanner wiring, `identity` policy, `require_signed`,
findings, degrade) is tested deterministically with a stubbed verifier — no
network, no `sigstore` needed. The module's offline paths are exercised where
`sigstore` is installed, and the real keyless sign+verify roundtrip runs only in
CI with an ambient OIDC identity.
"""

from __future__ import annotations

import hashlib
import pickle

import pytest

from purser.core.policy import Policy, PolicyError
from purser.core.scanner import scan_target
from purser.core.sigstore_verify import IdentityResult, bundle_path, verify

GHA_ISS = "https://token.actions.githubusercontent.com"
SAN_OK = "https://github.com/purser-io/purser/.github/workflows/release.yml@refs/tags/v0.1.3"


def _benign(tmp_path):
    p = tmp_path / "m.pkl"
    p.write_bytes(pickle.dumps({"w": [1.0]}))
    return p


def _stub(monkeypatch, result: IdentityResult):
    monkeypatch.setattr("purser.core.scanner.verify_sigstore", lambda t: result)


# --------------------------- scanner wiring (stubbed) -----------------------

def test_verified_identity_sets_provenance(monkeypatch, tmp_path):
    _stub(monkeypatch, IdentityResult("verified", "ok", issuer=GHA_ISS, identity=SAN_OK))
    r = scan_target(_benign(tmp_path))
    assert r.provenance_verified is True
    assert r.metadata["provenance_source"] == "sigstore"
    assert r.metadata["identity"] == SAN_OK
    assert r.metadata["identity_issuer"] == GHA_ISS
    assert r.metadata["sigstore_status"] == "verified"


def test_no_bundle_is_clean(monkeypatch, tmp_path):
    _stub(monkeypatch, IdentityResult("unsigned", "none"))
    r = scan_target(_benign(tmp_path))
    assert r.provenance_verified is False
    assert not any(f.rule_id.startswith("SIGSTORE_") for f in r.all_findings)


def test_invalid_bundle_is_a_finding(monkeypatch, tmp_path):
    _stub(monkeypatch, IdentityResult("invalid", "bad sig", issuer=GHA_ISS, identity=SAN_OK))
    r = scan_target(_benign(tmp_path))
    assert any(f.rule_id == "SIGSTORE_INVALID" and f.severity.name == "HIGH"
               for f in r.all_findings)


# --------------------------- require_signed --------------------------------

def test_require_signed_satisfied_by_sigstore(monkeypatch, tmp_path):
    _stub(monkeypatch, IdentityResult("verified", "ok", issuer=GHA_ISS, identity=SAN_OK))
    pol = Policy.from_dict({"origin": {"require_signed": True}})
    assert scan_target(_benign(tmp_path), policy=pol).verdict.name != "BLOCKED"


def test_require_signed_fails_closed_when_unavailable(monkeypatch, tmp_path):
    _stub(monkeypatch, IdentityResult("unavailable", "sigstore not installed"))
    pol = Policy.from_dict({"origin": {"require_signed": True}})
    r = scan_target(_benign(tmp_path), policy=pol)
    assert r.verdict.name == "BLOCKED"
    assert any(f.rule_id == "SIGSTORE_UNAVAILABLE" for f in r.all_findings)


# --------------------------- identity policy -------------------------------

def _identity_policy(mode, **kw):
    return Policy.from_dict({"identity": {"mode": mode, **kw}})


def test_identity_allowlist_blocks_unlisted(monkeypatch, tmp_path):
    _stub(monkeypatch, IdentityResult("verified", "ok", issuer=GHA_ISS,
                                      identity="https://github.com/evil/x@refs/heads/main"))
    pol = _identity_policy("allowlist", issuers=[GHA_ISS],
                           identities=["https://github.com/purser-io/*"])
    r = scan_target(_benign(tmp_path), policy=pol)
    assert r.verdict.name == "BLOCKED"
    assert any(f.rule_id == "POLICY_IDENTITY_BLOCKED" for f in r.policy_findings)


def test_identity_allowlist_permits_listed(monkeypatch, tmp_path):
    _stub(monkeypatch, IdentityResult("verified", "ok", issuer=GHA_ISS, identity=SAN_OK))
    pol = _identity_policy("allowlist", issuers=[GHA_ISS],
                           identities=["https://github.com/purser-io/*"])
    r = scan_target(_benign(tmp_path), policy=pol)
    assert not any(f.rule_id == "POLICY_IDENTITY_BLOCKED" for f in r.policy_findings)


def test_identity_blocklist(monkeypatch, tmp_path):
    _stub(monkeypatch, IdentityResult("verified", "ok",
                                      issuer="https://accounts.google.com",
                                      identity="attacker@evil.example"))
    pol = _identity_policy("blocklist", identities=["*@evil.example"])
    assert scan_target(_benign(tmp_path), policy=pol).verdict.name == "BLOCKED"


def test_identity_policy_noop_without_verified_identity(monkeypatch, tmp_path):
    _stub(monkeypatch, IdentityResult("unsigned", "none"))
    pol = _identity_policy("allowlist", identities=["x/*"])
    r = scan_target(_benign(tmp_path), policy=pol)
    assert not any(f.rule_id == "POLICY_IDENTITY_BLOCKED" for f in r.policy_findings)


def test_policy_identity_validation_and_roundtrip():
    with pytest.raises(PolicyError):
        Policy.from_dict({"identity": {"mode": "allowlist"}})  # needs issuers/identities
    d = Policy.from_dict({"identity": {"mode": "blocklist",
                                       "identities": ["*@evil"]}}).to_dict()
    assert d["identity"]["mode"] == "blocklist"
    assert d["identity"]["identities"] == ["*@evil"]


# --------------------------- module (needs sigstore) ------------------------

def test_bundle_path_discovery(tmp_path):
    f = tmp_path / "a.bin"
    f.write_bytes(b"x")
    assert bundle_path(f) is None
    (tmp_path / "a.bin.sigstore.json").write_text("{}")
    assert bundle_path(f) is not None
    d = tmp_path / "dir"
    d.mkdir()
    (d / "model.sigstore.json").write_text("{}")
    assert bundle_path(d) is not None


def test_verify_unsigned(tmp_path):
    f = tmp_path / "m.safetensors"
    f.write_bytes(b"\x00" * 16)
    assert verify(f).status == "unsigned"


def test_trust_root_loads_offline():
    pytest.importorskip("sigstore")
    from sigstore.models import TrustedRoot

    from purser.core.sigstore_verify import _trusted_root_file
    TrustedRoot.from_file(_trusted_root_file())  # no exception => vendored root is valid


def test_verify_malformed_bundle(tmp_path):
    pytest.importorskip("sigstore")
    f = tmp_path / "m.safetensors"
    f.write_bytes(b"\x00" * 16)
    (tmp_path / "m.safetensors.sigstore.json").write_text("{not a bundle}")
    assert verify(f).status == "invalid"


# --------------------------- real keyless roundtrip (CI only) ---------------

def test_sigstore_real_keyless_roundtrip(tmp_path):
    pytest.importorskip("sigstore")
    from sigstore.hashes import Hashed, HashAlgorithm
    from sigstore.models import DEFAULT_TUF_URL, ClientTrustConfig
    from sigstore.oidc import IdentityToken, detect_credential
    from sigstore.sign import SigningContext

    try:
        raw = detect_credential()
    except Exception:
        raw = None
    if not raw:
        pytest.skip("no ambient OIDC identity (runs in CI with id-token: write)")

    blob = tmp_path / "model.bin"
    blob.write_bytes(b"hello purser sigstore")
    digest = hashlib.sha256(blob.read_bytes()).digest()
    ctx = SigningContext.from_trust_config(ClientTrustConfig.from_tuf(DEFAULT_TUF_URL))
    with ctx.signer(IdentityToken(raw)) as signer:
        bundle = signer.sign_artifact(Hashed(algorithm=HashAlgorithm.SHA2_256, digest=digest))
    (tmp_path / "model.bin.sigstore.json").write_text(bundle.to_json())

    # Verified offline against the vendored trust root — also asserts the
    # vendored root is still current with production (a drift signal if not).
    r = verify(blob)
    assert r.verified, r.reason
    assert r.issuer and r.identity
