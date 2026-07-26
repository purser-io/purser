"""Sigstore (Fulcio/Rekor) verified-identity provenance — roadmap item 2.

The Ed25519 trust store (`core/signing.py`) binds `key -> publisher/country` by
an **operator assertion**. This module instead derives identity from a
**verified external root**: a Sigstore bundle whose signer identity (OIDC issuer
+ subject) is attested by Fulcio and logged in Rekor's transparency log. It is
verified **offline** against a vendored trust root
(`purser/data/sigstore_trusted_root.json`) — no network at scan time.

Bundle sidecar discovered next to the model:
  * single file:  ``<target>.sigstore.json`` / ``<target>.sigstore``
                  (bundle over the file's bytes — the usual `cosign sign-blob`)
  * directory:    ``model.sigstore.json`` / ``model.sigstore``
                  (bundle over the canonical file manifest, matching signing.py)

Signing is intentionally external (cosign / sigstore keyless needs a browser
OIDC flow). If the ``sigstore`` package isn't installed we return status
``unavailable`` so a ``require_signed`` policy fails **closed**.

This also covers HuggingFace-signed models, whose model-signing emits standard
Sigstore bundles. (Legacy HF GPG *commit* signatures are online-only and out of
scope for an offline file scanner.)
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from typing import Any

from purser.core.env import env_get
from purser.core.signing import _canonical, compute_manifest

_FILE_SUFFIXES = (".sigstore.json", ".sigstore")
_DIR_NAMES = ("model.sigstore.json", "model.sigstore")
# Fulcio OIDC-issuer certificate extensions (v2 is a DER UTF8String; v1 raw).
_OID_ISSUER_V2 = "1.3.6.1.4.1.57264.1.8"
_OID_ISSUER_V1 = "1.3.6.1.4.1.57264.1.1"


def sigstore_available() -> bool:
    try:
        import sigstore  # noqa: F401
        return True
    except ImportError:
        return False


@dataclass
class IdentityResult:
    """Outcome of Sigstore verification. `identity` is the verified SAN (an
    email, a workflow URI, or a username); `issuer` is the OIDC issuer."""

    status: str            # verified | unsigned | unavailable | invalid
    reason: str = ""
    issuer: str | None = None
    identity: str | None = None

    @property
    def verified(self) -> bool:
        return self.status == "verified"

    def to_dict(self) -> dict[str, Any]:
        return {"status": self.status, "reason": self.reason,
                "issuer": self.issuer, "identity": self.identity}


def bundle_path(target: Path) -> Path | None:
    """Locate a Sigstore bundle sidecar for target, or None."""
    target = Path(target)
    if target.is_dir():
        for name in _DIR_NAMES:
            cand = target / name
            if cand.is_file():
                return cand
        return None
    for suffix in _FILE_SUFFIXES:
        cand = target.with_name(target.name + suffix)
        if cand.is_file():
            return cand
    return None


def _trusted_root_file() -> str:
    override = env_get("SIGSTORE_TRUST_ROOT")
    if override:
        return override
    return str(resources.files("purser.data") / "sigstore_trusted_root.json")


def _signed_input(target: Path):
    """The (bytes | Hashed) the bundle is expected to cover: the canonical
    manifest for a directory, or a prehash of the file (avoids loading big
    weights)."""
    from sigstore.hashes import Hashed, HashAlgorithm

    target = Path(target)
    if target.is_dir():
        return _canonical(compute_manifest(target))
    h = hashlib.sha256()
    with open(target, "rb") as fh:
        while chunk := fh.read(4 * 1024 * 1024):
            h.update(chunk)
    return Hashed(algorithm=HashAlgorithm.SHA2_256, digest=h.digest())


def _der_utf8(raw: bytes) -> str:
    """Minimal DER UTF8String decode (issuers are short; single-byte length)."""
    if len(raw) >= 2 and raw[0] == 0x0C and raw[1] < 0x80:
        return raw[2:2 + raw[1]].decode("utf-8", "replace")
    return raw.decode("utf-8", "replace")


def _extract_identity(cert) -> tuple[str | None, str | None]:
    """(issuer, san) from a Fulcio leaf certificate."""
    from cryptography import x509

    issuer = None
    for oid, is_v2 in ((_OID_ISSUER_V2, True), (_OID_ISSUER_V1, False)):
        try:
            ext = cert.extensions.get_extension_for_oid(x509.ObjectIdentifier(oid))
        except x509.ExtensionNotFound:
            continue
        raw = getattr(ext.value, "value", b"")
        issuer = _der_utf8(raw) if is_v2 else raw.decode("utf-8", "replace")
        if issuer:
            break

    san = None
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        vals = (ext.value.get_values_for_type(x509.RFC822Name)
                + ext.value.get_values_for_type(x509.UniformResourceIdentifier))
        if vals:
            san = vals[0]
        else:
            for name in ext.value:
                if isinstance(name, x509.OtherName):
                    san = _der_utf8(name.value)
                    break
    except x509.ExtensionNotFound:
        pass
    return issuer, san


def verify(target: Path) -> IdentityResult:
    """Verify a model's Sigstore bundle (offline) and return its verified
    identity. Returns quickly with `unsigned` when no bundle is present, so
    this is cheap to call on every scan."""
    bundle_file = bundle_path(Path(target))
    if bundle_file is None:
        return IdentityResult("unsigned", "no Sigstore bundle sidecar found")
    if not sigstore_available():
        return IdentityResult(
            "unavailable",
            "sigstore not installed; cannot verify (install purser[sigstore])")

    try:
        from sigstore.models import Bundle, TrustedRoot
        from sigstore.verify import Verifier, policy
    except ImportError:
        return IdentityResult("unavailable", "sigstore import failed")

    try:
        trusted_root = TrustedRoot.from_file(_trusted_root_file())
        verifier = Verifier(trusted_root=trusted_root)
        bundle = Bundle.from_json(bundle_file.read_bytes())
    except Exception as exc:  # malformed bundle / trust root
        return IdentityResult("invalid", f"could not load bundle or trust root: {exc}")

    try:
        issuer, san = _extract_identity(bundle.signing_certificate)
    except Exception:
        issuer, san = (None, None)

    # Crypto + transparency-log verification with a no-op identity policy; the
    # issuer/SAN allow/blocklist is enforced in the Purser policy engine, so it
    # lives alongside the origin/format/publisher controls.
    try:
        verifier.verify_artifact(_signed_input(Path(target)), bundle, policy.UnsafeNoOp())
    except Exception as exc:
        return IdentityResult("invalid", f"sigstore verification failed: {exc}",
                              issuer=issuer, identity=san)

    return IdentityResult("verified", "identity verified against the Sigstore trust root",
                          issuer=issuer, identity=san)
