"""Model signing and signature verification (item 2: verified provenance).

Turns country-of-origin / publisher from an *unauthenticated claim* into a
*cryptographically verified* fact.

Scheme (dependency-light, offline-verifiable):
  * Ed25519 detached signatures (via `cryptography`; install `purser[sign]`).
  * The signer signs a **canonical manifest** — a sorted map of every file's
    relative POSIX path to its full SHA-256. For a single-file target the
    manifest has one entry.
  * The signature sidecar (`<target>.sig`, or `model.sig` inside a directory)
    carries: `key_id`, `algorithm`, the manifest, and the base64 signature.
  * Verification recomputes the manifest from the *actual* files, requires it to
    match the sidecar manifest byte-for-byte (tamper/extra-file detection), then
    verifies the signature with the public key that the **trust store** binds to
    that `key_id`. Publisher + origin come from the trust-store entry, so they
    are only ever as trustworthy as the key that signed them.

If `cryptography` is not installed, verification returns an explicit
"unavailable" result so a `require_signed` policy fails closed rather than open.
"""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml
from purser.core.env import env_get


def _parse_dt(value: str) -> datetime | None:
    """Parse an ISO date/datetime; return tz-aware UTC or None."""
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)

ALGORITHM = "ed25519"
SIG_SUFFIX = ".sig"
DIR_SIG_NAME = "model.sig"


class SigningError(RuntimeError):
    pass


def _crypto():
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
            Ed25519PublicKey,
        )
    except ImportError as exc:  # pragma: no cover - exercised via monkeypatch
        raise SigningError(
            "signing requires the 'cryptography' package; install purser[sign]"
        ) from exc
    return (InvalidSignature, serialization, Ed25519PrivateKey, Ed25519PublicKey)


def crypto_available() -> bool:
    try:
        _crypto()
        return True
    except SigningError:
        return False


# --------------------------------------------------------------------- manifest

def _file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while chunk := fh.read(4 * 1024 * 1024):
            h.update(chunk)
    return h.hexdigest()


def compute_manifest(target: Path) -> dict[str, str]:
    """Map of relative POSIX path -> sha256 for every file under target.

    Independent of scan skip-lists: a signature must cover *all* files so an
    attacker cannot smuggle in an unsigned one.
    """
    target = Path(target)
    if target.is_file():
        return {target.name: _file_sha256(target)}
    manifest: dict[str, str] = {}
    for p in sorted(target.rglob("*")):
        if p.is_file() and p.name != DIR_SIG_NAME and not p.is_symlink():
            rel = p.relative_to(target).as_posix()
            manifest[rel] = _file_sha256(p)
    return manifest


def _canonical(manifest: dict[str, str]) -> bytes:
    return json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()


# ----------------------------------------------------------------------- keys

def generate_keypair() -> tuple[bytes, bytes]:
    """Return (private_pem, public_pem) for a fresh Ed25519 key."""
    _, serialization, Ed25519PrivateKey, _ = _crypto()
    priv = Ed25519PrivateKey.generate()
    priv_pem = priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    pub_pem = priv.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return priv_pem, pub_pem


def _load_private(pem: bytes):
    _, serialization, _, _ = _crypto()
    return serialization.load_pem_private_key(pem, password=None)


def _load_public(pem: bytes):
    _, serialization, _, _ = _crypto()
    return serialization.load_pem_public_key(pem)


# ------------------------------------------------------------------ signatures

@dataclass
class Signature:
    key_id: str
    algorithm: str
    manifest: dict[str, str]
    signature_b64: str
    created: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "key_id": self.key_id,
            "algorithm": self.algorithm,
            "created": self.created,
            "manifest": self.manifest,
            "signature": self.signature_b64,
        }


def sidecar_path(target: Path) -> Path:
    target = Path(target)
    if target.is_dir():
        return target / DIR_SIG_NAME
    return target.with_name(target.name + SIG_SUFFIX)


def sign_target(target: Path, private_key_pem: bytes, key_id: str,
                created: str = "") -> Signature:
    if not key_id:
        raise SigningError("key_id is required")
    manifest = compute_manifest(Path(target))
    priv = _load_private(private_key_pem)
    sig = priv.sign(_canonical(manifest))
    return Signature(
        key_id=key_id,
        algorithm=ALGORITHM,
        manifest=manifest,
        signature_b64=base64.b64encode(sig).decode(),
        created=created,
    )


def write_signature(target: Path, private_key_pem: bytes, key_id: str,
                    created: str = "") -> Path:
    signature = sign_target(target, private_key_pem, key_id, created=created)
    out = sidecar_path(Path(target))
    out.write_text(json.dumps(signature.to_dict(), indent=2))
    return out


def load_signature(target: Path) -> Signature | None:
    out = sidecar_path(Path(target))
    if not out.is_file():
        return None
    try:
        doc = json.loads(out.read_text())
    except (json.JSONDecodeError, OSError):
        return None
    if not isinstance(doc, dict) or "signature" not in doc:
        return None
    return Signature(
        key_id=str(doc.get("key_id", "")),
        algorithm=str(doc.get("algorithm", "")),
        manifest=doc.get("manifest", {}) or {},
        signature_b64=str(doc.get("signature", "")),
        created=str(doc.get("created", "")),
    )


# ----------------------------------------------------------------- trust store

def load_trust_store(path: str | Path | None = None) -> dict[str, dict[str, str]]:
    """Load key_id -> {publisher, origin, public_key} from YAML.

    Search order: explicit path, PURSER_TRUST_STORE, /etc/purser/trust_store.yaml.
    """
    candidates: list[Path] = []
    if path:
        candidates.append(Path(path))
    env = env_get("TRUST_STORE")
    if env:
        candidates.append(Path(env))
    candidates.append(Path("/etc/purser/trust_store.yaml"))
    for cand in candidates:
        if cand.is_file():
            doc = yaml.safe_load(cand.read_text()) or {}
            store: dict[str, dict[str, str]] = {}
            for entry in doc.get("keys", []) or []:
                kid = str(entry.get("key_id", ""))
                if not kid:
                    continue
                store[kid] = {
                    "publisher": str(entry.get("publisher", "")),
                    "origin": str(entry.get("origin", "")).upper(),
                    "public_key": str(entry.get("public_key", "")),
                    # Optional lifecycle controls:
                    "revoked": str(bool(entry.get("revoked", False))),
                    "not_before": str(entry.get("not_before", "")),
                    "not_after": str(entry.get("not_after", "")),
                }
            return store
    return {}


# --------------------------------------------------------------- verification

@dataclass
class VerificationResult:
    status: str  # verified|invalid|untrusted|unsigned|unavailable|revoked|expired
    reason: str = ""
    key_id: str = ""
    publisher: str | None = None
    origin: str | None = None

    @property
    def verified(self) -> bool:
        return self.status == "verified"

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "reason": self.reason,
            "key_id": self.key_id,
            "publisher": self.publisher,
            "origin": self.origin,
        }


def verify_target(target: Path, trust_store: dict[str, dict[str, str]] | None = None,
                  now: datetime | None = None) -> VerificationResult:
    """Verify the signature sidecar for target against the trust store."""
    signature = load_signature(Path(target))
    if signature is None:
        return VerificationResult("unsigned", "no signature sidecar found")
    if not crypto_available():
        return VerificationResult(
            "unavailable", "cryptography not installed; cannot verify signature",
            key_id=signature.key_id,
        )
    if signature.algorithm != ALGORITHM:
        return VerificationResult(
            "invalid", f"unsupported algorithm {signature.algorithm!r}",
            key_id=signature.key_id,
        )

    store = trust_store if trust_store is not None else load_trust_store()
    entry = store.get(signature.key_id)
    if entry is None:
        return VerificationResult(
            "untrusted", f"key_id {signature.key_id!r} is not in the trust store",
            key_id=signature.key_id,
        )

    # Key lifecycle: revocation and validity window (checked against the
    # signature's `created` timestamp, falling back to the current time).
    if str(entry.get("revoked", "")).lower() in ("true", "1", "yes"):
        return VerificationResult(
            "revoked", f"key_id {signature.key_id!r} is revoked in the trust store",
            key_id=signature.key_id,
        )
    when = _parse_dt(signature.created) or (now or datetime.now(timezone.utc))
    not_before = _parse_dt(entry.get("not_before", ""))
    not_after = _parse_dt(entry.get("not_after", ""))
    if not_before and when < not_before:
        return VerificationResult(
            "expired", f"signed {when.date()} before key validity starts "
            f"({not_before.date()})", key_id=signature.key_id,
        )
    if not_after and when > not_after:
        return VerificationResult(
            "expired", f"signed {when.date()} after key validity ends "
            f"({not_after.date()})", key_id=signature.key_id,
        )

    # 1) actual files must match the signed manifest exactly
    actual = compute_manifest(Path(target))
    if actual != signature.manifest:
        return VerificationResult(
            "invalid",
            "file manifest does not match the signed manifest "
            "(content changed, or files added/removed)",
            key_id=signature.key_id,
        )

    # 2) signature must verify under the trust-store public key
    InvalidSignature, _, _, _ = _crypto()
    try:
        pub = _load_public(entry["public_key"].encode())
        pub.verify(base64.b64decode(signature.signature_b64), _canonical(signature.manifest))
    except InvalidSignature:
        return VerificationResult(
            "invalid", "signature does not verify under the trusted public key",
            key_id=signature.key_id,
        )
    except Exception as exc:  # malformed key/signature material
        return VerificationResult(
            "invalid", f"verification error: {exc}", key_id=signature.key_id,
        )

    return VerificationResult(
        "verified", "signature verified against trust store",
        key_id=signature.key_id,
        publisher=entry.get("publisher") or None,
        origin=entry.get("origin") or None,
    )
