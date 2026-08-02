"""Scan orchestrator: walks targets, dispatches scanners, applies policy."""

from __future__ import annotations

import hashlib
import time
from datetime import datetime, timezone
from pathlib import Path

from purser.core import atlas, audit, metrics
from purser.core.deep import DEEP_FORMATS, deep_enabled, run_deep
from purser.core.dispatch import scan_file
from purser.core.findings import FileResult, Finding, ScanReport, Severity, Verdict
from purser.core.formats import MODEL_EXTS, looks_like_binary_model
from purser.core.policy import Policy
from purser.core.provenance import resolve as resolve_provenance
from purser.core.sigstore_verify import IdentityResult
from purser.core.sigstore_verify import verify as verify_sigstore
from purser.core.signing import VerificationResult, verify_target
from purser.signals import SignalContext, collect_signals


def _signature_findings(result: VerificationResult) -> list[Finding]:
    """Translate a signature-verification outcome into findings.

    An absent signature is not itself a finding — policy decides whether that is
    acceptable via `origin.require_signed`. An *invalid* or *untrusted*
    signature always is: it means someone signed the artifact in a way that does
    not check out.
    """
    if result.status in ("verified", "unsigned"):
        return []
    sev = {
        "invalid": Severity.HIGH,
        "revoked": Severity.HIGH,
        "untrusted": Severity.MEDIUM,
        "expired": Severity.MEDIUM,
        "unavailable": Severity.LOW,
    }.get(result.status, Severity.MEDIUM)
    return [Finding(
        rule_id=f"SIGNATURE_{result.status.upper()}",
        severity=sev,
        title=f"Model signature {result.status}: {result.reason}",
        detail="Provenance cannot be trusted from this signature.",
        scanner="signing",
        tags=["provenance"],
        evidence={"key_id": result.key_id, "status": result.status},
    )]

def _sigstore_findings(result: IdentityResult) -> list[Finding]:
    """A present-but-invalid Sigstore bundle is a finding; an absent bundle
    ('unsigned') or a verified one is not — policy decides whether an unsigned
    model is acceptable via `origin.require_signed`."""
    if result.status in ("verified", "unsigned"):
        return []
    sev = {"invalid": Severity.HIGH, "unavailable": Severity.LOW}.get(
        result.status, Severity.MEDIUM)
    return [Finding(
        rule_id=f"SIGSTORE_{result.status.upper()}",
        severity=sev,
        title=f"Sigstore verification {result.status}: {result.reason}",
        detail="A Sigstore bundle is present but its signer identity could not "
               "be verified against the trust root.",
        scanner="sigstore",
        tags=["provenance"],
        evidence={"issuer": result.issuer, "identity": result.identity,
                  "status": result.status},
    )]


SKIP_NAMES = {".git", ".DS_Store", "__pycache__", ".cache"}
# Files never worth scanning as models but common in model repos.
SKIP_EXTS = {".md", ".txt", ".json", ".yaml", ".yml", ".toml", ".cfg", ".gitattributes",
             ".png", ".jpg", ".jpeg", ".gif", ".svg", ".license"}


def _sha256(path: Path) -> str:
    """Full-file SHA-256 — the report hash must be usable as an integrity pin."""
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while chunk := fh.read(4 * 1024 * 1024):
            h.update(chunk)
    return h.hexdigest()


def iter_scannable(target: Path) -> list[Path]:
    if target.is_file():
        return [target]
    files: list[Path] = []
    for p in sorted(target.rglob("*")):
        if not p.is_file():
            continue
        if any(part in SKIP_NAMES for part in p.parts):
            continue
        suffix = p.suffix.lower()
        # Always scan TF.js manifests and HF config JSON (auto_map lives there).
        is_config_json = suffix == ".json" and "config" in p.name.lower()
        if (
            suffix in SKIP_EXTS
            and suffix not in MODEL_EXTS
            and p.name != "model.json"
            and not is_config_json
        ):
            # Don't trust the extension: a payload disguised under a doc/config
            # name (e.g. a pickle called README.md) must still be scanned. Peek
            # the magic bytes before skipping.
            try:
                with p.open("rb") as fh:
                    head = fh.read(16)
            except OSError:
                continue
            if not looks_like_binary_model(head):
                continue
        files.append(p)
    return files


def scan_target(
    target: Path | str,
    policy: Policy | None = None,
    origin: str | None = None,
    publisher: str | None = None,
    repo_id: str | None = None,
    signal_context: "SignalContext | None" = None,
) -> ScanReport:
    """Scan a file or directory and evaluate the policy over the results.

    `signal_context` (where the artifact came from — hub, repo id, revision)
    lets network-using signal sources (`purser.signals`) fetch upstream
    intelligence; without it only offline sources (e.g. loader-CVE mapping)
    apply, and the scan makes no network calls.
    """
    target = Path(target)
    policy = policy or Policy.default()
    started = time.monotonic()
    report = ScanReport(
        target=str(target),
        started_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
    )

    if repo_id:
        report.metadata["repo_id"] = repo_id

    if not target.exists():
        prov = resolve_provenance(
            explicit_origin=origin, publisher=publisher, repo_id=repo_id,
        )
        report.origin = prov.origin
        report.publisher = prov.publisher
        report.metadata["provenance_source"] = prov.source
        report.verdict = Verdict.ERROR
        report.metadata["error"] = f"target does not exist: {target}"
        report.duration_seconds = time.monotonic() - started
        return report

    # Verified provenance (a valid signature) is authoritative and outranks any
    # self-asserted origin/publisher; an *invalid* signature is a finding.
    sig_result = verify_target(target)
    report.signature_findings = _signature_findings(sig_result)
    # Verified-external-root identity (Sigstore/Fulcio/Rekor). Cheap when no
    # bundle is present (returns 'unsigned' before importing sigstore).
    id_result = verify_sigstore(target)
    report.signature_findings += _sigstore_findings(id_result)
    report.metadata["signature_status"] = sig_result.status
    report.metadata["sigstore_status"] = id_result.status

    if sig_result.verified:
        report.origin = sig_result.origin
        report.publisher = sig_result.publisher
        report.provenance_verified = True
        report.metadata["provenance_source"] = "signed"
        report.metadata["signature_key_id"] = sig_result.key_id
    elif id_result.verified:
        # Verified identity from an external root. Country of origin is not
        # implied by an identity, so origin/publisher still resolve via the
        # provenance chain; the verified identity is authoritative for
        # `require_signed` and the `identity` policy.
        report.provenance_verified = True
        report.metadata["provenance_source"] = "sigstore"
        report.metadata["identity"] = id_result.identity
        report.metadata["identity_issuer"] = id_result.issuer
        prov = resolve_provenance(
            target=target, explicit_origin=origin,
            publisher=publisher, repo_id=repo_id,
        )
        report.origin = prov.origin
        report.publisher = prov.publisher
    else:
        prov = resolve_provenance(
            target=target, explicit_origin=origin,
            publisher=publisher, repo_id=repo_id,
        )
        report.origin = prov.origin
        report.publisher = prov.publisher
        report.provenance_verified = False
        report.metadata["provenance_source"] = prov.source

    for path in iter_scannable(target):
        try:
            fmt, findings = scan_file(path)
            for f in findings:
                f.file = str(path)
            report.files.append(FileResult(
                path=str(path),
                format=fmt.value,
                size=path.stat().st_size,
                sha256=_sha256(path),
                findings=findings,
            ))
        except Exception as exc:
            report.files.append(FileResult(
                path=str(path), format="unknown",
                size=path.stat().st_size if path.exists() else 0,
                sha256="", findings=[], error=str(exc),
            ))

    # Optional deep analysis via the separate purser-deep app (env-gated).
    if deep_enabled():
        for fr in report.files:
            if fr.format in DEEP_FORMATS:
                for f in run_deep(Path(fr.path)):
                    f.file = f.file or fr.path
                    report.deep_findings.append(f)
        report.metadata["deep_analysis"] = True

    # External signal sources (upstream verdicts, loader-CVE intel, plugins).
    # Signals run on every scan; each source decides its own applicability —
    # network-using sources gate themselves to hub-fetched scans (a context
    # with source="huggingface"), offline sources apply everywhere.
    ctx = signal_context or SignalContext()
    if ctx.target is None:
        ctx.target = target
    report.signal_findings = collect_signals(ctx)

    report = policy.evaluate(report)
    atlas.tag_report(report)  # ATLAS enrichment (additive tags; PURSER_ATLAS=0 off)
    report.duration_seconds = time.monotonic() - started

    # Observability: metrics (always, cheap) + structured audit (if enabled).
    try:
        metrics.record_scan(report)
        audit.record_scan(report)
    except Exception:
        pass  # telemetry must never break a scan

    return report


EXIT_CODES = {
    Verdict.PASS: 0,
    Verdict.WARN: 0,
    Verdict.FAIL: 1,
    Verdict.BLOCKED: 2,
    Verdict.ERROR: 3,
}
