"""Scan orchestrator: walks targets, dispatches scanners, applies policy."""

from __future__ import annotations

import hashlib
import time
from datetime import datetime, timezone
from pathlib import Path

from purser.core import audit, metrics
from purser.core.deep import DEEP_FORMATS, deep_enabled, run_deep
from purser.core.dispatch import scan_file
from purser.core.findings import FileResult, Finding, ScanReport, Severity, Verdict
from purser.core.formats import MODEL_EXTS
from purser.core.policy import Policy
from purser.core.provenance import resolve as resolve_provenance
from purser.core.signing import VerificationResult, verify_target


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

SKIP_NAMES = {".git", ".DS_Store", "__pycache__"}
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
            continue
        files.append(p)
    return files


def scan_target(
    target: Path | str,
    policy: Policy | None = None,
    origin: str | None = None,
    publisher: str | None = None,
    repo_id: str | None = None,
) -> ScanReport:
    """Scan a file or directory and evaluate the policy over the results."""
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
    if sig_result.verified:
        report.origin = sig_result.origin
        report.publisher = sig_result.publisher
        report.provenance_verified = True
        report.metadata["provenance_source"] = "signed"
        report.metadata["signature_key_id"] = sig_result.key_id
    else:
        prov = resolve_provenance(
            target=target, explicit_origin=origin,
            publisher=publisher, repo_id=repo_id,
        )
        report.origin = prov.origin
        report.publisher = prov.publisher
        report.provenance_verified = False
        report.metadata["provenance_source"] = prov.source
    report.metadata["signature_status"] = sig_result.status

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

    report = policy.evaluate(report)
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
