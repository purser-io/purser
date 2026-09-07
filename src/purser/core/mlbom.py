"""CycloneDX ML-BOM emission — the scan report as a bill of materials.

Purser already extracts everything an AI/ML bill of materials needs: per-file
format, size and SHA-256, the declared framework version, verified provenance
(publisher, country of origin, signer identity), mapped loader CVEs, and MITRE
ATLAS tags. This module renders that as a **CycloneDX 1.7** document so the
same scan that gates a pipeline also produces the artifact inventory
procurement and EU AI Act Annex IV documentation ask for.

Design decisions worth knowing:

* **Models are `machine-learning-model` components**, keyed by SHA-256. That
  digest is the same one the admission approvals path uses, so a BOM entry and
  an admitted digest are directly comparable.
* **Every finding lands in `vulnerabilities[]`**, not just CVE-backed ones.
  Loader-CVE findings carry their real CVE id; scanner findings get
  ``purser:<RULE_ID>`` with ``source.name = "purser"``. This mirrors how
  container scanners emit non-CVE findings and keeps a consumer from having to
  look in two places to answer "is anything wrong with this model". Ratings use
  ``method: "other"`` because Purser severities are not CVSS scores and
  pretending otherwise would be dishonest.
* **Purser-specific facts go in namespaced ``purser:`` properties**, the
  CycloneDX-sanctioned extension mechanism, rather than invented schema fields.
* **The serial number is content-addressed** — a UUIDv5 over the target plus
  the sorted file digests — so an unchanged scan always yields the same serial,
  and two BOMs of the same artifacts are directly comparable. Everything except
  ``metadata.timestamp`` is byte-identical across runs; the timestamp is when
  the BOM was produced, which by definition moves.

Nothing here re-analyzes the model; this is purely a projection of an existing
``ScanReport``.
"""

from __future__ import annotations

import uuid
from typing import Any

from purser import __version__
from purser.core.findings import Finding, ScanReport, Severity

SPEC_VERSION = "1.7"

# CycloneDX ratings vocabulary; Purser's Severity maps 1:1.
_SEVERITY_TO_CDX = {
    Severity.CRITICAL: "critical",
    Severity.HIGH: "high",
    Severity.MEDIUM: "medium",
    Severity.LOW: "low",
    Severity.INFO: "info",
}

# Stable namespace for deterministic serial numbers. Arbitrary but fixed: what
# matters is that the same input always yields the same UUID.
_NS = uuid.UUID("6f0d5b18-3a2e-5c47-9f1b-7a4c2d8e0b31")

_TARGET_REF = "purser:target"


def _model_ref(file_result) -> str:
    """bom-ref for a scanned file. Digest-keyed so refs are content-addressed."""
    digest = (file_result.sha256 or "").strip()
    return f"purser:model:{digest}" if digest else f"purser:model:path:{file_result.path}"


def _serial_number(report: ScanReport) -> str:
    seed = report.target + "\0" + "\0".join(
        sorted(f"{fr.sha256}:{fr.path}" for fr in report.files))
    return f"urn:uuid:{uuid.uuid5(_NS, seed)}"


def _props(pairs: list[tuple[str, Any]]) -> list[dict]:
    """CycloneDX properties, skipping empties (values are always strings)."""
    out = []
    for name, value in pairs:
        if value is None or value == "" or value == []:
            continue
        if isinstance(value, bool):
            value = "true" if value else "false"
        out.append({"name": name, "value": str(value)})
    return out


def _declared_versions(report: ScanReport) -> dict[str, tuple[str, str]]:
    """path -> (framework, declared version), from loader-CVE signal evidence.

    The `loader-cves` source records the version an artifact *declares*, which
    is exactly the "what framework is this model for" fact an ML-BOM wants.
    Keyed by file: a directory scan can mix frameworks, so attributing one
    scan-wide framework to every component would be wrong.
    """
    out: dict[str, tuple[str, str]] = {}
    for f in report.signal_findings:
        fw = f.evidence.get("framework")
        ver = f.evidence.get("declared_version")
        if f.file and fw and ver:
            out[f.file] = (str(fw), str(ver))
    return out


def _model_components(report: ScanReport) -> list[dict]:
    frameworks = _declared_versions(report)
    components = []
    for fr in report.files:
        name = fr.path.rsplit("/", 1)[-1] or fr.path
        comp: dict[str, Any] = {
            "bom-ref": _model_ref(fr),
            "type": "machine-learning-model",
            "name": name,
            "properties": _props([
                ("purser:format", fr.format),
                ("purser:path", fr.path),
                ("purser:size-bytes", fr.size),
                ("purser:findings", len(fr.findings)),
                ("purser:scan-error", fr.error),
            ]),
        }
        if fr.sha256:
            comp["hashes"] = [{"alg": "SHA-256", "content": fr.sha256}]

        # modelCard carries only what we actually know. `approach.type` and the
        # rest of the taxonomy require model semantics Purser deliberately never
        # loads the model to learn, so it stays absent rather than guessed.
        declared = frameworks.get(fr.path)
        card_props = _props([
            ("purser:framework", declared[0]),
            ("purser:declared-framework-version", declared[1]),
        ]) if declared else []
        if card_props:
            comp["modelCard"] = {
                "bom-ref": f"{_model_ref(fr)}:card",
                "properties": card_props,
            }
        components.append(comp)
    return components


def _cve_ids(finding: Finding) -> list[tuple[str, str]]:
    """(cve_id, reference) pairs from a loader-CVE finding's evidence."""
    out = []
    for entry in finding.evidence.get("cves") or []:
        if isinstance(entry, dict) and entry.get("cve"):
            out.append((str(entry["cve"]), str(entry.get("reference") or "")))
    return out


def _vuln(vid: str, source_name: str, finding: Finding, refs: list[str],
          url: str = "") -> dict:
    entry: dict[str, Any] = {
        "bom-ref": f"purser:vuln:{vid}",
        "id": vid,
        "source": {"name": source_name},
        "ratings": [{
            "severity": _SEVERITY_TO_CDX.get(finding.severity, "unknown"),
            # Purser severities are policy-relative, not CVSS. Say so.
            "method": "other",
            "source": {"name": "purser"},
        }],
        "description": finding.title,
    }
    if url:
        entry["source"]["url"] = url
    if finding.detail:
        entry["detail"] = finding.detail
    if finding.tags:
        # ATLAS technique tags ride along as-is (atlas:AML.T####).
        entry["properties"] = _props([("purser:tags", ",".join(finding.tags))])
    if refs:
        entry["affects"] = [{"ref": r} for r in refs]
    return entry


def _vulnerabilities(report: ScanReport) -> list[dict]:
    by_path = {fr.path: _model_ref(fr) for fr in report.files}
    all_refs = sorted(set(by_path.values()))
    out: list[dict] = []
    seen: set[str] = set()

    def add(entry: dict) -> None:
        if entry["id"] not in seen:
            seen.add(entry["id"])
            out.append(entry)

    # Real CVEs first, so a duplicate rule-id entry can't shadow them.
    for f in report.signal_findings:
        refs = [by_path[f.file]] if f.file in by_path else all_refs
        for cve, url in _cve_ids(f):
            add(_vuln(cve, "osv", f, refs, url))

    for f in report.all_findings:
        if _cve_ids(f):
            continue  # already emitted under its CVE id
        refs = [by_path[f.file]] if f.file in by_path else all_refs
        add(_vuln(f"purser:{f.rule_id}", "purser", f, refs))
    return out


def to_cyclonedx(report: ScanReport) -> dict:
    """Render a ScanReport as a CycloneDX 1.7 ML-BOM document."""
    components = _model_components(report)
    target_name = report.target.rsplit("/", 1)[-1] or report.target

    signers = sorted({
        str(f.evidence.get("identity") or f.evidence.get("key_id"))
        for f in report.signature_findings
        if f.evidence.get("identity") or f.evidence.get("key_id")
    })

    metadata: dict[str, Any] = {
        "tools": {"components": [{
            "type": "application",
            "name": "purser",
            "version": __version__,
        }]},
        "component": {
            "bom-ref": _TARGET_REF,
            "type": "application",
            "name": target_name,
        },
        "properties": _props([
            ("purser:verdict", report.verdict.value),
            ("purser:policy", report.policy_name),
            ("purser:publisher", report.publisher),
            ("purser:origin", report.origin),
            ("purser:provenance-verified", report.provenance_verified),
            ("purser:signer-identity", ",".join(signers)),
            ("purser:files-scanned", len(report.files)),
            ("purser:target", report.target),
        ]),
    }
    if report.started_at:
        metadata["timestamp"] = report.started_at

    doc: dict[str, Any] = {
        "bomFormat": "CycloneDX",
        "specVersion": SPEC_VERSION,
        "serialNumber": _serial_number(report),
        "version": 1,
        "metadata": metadata,
        "components": components,
    }

    vulns = _vulnerabilities(report)
    if vulns:
        doc["vulnerabilities"] = vulns
    if components:
        doc["dependencies"] = [
            {"ref": _TARGET_REF,
             "dependsOn": [c["bom-ref"] for c in components]},
            *({"ref": c["bom-ref"], "dependsOn": []} for c in components),
        ]
    return doc
