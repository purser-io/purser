"""Tests for compliance control tagging and the generated mapping doc."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from purser.core.compliance import (
    controls_for,
    frameworks,
    known_controls,
    tag_report,
)
from purser.core.findings import Finding, ScanReport, Severity
from purser.core.scanner import scan_target

ROOT = Path(__file__).resolve().parents[1]


def malicious_pickle(path: Path) -> Path:
    p = path / "model.pkl"
    p.write_bytes(b"cos\nsystem\n(S'echo inert'\ntR.")
    return p


# -- the mapping ------------------------------------------------------------------

def test_every_mapped_control_exists_in_the_catalogue():
    """A tag must never reference a control the frameworks section doesn't define."""
    probes = [
        "PICKLE_DANGEROUS_IMPORT", "PYTORCH_EMBEDDED_SOURCE", "KERAS_LAMBDA_LAYER",
        "GGUF_TEMPLATE_INJECTION", "GGUF_BAD_MAGIC", "EXFIL_SECRET", "EXFIL_URL",
        "LOADER_CVE", "CARD_MISSING", "CARD_NO_EVAL_RESULTS", "ARCHIVE_ZIP_BOMB",
        "ARCHIVE_PATH_TRAVERSAL", "DEEP_WEIGHTS_STEGO", "DEEP_GADGET_PIVOT",
        "SIGNATURE_INVALID", "SIGSTORE_UNVERIFIED", "HF_UPSTREAM_UNSAFE",
        "PY_DANGEROUS_CALL", "HF_CONFIG_REMOTE_CODE", "ONNX_CUSTOM_OP",
    ]
    mapped = {c for rid in probes for c in controls_for(rid)}
    assert mapped, "probes should map to something"
    assert mapped <= known_controls(), sorted(mapped - known_controls())


def test_longest_prefix_wins():
    """ARCHIVE_ZIP_BOMB is resource exhaustion, not generic archive handling."""
    assert "owasp-llm:LLM10" in controls_for("ARCHIVE_ZIP_BOMB")
    assert "owasp-llm:LLM10" not in controls_for("ARCHIVE_PATH_TRAVERSAL")


def test_umbrella_applies_to_artifact_findings():
    for rid in ("PICKLE_DANGEROUS_IMPORT", "EXFIL_SECRET", "LOADER_CVE"):
        got = controls_for(rid)
        assert "owasp-llm:LLM03" in got      # Supply Chain
        assert "owasp-ml:ML06" in got        # ML Supply Chain Attacks
        assert "eu-ai-act:AnnexIV-2" in got  # cybersecurity measures


def test_card_findings_are_excluded_from_the_supply_chain_umbrella():
    """A missing model card is a documentation gap, not a supply-chain attack."""
    got = controls_for("CARD_MISSING")
    assert "owasp-llm:LLM03" not in got
    assert "owasp-ml:ML06" not in got
    assert "eu-ai-act:AnnexIV-1" in got   # general description
    assert "eu-ai-act:AnnexIV-4" in got   # performance metrics


def test_unknown_rule_maps_to_nothing():
    assert controls_for("SOME_FUTURE_RULE") == []


def test_prompt_injection_is_distinguished_from_plain_supply_chain():
    got = controls_for("GGUF_TEMPLATE_INJECTION")
    assert "owasp-llm:LLM01" in got   # fires when the model is prompted
    assert "owasp-llm:LLM03" in got   # ...and arrived via the supply chain


# -- tagging behaviour ------------------------------------------------------------

def test_tags_are_appended_so_the_metrics_category_stays_first():
    report = ScanReport(target="/m", policy_findings=[Finding(
        rule_id="PICKLE_DANGEROUS_IMPORT", severity=Severity.HIGH,
        title="t", tags=["malicious-code"])])
    tag_report(report)
    (f,) = report.policy_findings
    assert f.tags[0] == "malicious-code"
    assert "owasp-llm:LLM03" in f.tags


def test_tagging_is_idempotent():
    report = ScanReport(target="/m", policy_findings=[Finding(
        rule_id="EXFIL_SECRET", severity=Severity.HIGH, title="t")])
    tag_report(report)
    once = list(report.policy_findings[0].tags)
    tag_report(report)
    assert report.policy_findings[0].tags == once


def test_disabled_by_env(monkeypatch):
    monkeypatch.setenv("PURSER_COMPLIANCE", "0")
    report = ScanReport(target="/m", policy_findings=[Finding(
        rule_id="PICKLE_DANGEROUS_IMPORT", severity=Severity.HIGH, title="t")])
    tag_report(report)
    assert report.policy_findings[0].tags == []


def test_end_to_end_scan_carries_control_tags(tmp_path):
    malicious_pickle(tmp_path)
    report = scan_target(tmp_path)
    tags = {t for fr in report.files for f in fr.findings for t in f.tags}
    assert "owasp-llm:LLM03" in tags
    assert "eu-ai-act:AnnexIV-2" in tags
    # ATLAS enrichment must still be there — the two are additive, not exclusive
    assert any(t.startswith("atlas:") for t in tags)


def test_control_tags_reach_the_ml_bom(tmp_path):
    """The BOM handed to an auditor must carry the control references."""
    from purser.core.mlbom import to_cyclonedx

    malicious_pickle(tmp_path)
    doc = to_cyclonedx(scan_target(tmp_path))
    blob = json.dumps(doc)
    assert "owasp-llm:LLM03" in blob
    assert "eu-ai-act:AnnexIV-2" in blob


# -- the generated doc ------------------------------------------------------------

def test_generated_doc_is_committed_and_current():
    """docs/compliance-mapping.md is generated; a stale copy must fail CI."""
    target = ROOT / "docs/compliance-mapping.md"
    assert target.exists(), "run `make compliance-doc`"
    committed = target.read_text()

    out = ROOT / "docs/.compliance-mapping.check.md"
    try:
        subprocess.run(
            [sys.executable, str(ROOT / "scripts/gen_compliance_doc.py"), str(out)],
            check=True, capture_output=True,
        )
        assert out.read_text() == committed, (
            "docs/compliance-mapping.md is stale — run `make compliance-doc`")
    finally:
        out.unlink(missing_ok=True)


def test_doc_lists_every_framework():
    text = (ROOT / "docs/compliance-mapping.md").read_text()
    for fid, spec in frameworks().items():
        assert f"`{fid}`" in text
        assert (spec or {}).get("name", "") in text


def test_doc_states_it_is_not_a_compliance_claim():
    """The disclaimer is load-bearing: an auditor must not over-read this."""
    text = (ROOT / "docs/compliance-mapping.md").read_text()
    assert "not a compliance claim" in text
