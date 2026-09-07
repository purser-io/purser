"""Tests for CycloneDX ML-BOM emission."""

from __future__ import annotations

import json
import zipfile
from pathlib import Path

from purser.core.findings import Finding, FileResult, ScanReport, Severity, Verdict
from purser.core.mlbom import SPEC_VERSION, to_cyclonedx
from purser.core.scanner import scan_target


def hf_config(path: Path, version: str = "4.35.0") -> Path:
    (path / "config.json").write_text(json.dumps(
        {"model_type": "bert", "transformers_version": version}))
    return path / "config.json"


def malicious_pickle(path: Path) -> Path:
    """Inert protocol-0 pickle referencing os.system — parsed, never executed."""
    p = path / "model.pkl"
    p.write_bytes(b"cos\nsystem\n(S'echo inert'\ntR.")
    return p


def props(obj: dict) -> dict[str, str]:
    return {p["name"]: p["value"] for p in obj.get("properties", [])}


def vulns_by_id(doc: dict) -> dict[str, dict]:
    return {v["id"]: v for v in doc.get("vulnerabilities", [])}


# -- document shape --------------------------------------------------------------

def test_envelope_and_component_type(tmp_path):
    malicious_pickle(tmp_path)
    doc = to_cyclonedx(scan_target(tmp_path))

    assert doc["bomFormat"] == "CycloneDX"
    assert doc["specVersion"] == SPEC_VERSION == "1.7"
    assert doc["serialNumber"].startswith("urn:uuid:")
    assert doc["version"] == 1
    assert doc["metadata"]["tools"]["components"][0]["name"] == "purser"
    # every scanned file is a machine-learning-model component
    assert doc["components"]
    assert {c["type"] for c in doc["components"]} == {"machine-learning-model"}


def test_components_carry_sha256_and_format(tmp_path):
    malicious_pickle(tmp_path)
    doc = to_cyclonedx(scan_target(tmp_path))
    (comp,) = doc["components"]

    (h,) = comp["hashes"]
    assert h["alg"] == "SHA-256"
    assert len(h["content"]) == 64
    # bom-ref is content-addressed, so it matches the admission approvals digest
    assert comp["bom-ref"] == f"purser:model:{h['content']}"
    assert props(comp)["purser:format"] == "pickle"
    assert int(props(comp)["purser:size-bytes"]) > 0


def test_metadata_records_verdict_and_provenance(tmp_path):
    malicious_pickle(tmp_path)
    report = scan_target(tmp_path)
    meta = props(to_cyclonedx(report)["metadata"])

    assert meta["purser:verdict"] == report.verdict.value
    assert meta["purser:files-scanned"] == "1"
    assert meta["purser:provenance-verified"] == "false"


def test_dependency_graph_roots_at_the_target(tmp_path):
    malicious_pickle(tmp_path)
    hf_config(tmp_path)
    doc = to_cyclonedx(scan_target(tmp_path))

    deps = {d["ref"]: d["dependsOn"] for d in doc["dependencies"]}
    refs = {c["bom-ref"] for c in doc["components"]}
    assert set(deps["purser:target"]) == refs


# -- findings -> vulnerabilities -------------------------------------------------

def test_loader_cves_become_real_cve_entries(tmp_path):
    hf_config(tmp_path, "4.35.0")
    got = vulns_by_id(to_cyclonedx(scan_target(tmp_path)))

    # from the vendored loader-CVE dataset for transformers 4.35.0
    assert "CVE-2023-6730" in got
    entry = got["CVE-2023-6730"]
    assert entry["source"]["name"] == "osv"
    assert entry["source"]["url"].startswith("https://osv.dev/")
    assert entry["affects"]


def test_scanner_findings_are_namespaced_not_faked_as_cves(tmp_path):
    malicious_pickle(tmp_path)
    got = vulns_by_id(to_cyclonedx(scan_target(tmp_path)))

    ids = [i for i in got if i.startswith("purser:")]
    assert ids, "a dangerous pickle import must reach the BOM"
    # a Purser rule must never masquerade as a CVE id
    assert not [i for i in got if i.startswith("CVE-") and got[i]["source"]["name"] == "purser"]
    assert all(got[i]["source"]["name"] == "purser" for i in ids)


def test_severity_maps_to_cyclonedx_vocabulary_with_honest_method():
    report = ScanReport(
        target="/m",
        files=[FileResult(path="/m/a.pkl", format="pickle", size=1, sha256="a" * 64)],
        policy_findings=[Finding(rule_id="X", severity=Severity.CRITICAL,
                                 title="t", file="/m/a.pkl")],
        verdict=Verdict.FAIL,
    )
    (v,) = to_cyclonedx(report)["vulnerabilities"]
    (rating,) = v["ratings"]
    assert rating["severity"] == "critical"
    # Purser severities are policy-relative, not CVSS — must not claim otherwise
    assert rating["method"] == "other"


def test_a_cve_is_not_also_emitted_under_its_rule_id(tmp_path):
    hf_config(tmp_path, "4.35.0")
    got = vulns_by_id(to_cyclonedx(scan_target(tmp_path)))
    assert "purser:LOADER_CVE" not in got
    assert any(i.startswith("CVE-") for i in got)


def test_clean_scan_emits_no_vulnerabilities(tmp_path):
    (tmp_path / "config.json").write_text(json.dumps({"model_type": "bert"}))
    doc = to_cyclonedx(scan_target(tmp_path))
    assert "vulnerabilities" not in doc


# -- per-file attribution --------------------------------------------------------

def test_declared_framework_is_attributed_per_file_not_scan_wide(tmp_path):
    """A directory can mix frameworks; the version must not smear across files."""
    hf_config(tmp_path, "4.35.0")
    with zipfile.ZipFile(tmp_path / "model.keras", "w") as zf:
        zf.writestr("metadata.json", json.dumps({"keras_version": "3.9.0"}))
        zf.writestr("config.json", json.dumps({"class_name": "Sequential"}))

    cards = {c["name"]: props(c.get("modelCard", {}))
             for c in to_cyclonedx(scan_target(tmp_path))["components"]}
    assert cards["config.json"]["purser:framework"] == "transformers"
    assert cards["config.json"]["purser:declared-framework-version"] == "4.35.0"
    assert cards["model.keras"]["purser:framework"] == "keras"
    assert cards["model.keras"]["purser:declared-framework-version"] == "3.9.0"


def test_no_model_card_without_a_declared_version(tmp_path):
    malicious_pickle(tmp_path)
    (comp,) = to_cyclonedx(scan_target(tmp_path))["components"]
    assert "modelCard" not in comp  # absent rather than guessed


# -- reproducibility -------------------------------------------------------------

def test_serial_number_is_content_addressed(tmp_path):
    malicious_pickle(tmp_path)
    first = to_cyclonedx(scan_target(tmp_path))
    second = to_cyclonedx(scan_target(tmp_path))
    assert first["serialNumber"] == second["serialNumber"]

    # everything except the BOM timestamp is stable across runs
    for doc in (first, second):
        doc["metadata"].pop("timestamp", None)
    assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)


def test_changing_content_changes_the_serial(tmp_path):
    hf_config(tmp_path, "4.35.0")
    before = to_cyclonedx(scan_target(tmp_path))["serialNumber"]
    hf_config(tmp_path, "4.36.0")
    assert to_cyclonedx(scan_target(tmp_path))["serialNumber"] != before


def test_missing_digest_still_yields_a_unique_ref():
    report = ScanReport(
        target="/m",
        files=[FileResult(path="/m/a.pkl", format="pickle", size=0, sha256="")],
    )
    (comp,) = to_cyclonedx(report)["components"]
    assert comp["bom-ref"] == "purser:model:path:/m/a.pkl"
    assert "hashes" not in comp


# -- CLI wiring ------------------------------------------------------------------

def test_cli_format_cyclonedx(tmp_path):
    from typer.testing import CliRunner

    from purser.cli import app

    malicious_pickle(tmp_path)
    out = tmp_path / "bom.json"
    CliRunner().invoke(app, ["scan", str(tmp_path), "--format", "cyclonedx",
                             "--output", str(out)])
    doc = json.loads(out.read_text())
    assert doc["bomFormat"] == "CycloneDX"
    assert doc["components"]
