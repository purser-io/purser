"""Tests for the offline loader-CVE signal source."""

from __future__ import annotations

import json
import zipfile
from pathlib import Path

from purser.core.findings import Verdict
from purser.core.scanner import scan_target
from purser.signals import SignalContext
from purser.signals.loader_cves import LoaderCVEsSource, _in_range


def make_keras_v3(path: Path, keras_version: str) -> Path:
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("metadata.json", json.dumps(
            {"keras_version": keras_version, "date_saved": "2026-01-01"}))
        zf.writestr("config.json", json.dumps(
            {"class_name": "Sequential", "config": {"layers": []}}))
    return path


def make_h5_with_version(path: Path, keras_version: str) -> Path:
    body = (b"\x89HDF\r\n\x1a\n" + b"\x00" * 64 +
            b"keras_version\x00" + keras_version.encode() + b"\x00" * 32 +
            b'{"class_name": "Sequential", "config": {"layers": []}}')
    path.write_bytes(body)
    return path


def cves(findings):
    out = set()
    for f in findings:
        for c in f.evidence.get("cves", []):
            out.add(c["cve"])
    return out


# -- version range matching ------------------------------------------------------

def test_in_range_comparators():
    assert _in_range("3.9.0", ">=3.0,<3.11.3")
    assert _in_range("3.11.2", ">=3.0,<3.11.3")
    assert not _in_range("3.11.3", ">=3.0,<3.11.3")
    assert not _in_range("2.15", ">=3.0,<3.11.3")
    assert _in_range("2.12.0", "<2.13")
    assert not _in_range("2.13", "<2.13")
    assert not _in_range("garbage", "<2.13")


# -- the source ------------------------------------------------------------------

def test_vulnerable_keras_v3_declared_version_fires(tmp_path):
    make_keras_v3(tmp_path / "model.keras", "3.9.0")
    fs = LoaderCVEsSource().collect(SignalContext(target=tmp_path))
    assert {"CVE-2025-9906", "CVE-2025-9905"} <= cves(fs)
    assert len(fs) == 1  # ONE aggregated finding per file+framework, not N
    (f,) = fs
    assert f.rule_id == "LOADER_CVE"
    assert f.severity.name == "LOW"
    assert "not thereby malicious" in f.detail  # honesty clause
    assert f.evidence["clear_at"]  # actionable: the version that clears all


def test_fixed_keras_version_is_silent(tmp_path):
    # above every affected range in the refreshed dataset (latest fix: 3.14.0)
    make_keras_v3(tmp_path / "model.keras", "3.15.0")
    assert LoaderCVEsSource().collect(SignalContext(target=tmp_path)) == []


def test_undeclared_version_is_silent_no_format_noise(tmp_path):
    """A .keras file with no version declaration must produce nothing."""
    with zipfile.ZipFile(tmp_path / "model.keras", "w") as zf:
        zf.writestr("config.json", json.dumps({"class_name": "Sequential"}))
    assert LoaderCVEsSource().collect(SignalContext(target=tmp_path)) == []


def test_h5_byte_heuristic_version(tmp_path):
    make_h5_with_version(tmp_path / "model.h5", "2.12.0")
    fs = LoaderCVEsSource().collect(SignalContext(target=tmp_path))
    assert "CVE-2024-3660" in cves(fs)


def test_runs_on_local_scans_via_scan_target(tmp_path):
    """The first offline signal: fires with NO SignalContext passed."""
    make_keras_v3(tmp_path / "model.keras", "3.9.0")
    report = scan_target(tmp_path)
    assert "LOADER_CVE" in {f.rule_id for f in report.signal_findings}
    # LOW advisory -> WARN, not FAIL
    assert report.verdict == Verdict.WARN


def test_policy_can_ignore_or_deny_loader_cves(tmp_path):
    from purser.core.policy import Policy

    make_keras_v3(tmp_path / "model.keras", "3.9.0")
    ignore = Policy.from_dict({"name": "i", "rules": [
        {"id": "LOADER_CVE", "action": "ignore"}]})
    assert scan_target(tmp_path, policy=ignore).verdict == Verdict.PASS

    deny = Policy.from_dict({"name": "d", "rules": [
        {"id": "LOADER_CVE", "action": "deny"}]})
    assert scan_target(tmp_path, policy=deny).verdict == Verdict.BLOCKED


def test_benign_corpus_formats_unaffected(benign_pickle, safetensors_valid):
    """No LOADER_CVE noise on non-Keras formats."""
    for target in (benign_pickle, safetensors_valid):
        report = scan_target(target)
        assert "LOADER_CVE" not in {f.rule_id for f in report.signal_findings}


# -- v2: transformers channel, any-of specs, operator override, refresh script ----

def test_transformers_version_channel(tmp_path):
    (tmp_path / "config.json").write_text(json.dumps(
        {"model_type": "bert", "transformers_version": "4.35.0"}))
    fs = LoaderCVEsSource().collect(SignalContext(target=tmp_path))
    got = cves(fs)
    assert "CVE-2023-6730" in got        # <4.36.0
    assert "CVE-2024-11392" in got       # <4.48.0
    assert len(fs) == 1                  # aggregated, not one per CVE
    assert fs[0].evidence["framework"] == "transformers"


def test_transformers_current_version_is_silent(tmp_path):
    (tmp_path / "config.json").write_text(json.dumps(
        {"model_type": "bert", "transformers_version": "5.6.0"}))
    assert LoaderCVEsSource().collect(SignalContext(target=tmp_path)) == []


def test_config_without_version_is_silent(tmp_path):
    (tmp_path / "config.json").write_text(json.dumps({"model_type": "bert"}))
    assert LoaderCVEsSource().collect(SignalContext(target=tmp_path)) == []


def test_any_of_affected_specs(tmp_path):
    """CVE-2026-0897 has two windows; a version in the second must match."""
    make_keras_v3(tmp_path / "model.keras", "3.13.1")
    got = cves(LoaderCVEsSource().collect(SignalContext(target=tmp_path)))
    assert "CVE-2026-0897" in got        # >=3.13.0,<3.13.2 (second window)
    make_keras_v3(tmp_path / "model.keras", "3.12.2")
    got = cves(LoaderCVEsSource().collect(SignalContext(target=tmp_path)))
    assert "CVE-2026-0897" not in got    # between the two windows


def test_operator_dataset_override(tmp_path, monkeypatch):
    custom = tmp_path / "my_cves.yaml"
    custom.write_text(
        "- cve: CVE-9999-0001\n  framework: keras\n  channel: keras_version\n"
        "  affected: '<9.0'\n  summary: test entry\n  reference: x\n")
    monkeypatch.setenv("PURSER_LOADER_CVES", str(custom))
    make_keras_v3(tmp_path / "model.keras", "3.9.0")
    got = cves(LoaderCVEsSource().collect(SignalContext(target=tmp_path)))
    assert got == {"CVE-9999-0001"}      # override replaces the vendored set


def test_refresh_script_filter_and_mapping():
    import importlib.util
    from pathlib import Path as P
    spec = importlib.util.spec_from_file_location(
        "refresh_loader_cves",
        P(__file__).resolve().parents[1] / "scripts/refresh_loader_cves.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    redos = {"id": "GHSA-x", "summary": "ReDoS in tokenizer",
             "details": "regular expression denial of service",
             "database_specific": {"cwe_ids": ["CWE-1333"]}}
    assert mod.is_load_relevant(redos)[0] is False

    deser = {"id": "GHSA-y", "summary": "Deserialization of Untrusted Data",
             "database_specific": {"cwe_ids": ["CWE-502"]}}
    assert mod.is_load_relevant(deser)[0] is True

    kw_only = {"id": "PYSEC-1", "summary": "",
               "details": "path traversal when loading a model archive"}
    assert mod.is_load_relevant(kw_only)[0] is True

    vuln = {"affected": [{"package": {"name": "keras"},
                          "ranges": [{"type": "ECOSYSTEM", "events": [
                              {"introduced": "3.0.0"}, {"fixed": "3.12.1"},
                              {"introduced": "3.13.0"}, {"fixed": "3.13.2"}]}]}]}
    assert mod.specs_from_affected(vuln, "keras") == [
        ">=3.0.0,<3.12.1", ">=3.13.0,<3.13.2"]

    unfixed = {"affected": [{"package": {"name": "keras"},
                             "ranges": [{"type": "ECOSYSTEM", "events": [
                                 {"introduced": "2.0.0"}]}]}]}
    assert mod.specs_from_affected(unfixed, "keras") == [">=2.0.0"]

    ghsa = {"id": "GHSA-a", "aliases": ["CVE-1-1"]}
    pysec = {"id": "PYSEC-b", "aliases": ["CVE-1-1"]}
    assert mod.dedupe_by_cve([pysec, ghsa])[0]["id"] == "GHSA-a"
