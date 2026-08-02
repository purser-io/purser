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
    return {f.evidence["cve"] for f in findings}


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
    (f, *_) = fs
    assert f.rule_id == "LOADER_CVE"
    assert f.severity.name == "LOW"
    assert "not thereby malicious" in f.detail  # honesty clause


def test_fixed_keras_version_is_silent(tmp_path):
    make_keras_v3(tmp_path / "model.keras", "3.11.3")
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
