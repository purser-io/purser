"""Tests for the offline loader-CVE signal source."""

from __future__ import annotations

import json
import zipfile
from pathlib import Path

import pytest

from purser.core.findings import Verdict
from purser.core.scanner import scan_target
from purser.signals import SignalContext
from purser.signals.loader_cves import (
    LoaderCVEsSource,
    _dataset,
    _in_range,
    _vtuple,
)


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


def _specs(entry: dict) -> list[str]:
    spec = entry.get("affected", "")
    return [str(s) for s in (spec if isinstance(spec, list) else [spec])]


def clean_version(framework: str) -> str:
    """The lowest version above every affected range for `framework`.

    Derived from the dataset instead of hardcoded. A pinned literal here is a
    time bomb: the weekly refresh job wedged when OSV published a transformers
    CVE fixed in 5.10.0, which swallowed a pinned "5.6.0" that had been clean
    the week before. The keras pin was one patch release from the same fate.

    Handles both bound kinds, since `last_affected` ranges map to `<=`:
    `<X` is cleared by X itself, `<=X` only by something above X.
    """
    entries = [e for e in _dataset() if e.get("framework") == framework]
    assert entries, f"no {framework} entries in the dataset"

    best: tuple[int, ...] = ()
    for e in entries:
        bounds = [part.strip() for s in _specs(e) for part in s.split(",")
                  if part.strip().startswith("<")]
        if not bounds:
            # Affected from some version with no upper bound at all: nothing
            # clears it, so no version can be asserted silent.
            pytest.skip(f"{framework} has an unbounded range — none is clean")
        for part in bounds:
            if part.startswith("<="):
                v = _vtuple(part[2:])
                v = v[:-1] + (v[-1] + 1,) if v else v  # must exceed it
            else:
                v = _vtuple(part[1:])
            best = max(best, v)
    assert best, f"{framework}: no upper bound to derive a clean version from"
    return ".".join(str(x) for x in best)


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
    make_keras_v3(tmp_path / "model.keras", clean_version("keras"))
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
        {"model_type": "bert",
         "transformers_version": clean_version("transformers")}))
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

    # `last_affected` is inclusive and has no `fixed` — the shape that
    # silently dropped 8 transformers RCEs plus CVE-2024-55459.
    last_affected = {"affected": [{"package": {"name": "transformers"},
                                   "ranges": [{"type": "ECOSYSTEM", "events": [
                                       {"introduced": "0"},
                                       {"last_affected": "4.54.1"}]}]}]}
    assert mod.specs_from_affected(last_affected, "transformers") == ["<=4.54.1"]

    # introduced + last_affected -> a closed, inclusive window
    window = {"affected": [{"package": {"name": "keras"},
                            "ranges": [{"type": "ECOSYSTEM", "events": [
                                {"introduced": "3.0.0"},
                                {"last_affected": "3.7.0"}]}]}]}
    assert mod.specs_from_affected(window, "keras") == [">=3.0.0,<=3.7.0"]

    unfixed = {"affected": [{"package": {"name": "keras"},
                             "ranges": [{"type": "ECOSYSTEM", "events": [
                                 {"introduced": "2.0.0"}]}]}]}
    assert mod.specs_from_affected(unfixed, "keras") == [">=2.0.0"]

    # Save-time only -> skipped. The CVE-2026-9856 shape: a CWE-22 traversal
    # in save_pretrained with no load trigger. "downloads" must not register
    # as a load mention, or the veto never bites.
    save_only = {"id": "GHSA-s", "summary": "save_pretrained path traversal",
                 "details": "chat_template keys are used directly as "
                            "filenames; when a victim downloads and saves the "
                            "tokenizer they escape the save directory",
                 "database_specific": {"cwe_ids": ["CWE-22"]}}
    relevant, reason = mod.is_load_relevant(save_only)
    assert relevant is False
    assert "save-time only" in reason

    # ...but a traversal that fires on save OR load is kept (CVE-2026-12479).
    # Worded to carry no LOAD_TRIGGERS term, so only the word-bounded load
    # mention ("loading" / "loaded") can rescue it.
    save_and_load = {"id": "GHSA-l", "summary": "DiskIOStore path traversal",
                     "details": "in the Keras 3 model saving and loading "
                                "library, an attacker-supplied layer name "
                                "escapes the working directory when a model "
                                "is saved or loaded",
                     "database_specific": {"cwe_ids": ["CWE-22"]}}
    assert mod.is_load_relevant(save_and_load)[0] is True

    ghsa = {"id": "GHSA-a", "aliases": ["CVE-1-1"]}
    pysec = {"id": "PYSEC-b", "aliases": ["CVE-1-1"]}
    assert mod.dedupe_by_cve([pysec, ghsa])[0]["id"] == "GHSA-a"


def test_rehearsal_forced_failure():
    """TEMPORARY — scratch branch only, to rehearse the validation-failure path."""
    assert False, "deliberate failure to exercise the workflow's failure path"
