"""Tests for the pluggable signal-source subsystem and the HuggingFace
upstream scan-verdict source.

Network is always mocked: the suite monkeypatches `urllib.request.urlopen`
inside `purser.signals.hf_verdicts`. The mocked payload shapes mirror the
live Hub API (verified 2026-08-02): `securityRepoStatus.filesWithIssues`
on `GET /api/models/{repo}?securityStatus=true`, and per-scanner
`securityFileStatus` blobs on `POST .../paths-info/{rev}`.
"""

from __future__ import annotations

import json
import pickle
import struct
import urllib.error
from pathlib import Path

from purser.core.findings import Severity, Verdict
from purser.core.scanner import scan_target
from purser.signals import (
    SignalContext,
    collect_signals,
    source_enabled,
    signals_enabled,
    unavailable_finding,
)
from purser.signals.hf_verdicts import HFVerdictsSource, _statuses
from tests.conftest import EvilOsSystem


def rules(fs):
    return {f.rule_id for f in fs}


class FakeResponse:
    def __init__(self, body):
        self._body = json.dumps(body).encode()

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def patch_hub(monkeypatch, repo_status: dict, paths_info: list | None = None):
    """Serve the repo-level securityStatus body and (optionally) paths-info."""
    calls = []

    def fake_urlopen(req, timeout=0):
        calls.append(req)
        if "/paths-info/" in req.full_url:
            return FakeResponse(paths_info if paths_info is not None else [])
        return FakeResponse({"securityRepoStatus": repo_status})

    monkeypatch.setattr("purser.signals.hf_verdicts.urllib.request.urlopen",
                        fake_urlopen)
    return calls


def issue(path: str, level: str) -> dict:
    return {"path": path, "level": level}


HF_CTX = SignalContext(repo_id="evil-org/bad-model", revision="deadbeef",
                       source="huggingface")


def write_safetensors(tmp_path: Path) -> None:
    header = b'{"w":{"dtype":"F32","shape":[1],"data_offsets":[0,4]}}'
    (tmp_path / "weights.safetensors").write_bytes(
        struct.pack("<Q", len(header)) + header + b"\x00" * 4)


# -- status-blob walking (paths-info detail) -----------------------------------

def test_statuses_walks_nested_scanner_reports():
    blob = {
        "status": "unsafe",
        "avScan": {"virusFound": True, "status": "unsafe"},
        "pickleImportScan": {"status": "safe", "imports": []},
        "scans": [{"name": "guardian", "securityStatus": "suspicious"}],
    }
    got = dict(_statuses(blob))
    assert got["status"] == "unsafe"
    assert got["avScan.status"] == "unsafe"
    assert got["pickleImportScan.status"] == "safe"
    assert got["scans[0].securityStatus"] == "suspicious"


# -- the HF verdicts source ----------------------------------------------------

def test_hf_unsafe_verdict_becomes_high_finding(monkeypatch):
    patch_hub(monkeypatch, {
        "scansDone": True,
        "filesWithIssues": [issue("model.bin", "unsafe")],
    })
    fs = HFVerdictsSource().collect(HF_CTX)
    assert rules(fs) == {"HF_UPSTREAM_UNSAFE"}
    (f,) = fs
    assert f.severity == Severity.HIGH
    assert f.file == "model.bin"
    assert f.evidence["repo_id"] == "evil-org/bad-model"
    assert f.evidence["revision"] == "deadbeef"


def test_hf_caution_maps_to_medium(monkeypatch):
    patch_hub(monkeypatch, {
        "scansDone": True,
        "filesWithIssues": [issue("build_pickles.py", "caution")],
    })
    (f,) = HFVerdictsSource().collect(HF_CTX)
    assert f.rule_id == "HF_UPSTREAM_SUSPICIOUS"
    assert f.severity == Severity.MEDIUM


def test_hf_unknown_level_still_an_issue(monkeypatch):
    """Anything in filesWithIssues is an issue even if the level is novel."""
    patch_hub(monkeypatch, {
        "scansDone": True,
        "filesWithIssues": [issue("x.bin", "some-future-level")],
    })
    (f,) = HFVerdictsSource().collect(HF_CTX)
    assert f.rule_id == "HF_UPSTREAM_SUSPICIOUS"
    assert f.severity == Severity.MEDIUM


def test_hf_clean_repo_produces_nothing(monkeypatch):
    calls = patch_hub(monkeypatch, {"scansDone": True, "filesWithIssues": []})
    assert HFVerdictsSource().collect(HF_CTX) == []
    # no issues -> no second (paths-info) request either
    assert len(calls) == 1
    assert "securityStatus=true" in calls[0].full_url
    assert "/revision/deadbeef" in calls[0].full_url


def test_hf_scans_not_done_is_visible_gap(monkeypatch):
    patch_hub(monkeypatch, {"scansDone": False, "filesWithIssues": []})
    fs = HFVerdictsSource().collect(HF_CTX)
    assert rules(fs) == {"SIGNAL_UNAVAILABLE"}
    assert "not finished scanning" in fs[0].detail


def test_hf_scanner_detail_recorded_as_evidence(monkeypatch):
    patch_hub(
        monkeypatch,
        {"scansDone": True, "filesWithIssues": [issue("model.bin", "unsafe")]},
        paths_info=[{
            "path": "model.bin",
            "securityFileStatus": {
                "status": "unsafe",
                "protectAiScan": {"status": "unsafe", "message": "..."},
                "avScan": {"status": "safe"},
                "pickleImportScan": {"status": "unsafe", "version": "0.0.32"},
            },
        }])
    (f,) = HFVerdictsSource().collect(HF_CTX)
    assert f.evidence["reported_by"] == ["pickleImportScan", "protectAiScan"]


def test_hf_paths_info_failure_does_not_lose_the_finding(monkeypatch):
    def fake_urlopen(req, timeout=0):
        if "/paths-info/" in req.full_url:
            raise urllib.error.URLError("boom")
        return FakeResponse({"securityRepoStatus": {
            "scansDone": True,
            "filesWithIssues": [issue("model.bin", "unsafe")],
        }})

    monkeypatch.setattr("purser.signals.hf_verdicts.urllib.request.urlopen",
                        fake_urlopen)
    (f,) = HFVerdictsSource().collect(HF_CTX)
    assert f.rule_id == "HF_UPSTREAM_UNSAFE"
    assert f.evidence["reported_by"] == []


def test_hf_flood_of_issues_is_capped(monkeypatch):
    patch_hub(monkeypatch, {
        "scansDone": True,
        "filesWithIssues": [issue(f"f{i}.bin", "unsafe") for i in range(80)],
    })
    fs = HFVerdictsSource().collect(HF_CTX)
    assert len(fs) == 51  # 50 individual + 1 truncation summary
    assert fs[-1].evidence["flagged_total"] == 80


def test_hf_network_error_is_coverage_gap_not_crash(monkeypatch):
    def boom(req, timeout=0):
        raise urllib.error.URLError("connection refused")

    monkeypatch.setattr("purser.signals.hf_verdicts.urllib.request.urlopen", boom)
    fs = HFVerdictsSource().collect(HF_CTX)
    assert rules(fs) == {"SIGNAL_UNAVAILABLE"}
    assert fs[0].severity == Severity.LOW
    assert "coverage-gap" in fs[0].tags


def test_hf_missing_security_block_is_coverage_gap(monkeypatch):
    monkeypatch.setattr(
        "purser.signals.hf_verdicts.urllib.request.urlopen",
        lambda req, timeout=0: FakeResponse({"id": "repo", "siblings": []}))
    fs = HFVerdictsSource().collect(HF_CTX)
    assert rules(fs) == {"SIGNAL_UNAVAILABLE"}


def test_hf_available_only_for_hub_scans():
    src = HFVerdictsSource()
    assert src.available(HF_CTX)
    assert not src.available(SignalContext(target=Path(".")))
    assert not src.available(SignalContext(source="huggingface"))  # no repo_id


def test_hf_token_sent_when_set(monkeypatch):
    seen = {}

    def fake_urlopen(req, timeout=0):
        seen["auth"] = req.get_header("Authorization")
        return FakeResponse({"securityRepoStatus": {"scansDone": True,
                                                    "filesWithIssues": []}})

    monkeypatch.setattr("purser.signals.hf_verdicts.urllib.request.urlopen",
                        fake_urlopen)
    monkeypatch.setenv("HF_TOKEN", "hf_secret")
    HFVerdictsSource().collect(HF_CTX)
    assert seen["auth"] == "Bearer hf_secret"


# -- registry / gates / plugins -------------------------------------------------

def test_signals_master_switch(monkeypatch):
    monkeypatch.setenv("PURSER_SIGNALS", "0")
    assert not signals_enabled()
    assert collect_signals(HF_CTX) == []


def test_per_source_gate(monkeypatch):
    monkeypatch.setenv("PURSER_SIGNAL_HF_VERDICTS", "0")
    assert not source_enabled("hf-verdicts")
    assert source_enabled("something-else")


def test_collect_signals_survives_raising_source(monkeypatch):
    class Bomb:
        name = "bomb"

        def available(self, ctx):
            return True

        def collect(self, ctx):
            raise RuntimeError("kaboom")

    monkeypatch.setattr("purser.signals._builtin_sources", lambda: [Bomb()])
    monkeypatch.setattr("purser.signals._plugin_sources", lambda: [])
    fs = collect_signals(HF_CTX)
    assert rules(fs) == {"SIGNAL_UNAVAILABLE"}
    assert "kaboom" in fs[0].detail


def test_entry_point_plugin_discovered(monkeypatch):
    class PluginSource:
        name = "my-plugin"

        def available(self, ctx):
            return True

        def collect(self, ctx):
            return [unavailable_finding("my-plugin", "hello from plugin")]

    class FakeEP:
        name = "my-plugin"

        def load(self):
            return PluginSource

    monkeypatch.setattr(
        "purser.signals.importlib_metadata.entry_points",
        lambda group: [FakeEP()] if group == "purser.signals" else [])
    monkeypatch.setattr("purser.signals._builtin_sources", lambda: [])
    fs = collect_signals(HF_CTX)
    assert len(fs) == 1
    assert "hello from plugin" in fs[0].detail


def test_broken_plugin_is_visible_not_fatal(monkeypatch):
    class FakeEP:
        name = "busted"

        def load(self):
            raise ImportError("missing dep")

    monkeypatch.setattr(
        "purser.signals.importlib_metadata.entry_points",
        lambda group: [FakeEP()])
    monkeypatch.setattr("purser.signals._builtin_sources", lambda: [])
    fs = collect_signals(HF_CTX)
    assert rules(fs) == {"SIGNAL_UNAVAILABLE"}
    assert "busted" in fs[0].title


# -- end-to-end through scan_target + policy -------------------------------------

def test_upstream_unsafe_fails_clean_local_scan(monkeypatch, tmp_path):
    """A model whose bytes look clean still FAILs when upstream flags it."""
    patch_hub(monkeypatch, {
        "scansDone": True,
        "filesWithIssues": [issue("weights.safetensors", "unsafe")],
    })
    write_safetensors(tmp_path)
    report = scan_target(tmp_path, signal_context=HF_CTX)
    assert "HF_UPSTREAM_UNSAFE" in rules(report.signal_findings)
    assert report.verdict == Verdict.FAIL
    assert report.to_dict()["signal_findings"]  # serialized in the report


def test_upstream_safe_never_downgrades_own_verdict(monkeypatch, tmp_path):
    """Purser finds malice; upstream says all-clean; verdict must stay FAIL."""
    patch_hub(monkeypatch, {"scansDone": True, "filesWithIssues": []})
    (tmp_path / "model.pkl").write_bytes(pickle.dumps(EvilOsSystem()))
    report = scan_target(tmp_path, signal_context=HF_CTX)
    assert report.signal_findings == []
    assert report.verdict == Verdict.FAIL


def test_local_scan_makes_no_network_calls(monkeypatch, benign_pickle):
    def boom(req, timeout=0):
        raise AssertionError("network touched during a local scan")

    monkeypatch.setattr("purser.signals.hf_verdicts.urllib.request.urlopen", boom)
    report = scan_target(benign_pickle)
    assert report.signal_findings == []


def test_policy_rule_override_applies_to_signal_findings(monkeypatch, tmp_path):
    from purser.core.policy import Policy

    patch_hub(monkeypatch, {
        "scansDone": True,
        "filesWithIssues": [issue("weights.safetensors", "unsafe")],
    })
    write_safetensors(tmp_path)
    pol_yaml = tmp_path / "pol.yaml"
    pol_yaml.write_text(
        "version: 1\nname: t\nfail_on: {severity: HIGH}\n"
        "rules:\n  - {id: HF_UPSTREAM_UNSAFE, action: ignore}\n")
    report = scan_target(tmp_path, policy=Policy.load(str(pol_yaml)),
                         signal_context=HF_CTX)
    assert report.signal_findings == []
    assert report.verdict == Verdict.PASS
