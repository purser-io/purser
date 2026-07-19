"""Tests for model-name blocklist/allowlist policy."""

import pickle
from pathlib import Path

import pytest

from purser.core.findings import Verdict
from purser.core.policy import Policy, PolicyError
from purser.core.scanner import scan_target


@pytest.fixture
def model(tmp_path: Path) -> Path:
    p = tmp_path / "DeepSeek-R1.pkl"
    p.write_bytes(pickle.dumps({"w": [1.0]}))
    return p


def test_blocklist_matches_repo_id(model: Path):
    pol = Policy.from_dict({"models": {"mode": "blocklist", "patterns": ["evilcorp/*"]}})
    report = scan_target(model, policy=pol, repo_id="evilcorp/badmodel")
    assert report.verdict == Verdict.BLOCKED
    assert any(f.rule_id == "POLICY_MODEL_BLOCKED" for f in report.policy_findings)


def test_blocklist_matches_name_component(model: Path):
    # pattern matches the last path component of the repo id
    pol = Policy.from_dict({"models": {"mode": "blocklist", "patterns": ["*-r1"]}})
    report = scan_target(model, policy=pol, repo_id="deepseek-ai/DeepSeek-R1")
    assert report.verdict == Verdict.BLOCKED


def test_blocklist_matches_target_basename(model: Path):
    pol = Policy.from_dict({"models": {"mode": "blocklist", "patterns": ["deepseek-*.pkl"]}})
    report = scan_target(model, policy=pol)  # no repo_id; matches filename
    assert report.verdict == Verdict.BLOCKED


def test_blocklist_no_match_passes(model: Path):
    pol = Policy.from_dict({"models": {"mode": "blocklist", "patterns": ["evilcorp/*"]}})
    report = scan_target(model, policy=pol, repo_id="openai-community/gpt2")
    assert report.verdict in (Verdict.PASS, Verdict.WARN)


def test_allowlist_blocks_non_matching(model: Path):
    pol = Policy.from_dict({"models": {"mode": "allowlist", "patterns": ["approved/*"]}})
    report = scan_target(model, policy=pol, repo_id="random/model")
    assert report.verdict == Verdict.BLOCKED
    assert any(f.rule_id == "POLICY_MODEL_NOT_ALLOWED" for f in report.policy_findings)


def test_allowlist_permits_matching(model: Path):
    pol = Policy.from_dict({"models": {"mode": "allowlist", "patterns": ["approved/*"]}})
    report = scan_target(model, policy=pol, repo_id="approved/model-v2")
    assert report.verdict in (Verdict.PASS, Verdict.WARN)


def test_case_insensitive(model: Path):
    pol = Policy.from_dict({"models": {"mode": "blocklist", "patterns": ["EvilCorp/BadModel"]}})
    report = scan_target(model, policy=pol, repo_id="evilcorp/badmodel")
    assert report.verdict == Verdict.BLOCKED


def test_hf_uri_target(model: Path):
    pol = Policy.from_dict({"models": {"mode": "blocklist", "patterns": ["*/badmodel"]}})
    # simulate an hf:// scan where target is set to the uri
    report = scan_target(model, policy=pol, repo_id="evilcorp/badmodel")
    report_names_blocked = report.verdict == Verdict.BLOCKED
    assert report_names_blocked


def test_empty_patterns_rejected():
    with pytest.raises(PolicyError):
        Policy.from_dict({"models": {"mode": "blocklist", "patterns": []}})


def test_bad_mode_rejected():
    with pytest.raises(PolicyError):
        Policy.from_dict({"models": {"mode": "bogus", "patterns": ["x"]}})


def test_to_dict_roundtrip():
    pol = Policy.from_dict({"models": {"mode": "blocklist", "patterns": ["a/*", "b"]}})
    d = pol.to_dict()
    assert d["models"]["mode"] == "blocklist"
    assert d["models"]["patterns"] == ["a/*", "b"]
