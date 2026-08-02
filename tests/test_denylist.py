"""Tests for the known-bad denylist policy dimension."""

from __future__ import annotations

import hashlib
import struct

import pytest

from purser.core.policy import Policy, PolicyError
from purser.core.findings import Verdict
from purser.core.scanner import scan_target


def write_benign(tmp_path):
    header = b'{"w":{"dtype":"F32","shape":[1],"data_offsets":[0,4]}}'
    blob = struct.pack("<Q", len(header)) + header + b"\x00" * 4
    p = tmp_path / "model.safetensors"
    p.write_bytes(blob)
    return p, hashlib.sha256(blob).hexdigest()


def policy_from(doc: dict) -> Policy:
    return Policy.from_dict({"version": 1, "name": "t", **doc})


def rule_ids(report):
    return {f.rule_id for f in report.policy_findings}


def test_hash_denylist_blocks_matching_content(tmp_path):
    path, digest = write_benign(tmp_path)
    pol = policy_from({"denylist": {"hashes": [f"sha256:{digest}"]}})
    report = scan_target(path, policy=pol)
    assert report.verdict == Verdict.BLOCKED
    assert "POLICY_DENYLIST_HASH" in rule_ids(report)


def test_hash_denylist_ignores_other_content(tmp_path):
    path, _ = write_benign(tmp_path)
    pol = policy_from({"denylist": {"hashes": ["f" * 64]}})
    report = scan_target(path, policy=pol)
    assert report.verdict == Verdict.PASS


def test_publisher_glob_denylist(tmp_path):
    path, _ = write_benign(tmp_path)
    pol = policy_from({"denylist": {"publishers": ["evil-*"]}})
    report = scan_target(path, policy=pol, publisher="evil-org")
    assert report.verdict == Verdict.BLOCKED
    assert "POLICY_DENYLIST_PUBLISHER" in rule_ids(report)
    ok = scan_target(path, policy=pol, publisher="good-org")
    assert ok.verdict != Verdict.BLOCKED


def test_model_glob_denylist(tmp_path):
    path, _ = write_benign(tmp_path)
    pol = policy_from({"denylist": {"models": ["*/nullif*"]}})
    report = scan_target(path, policy=pol, repo_id="acme/nullif-ai-v2")
    assert report.verdict == Verdict.BLOCKED
    assert "POLICY_DENYLIST_MODEL" in rule_ids(report)


def test_external_feed_file_reread_per_evaluation(tmp_path):
    """Dropping a new feed file takes effect without reloading the policy."""
    path, digest = write_benign(tmp_path)
    feed = tmp_path / "feed.txt"
    feed.write_text("# empty feed\n")
    pol = policy_from({"denylist": {"files": [str(feed)]}})

    assert scan_target(path, policy=pol).verdict == Verdict.PASS
    feed.write_text(f"# refreshed\nsha256:{digest}\n")
    report = scan_target(path, policy=pol)  # same Policy object
    assert report.verdict == Verdict.BLOCKED
    assert "POLICY_DENYLIST_HASH" in rule_ids(report)


def test_missing_feed_file_is_skipped_not_fatal(tmp_path):
    path, _ = write_benign(tmp_path)
    pol = policy_from({"denylist": {"files": [str(tmp_path / "nope.txt")],
                                    "hashes": ["e" * 64]}})
    assert scan_target(path, policy=pol).verdict == Verdict.PASS


def test_invalid_hash_rejected_at_load():
    with pytest.raises(PolicyError):
        policy_from({"denylist": {"hashes": ["not-a-hash"]}})


def test_denylist_in_policy_check_roundtrip():
    pol = policy_from({"denylist": {"hashes": ["a" * 64],
                                    "publishers": ["evil-*"],
                                    "models": ["*/bad*"]}})
    d = pol.to_dict()["denylist"]
    assert d["hashes"] == ["a" * 64]
    assert d["publishers"] == ["evil-*"]
    assert d["models"] == ["*/bad*"]
