from pathlib import Path

import pytest

from purser.core.findings import Verdict
from purser.core.policy import Policy, PolicyError
from purser.core.scanner import scan_target


def test_default_policy_fails_on_malicious(evil_os_pickle: Path):
    report = scan_target(evil_os_pickle)
    assert report.verdict == Verdict.FAIL


def test_default_policy_passes_benign(safetensors_valid: Path):
    report = scan_target(safetensors_valid)
    assert report.verdict in (Verdict.PASS, Verdict.WARN)


def test_origin_blocklist_blocks(benign_pickle: Path):
    policy = Policy.from_dict({
        "name": "geo",
        "origin": {"mode": "blocklist", "countries": ["CN", "RU"]},
    })
    report = scan_target(benign_pickle, policy=policy, origin="CN")
    assert report.verdict == Verdict.BLOCKED
    assert any(f.rule_id == "POLICY_ORIGIN_BLOCKED" for f in report.policy_findings)


def test_origin_allowlist(benign_pickle: Path):
    policy = Policy.from_dict({
        "origin": {"mode": "allowlist", "countries": ["US"], "unknown_origin": "deny"},
    })
    assert scan_target(benign_pickle, policy=policy, origin="US").verdict != Verdict.BLOCKED
    assert scan_target(benign_pickle, policy=policy, origin="RU").verdict == Verdict.BLOCKED
    # unknown origin denied
    assert scan_target(benign_pickle, policy=policy).verdict == Verdict.BLOCKED


def test_origin_from_publisher_database(benign_pickle: Path):
    policy = Policy.from_dict({
        "origin": {"mode": "blocklist", "countries": ["CN"]},
    })
    report = scan_target(benign_pickle, policy=policy, repo_id="deepseek-ai/some-model")
    assert report.origin == "CN"
    assert report.verdict == Verdict.BLOCKED


def test_origin_from_sidecar(tmp_path: Path, benign_pickle: Path):
    sidecar = benign_pickle.parent / "provenance.yaml"
    sidecar.write_text("origin: RU\npublisher: acme-labs\n")
    policy = Policy.from_dict({"origin": {"mode": "blocklist", "countries": ["RU"]}})
    report = scan_target(benign_pickle, policy=policy)
    assert report.origin == "RU"
    assert report.verdict == Verdict.BLOCKED


def test_format_blocklist(benign_pickle: Path):
    policy = Policy.from_dict({
        "formats": {"mode": "blocklist", "list": ["pickle"]},
    })
    report = scan_target(benign_pickle, policy=policy)
    assert report.verdict == Verdict.BLOCKED
    assert any(f.rule_id == "POLICY_FORMAT_BLOCKED" for f in report.policy_findings)


def test_format_allowlist(safetensors_valid: Path, benign_pickle: Path):
    policy = Policy.from_dict({
        "formats": {"mode": "allowlist", "list": ["safetensors"]},
    })
    assert scan_target(safetensors_valid, policy=policy).verdict != Verdict.BLOCKED
    assert scan_target(benign_pickle, policy=policy).verdict == Verdict.BLOCKED


def test_publisher_blocklist(benign_pickle: Path):
    policy = Policy.from_dict({"publishers": {"blocked": ["evilcorp"]}})
    report = scan_target(benign_pickle, policy=policy, repo_id="evilcorp/model")
    assert report.verdict == Verdict.BLOCKED


def test_rule_override_ignore(evil_os_pickle: Path):
    policy = Policy.from_dict({
        "rules": [{"id": "PICKLE_DANGEROUS_IMPORT", "action": "ignore"},
                  {"id": "PICKLE_UNKNOWN_IMPORT", "action": "ignore"}],
    })
    report = scan_target(evil_os_pickle, policy=policy)
    assert report.verdict in (Verdict.PASS, Verdict.WARN)


def test_invalid_policy_rejected():
    with pytest.raises(PolicyError):
        Policy.from_dict({"origin": {"mode": "bogus"}})
    with pytest.raises(PolicyError):
        Policy.from_dict({"rules": [{"id": "X", "action": "explode"}]})


def test_policy_files_load():
    root = Path(__file__).resolve().parents[1] / "policies"
    for name in ("default.yaml", "strict.yaml", "allowlist-us-eu.yaml"):
        pol = Policy.load(root / name)
        assert pol.name
