"""Tests for MITRE ATLAS tagging and the hf-verdicts lookup cache."""

from __future__ import annotations

import json
import urllib.error


from purser.core.atlas import tag_report, techniques_for
from purser.core.scanner import scan_target
from purser.signals import SignalContext
from purser.signals import hf_verdicts as hv
from purser.signals.hf_verdicts import HFVerdictsSource


# (the autouse cache-clear fixture lives in conftest.py)


# -- ATLAS tagging ----------------------------------------------------------------

def test_techniques_for_rule_prefixes():
    assert "AML.T0011" in techniques_for("PICKLE_DANGEROUS_IMPORT")
    assert "AML.T0025" in techniques_for("EXFIL_URL")
    assert "AML.T0018" in techniques_for("DEEP_GADGET_PIVOT")
    assert "AML.T0010.003" in techniques_for("HF_UPSTREAM_UNSAFE")
    # umbrella technique rides along with the specific one
    assert "AML.T0010.003" in techniques_for("PICKLE_DANGEROUS_IMPORT")
    assert techniques_for("SOME_UNMAPPED_RULE") == []


def test_scan_findings_carry_atlas_tags(evil_os_pickle):
    report = scan_target(evil_os_pickle)
    tagged = [f for f in report.all_findings
              if f.rule_id.startswith("PICKLE_")]
    assert tagged
    for f in tagged:
        assert "atlas:AML.T0011" in f.tags
        assert "atlas:AML.T0010.003" in f.tags
        # tags[0] must remain the original category (metrics contract)
        assert not f.tags[0].startswith("atlas:")


def test_atlas_disabled_by_env(monkeypatch, evil_os_pickle):
    monkeypatch.setenv("PURSER_ATLAS", "0")
    report = scan_target(evil_os_pickle)
    assert not any(t.startswith("atlas:")
                   for f in report.all_findings for t in f.tags)


def test_tagging_is_idempotent(evil_os_pickle):
    report = scan_target(evil_os_pickle)
    before = [list(f.tags) for f in report.all_findings]
    tag_report(report)
    assert [list(f.tags) for f in report.all_findings] == before


def test_mapping_covers_all_signal_and_deep_rules():
    for rid in ("HF_UPSTREAM_SUSPICIOUS", "POLICY_DENYLIST_HASH",
                "LOADER_CVE", "SIGNATURE_INVALID", "SIGSTORE_INVALID",
                "DEEP_WEIGHT_STEGO"):
        assert techniques_for(rid), f"unmapped rule family: {rid}"


# -- hf-verdicts cache --------------------------------------------------------------

class CountingHub:
    def __init__(self):
        self.calls = 0

    def urlopen(self, req, timeout=0):
        self.calls += 1

        class R:
            def read(self_inner):
                return json.dumps({"securityRepoStatus": {
                    "scansDone": True,
                    "filesWithIssues": [{"path": "m.bin", "level": "unsafe"}],
                }}).encode()

            def __enter__(self_inner):
                return self_inner

            def __exit__(self_inner, *a):
                return False

        if "/paths-info/" in req.full_url:
            class P(R):
                def read(self_inner):
                    return b"[]"
            return P()
        return R()


SHA = "a" * 40


def test_immutable_revision_cached_across_calls(monkeypatch):
    hub = CountingHub()
    monkeypatch.setattr("purser.signals.hf_verdicts.urllib.request.urlopen",
                        hub.urlopen)
    ctx = SignalContext(repo_id="org/m", revision=SHA, source="huggingface")
    first = HFVerdictsSource().collect(ctx)
    calls_after_first = hub.calls
    second = HFVerdictsSource().collect(ctx)
    assert hub.calls == calls_after_first  # served from cache
    assert [f.rule_id for f in second] == [f.rule_id for f in first]
    # cached findings are copies, not shared objects
    assert second[0] is not first[0]


def test_mutable_ref_expires_with_ttl(monkeypatch):
    hub = CountingHub()
    monkeypatch.setattr("purser.signals.hf_verdicts.urllib.request.urlopen",
                        hub.urlopen)
    ctx = SignalContext(repo_id="org/m", revision="main", source="huggingface")
    HFVerdictsSource().collect(ctx)
    n = hub.calls
    HFVerdictsSource().collect(ctx)
    assert hub.calls == n  # within TTL
    # simulate expiry
    key = next(iter(hv._cache))
    expiry, findings = hv._cache[key]
    assert expiry is not None  # mutable refs must not cache forever
    hv._cache[key] = (0.0, findings)
    HFVerdictsSource().collect(ctx)
    assert hub.calls > n


def test_failures_are_not_cached(monkeypatch):
    calls = {"n": 0}

    def boom(req, timeout=0):
        calls["n"] += 1
        raise urllib.error.URLError("down")

    monkeypatch.setattr("purser.signals.hf_verdicts.urllib.request.urlopen", boom)
    ctx = SignalContext(repo_id="org/m", revision=SHA, source="huggingface")
    HFVerdictsSource().collect(ctx)
    HFVerdictsSource().collect(ctx)
    assert calls["n"] == 2  # retried, not served from cache


def test_cache_disabled_with_zero_ttl(monkeypatch):
    monkeypatch.setenv("PURSER_SIGNAL_CACHE_TTL", "0")
    hub = CountingHub()
    monkeypatch.setattr("purser.signals.hf_verdicts.urllib.request.urlopen",
                        hub.urlopen)
    ctx = SignalContext(repo_id="org/m", revision=SHA, source="huggingface")
    HFVerdictsSource().collect(ctx)
    n = hub.calls
    HFVerdictsSource().collect(ctx)
    assert hub.calls > n
