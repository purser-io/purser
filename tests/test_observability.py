"""Tests for Prometheus metrics and structured audit logging."""

import json
import pickle
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from purser.core import audit, metrics
from purser.core.scanner import scan_target


@pytest.fixture(autouse=True)
def _reset_metrics():
    metrics.reset()
    yield
    metrics.reset()


def _benign(tmp_path: Path) -> Path:
    p = tmp_path / "m.pkl"
    p.write_bytes(pickle.dumps({"w": [1.0]}))
    return p


# -- metrics -----------------------------------------------------------------

def test_metrics_record_and_render(tmp_path: Path):
    scan_target(_benign(tmp_path))
    out = metrics.render()
    assert "purser_build_info{version=" in out
    assert 'purser_scans_total{verdict="PASS"} 1' in out
    assert "purser_scan_duration_seconds_bucket" in out
    assert 'purser_scan_duration_seconds_bucket{le="+Inf"} 1' in out
    assert "purser_scan_duration_seconds_count 1" in out


def test_metrics_counts_verdicts_and_findings(tmp_path: Path):
    class Evil:
        def __reduce__(self):
            import os
            return (os.system, ("true",))
    bad = tmp_path / "bad.pkl"
    bad.write_bytes(pickle.dumps(Evil()))
    scan_target(bad)
    out = metrics.render()
    assert 'purser_scans_total{verdict="FAIL"} 1' in out
    assert 'purser_findings_total{severity="CRITICAL"}' in out
    # the critical finding was counted (>0)
    crit = [ln for ln in out.splitlines() if 'findings_total{severity="CRITICAL"}' in ln][0]
    assert int(crit.split()[-1]) >= 1


def test_metrics_valid_exposition_format(tmp_path: Path):
    scan_target(_benign(tmp_path))
    for line in metrics.render().splitlines():
        assert line.startswith("#") or line.split()  # HELP/TYPE or "name value"


def test_domain_metrics_present(tmp_path: Path):
    class Evil:
        def __reduce__(self):
            import os
            return (os.system, ("true",))
    bad = tmp_path / "bad.pkl"
    bad.write_bytes(pickle.dumps(Evil()))
    scan_target(bad, repo_id="acme/evil")
    out = metrics.render()
    # threat category, model format, provenance, origin, throughput
    assert 'purser_findings_by_category_total{category="os-command"}' in out
    assert 'purser_scan_files_total{format="pickle"} 1' in out
    assert 'purser_provenance_total{status="unsigned"} 1' in out
    assert 'purser_scans_by_origin_total{origin="UNKNOWN"} 1' in out
    assert "purser_scans_in_progress 0" in out
    bytes_line = [ln for ln in out.splitlines() if ln.startswith("purser_bytes_scanned_total ")][0]
    assert int(bytes_line.split()[-1]) > 0


def test_policy_block_metric(tmp_path: Path):
    from purser.core.policy import Policy
    p = _benign(tmp_path)
    pol = Policy.from_dict({"origin": {"mode": "blocklist", "countries": ["CN"]}})
    scan_target(p, policy=pol, repo_id="deepseek-ai/x")   # CN via publisher DB -> blocked
    out = metrics.render()
    assert 'purser_policy_blocks_total{reason="origin"} 1' in out
    assert 'purser_scans_by_origin_total{origin="CN"} 1' in out


def test_reject_metric_via_api(tmp_path, monkeypatch):
    metrics.reset()
    monkeypatch.setenv("PURSER_API_KEY", "k")
    from purser.api import app
    client = TestClient(app)
    client.get("/v1/policy")  # no key -> 401 -> reject{auth}
    out = client.get("/metrics").text
    assert 'purser_requests_rejected_total{reason="auth"} 1' in out


# -- audit -------------------------------------------------------------------

def test_audit_build_record(tmp_path: Path):
    report = scan_target(_benign(tmp_path))
    rec = audit.build_record(report)
    assert rec["event"] == "model_scan"
    assert rec["verdict"] in ("PASS", "WARN")
    assert "severity_counts" in rec and "duration_seconds" in rec
    assert isinstance(rec["finding_rule_ids"], list)


def test_audit_off_by_default_silent(tmp_path: Path, capsys, monkeypatch):
    monkeypatch.delenv("PURSER_AUDIT", raising=False)
    audit._current_mode = None
    scan_target(_benign(tmp_path))
    assert capsys.readouterr().err.strip() == ""


def test_audit_stdout_emits_json(tmp_path: Path, capsys, monkeypatch):
    monkeypatch.setenv("PURSER_AUDIT", "stdout")
    audit._current_mode = None
    report = scan_target(_benign(tmp_path))
    err = capsys.readouterr().err.strip()
    rec = json.loads(err.splitlines()[-1])
    assert rec["event"] == "model_scan" and rec["verdict"] == report.verdict.value
    monkeypatch.delenv("PURSER_AUDIT", raising=False)
    audit._current_mode = None


# -- API endpoint ------------------------------------------------------------

def test_metrics_endpoint(tmp_path, monkeypatch):
    monkeypatch.delenv("PURSER_POLICY", raising=False)
    monkeypatch.setenv("PURSER_SCAN_ROOT", str(tmp_path))
    from purser.api import app
    client = TestClient(app)
    r = client.get("/metrics")
    assert r.status_code == 200
    assert "text/plain" in r.headers["content-type"]
    assert "purser_scans_total" in r.text


def test_metrics_endpoint_disabled(tmp_path, monkeypatch):
    monkeypatch.setenv("PURSER_METRICS_ENABLED", "0")
    from purser.api import app
    assert TestClient(app).get("/metrics").status_code == 404
