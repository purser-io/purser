"""Tests for the approval store (scan→approve→admit loop)."""

from __future__ import annotations

import json
import pickle

from purser.core import approvals
from purser.core.approvals import (
    ConfigMapApprovals,
    FileApprovals,
    parse_digests,
    record_report,
)
from purser.core.findings import FileResult, ScanReport, Verdict
from purser.core.scanner import scan_target
from tests.conftest import EvilOsSystem

D1 = "a" * 64
D2 = "b" * 64
D3 = "c" * 64


def make_report(verdict: Verdict, digests: list[str], target="m") -> ScanReport:
    r = ScanReport(target=target, policy_name="default")
    r.verdict = verdict
    r.files = [FileResult(path=f"f{i}", format="safetensors", size=1, sha256=d)
               for i, d in enumerate(digests)]
    return r


# -- file backend ---------------------------------------------------------------

def test_file_backend_approve_and_reload(tmp_path):
    store = FileApprovals(str(tmp_path / "approved.txt"))
    store.apply({D1: "PASS m1", D2: ""}, set())
    text = (tmp_path / "approved.txt").read_text()
    assert parse_digests(text) == {D1, D2}
    # notes survive a second apply
    store.apply({D3: "PASS m3"}, set())
    assert parse_digests((tmp_path / "approved.txt").read_text()) == {D1, D2, D3}
    assert "PASS m1" in (tmp_path / "approved.txt").read_text()


def test_file_backend_revoke(tmp_path):
    store = FileApprovals(str(tmp_path / "approved.txt"))
    store.apply({D1: "", D2: ""}, set())
    store.apply({}, {D1})
    assert parse_digests((tmp_path / "approved.txt").read_text()) == {D2}


def test_file_format_readable_by_admission_webhook(tmp_path, monkeypatch):
    """The store writes exactly what admission.load_approved_digests reads."""
    from purser.admission import load_approved_digests

    path = tmp_path / "approved.txt"
    FileApprovals(str(path)).apply({D1: "PASS model-a", D2: ""}, set())
    monkeypatch.setenv("PURSER_ADMISSION_APPROVED_DIGESTS", str(path))
    assert load_approved_digests() == {D1, D2}


# -- record_report gating ---------------------------------------------------------

def test_disabled_by_default(tmp_path, monkeypatch):
    monkeypatch.setenv("PURSER_APPROVALS_PATH", str(tmp_path / "a.txt"))
    assert record_report(make_report(Verdict.PASS, [D1])) is None
    assert not (tmp_path / "a.txt").exists()


def test_pass_approves_and_fail_revokes(tmp_path, monkeypatch):
    path = tmp_path / "a.txt"
    monkeypatch.setenv("PURSER_AUTO_APPROVE", "1")
    monkeypatch.setenv("PURSER_APPROVALS_PATH", str(path))

    out = record_report(make_report(Verdict.PASS, [D1, D2]))
    assert out["action"] == "approved" and set(out["digests"]) == {D1, D2}
    assert parse_digests(path.read_text()) == {D1, D2}

    out = record_report(make_report(Verdict.FAIL, [D2]))
    assert out["action"] == "revoked"
    assert parse_digests(path.read_text()) == {D1}

    out = record_report(make_report(Verdict.BLOCKED, [D1]))
    assert out["action"] == "revoked"
    assert parse_digests(path.read_text()) == set()


def test_warn_not_approved_by_default_but_configurable(tmp_path, monkeypatch):
    path = tmp_path / "a.txt"
    monkeypatch.setenv("PURSER_AUTO_APPROVE", "1")
    monkeypatch.setenv("PURSER_APPROVALS_PATH", str(path))
    assert record_report(make_report(Verdict.WARN, [D1])) is None

    monkeypatch.setenv("PURSER_AUTO_APPROVE_VERDICTS", "PASS,WARN")
    out = record_report(make_report(Verdict.WARN, [D1]))
    assert out["action"] == "approved"


def test_enabled_but_unconfigured_reports_error(monkeypatch):
    monkeypatch.setenv("PURSER_AUTO_APPROVE", "1")
    monkeypatch.delenv("PURSER_APPROVALS_PATH", raising=False)
    monkeypatch.delenv("PURSER_APPROVALS_CONFIGMAP", raising=False)
    out = record_report(make_report(Verdict.PASS, [D1]))
    assert "error" in out


def test_store_failure_never_raises(tmp_path, monkeypatch):
    monkeypatch.setenv("PURSER_AUTO_APPROVE", "1")
    # a directory path that cannot be a file
    monkeypatch.setenv("PURSER_APPROVALS_PATH", str(tmp_path))
    out = record_report(make_report(Verdict.PASS, [D1]))
    assert "error" in out


def test_errored_files_are_not_approved(tmp_path, monkeypatch):
    path = tmp_path / "a.txt"
    monkeypatch.setenv("PURSER_AUTO_APPROVE", "1")
    monkeypatch.setenv("PURSER_APPROVALS_PATH", str(path))
    r = make_report(Verdict.PASS, [D1])
    r.files.append(FileResult(path="bad", format="unknown", size=0,
                              sha256=D2, error="boom"))
    out = record_report(r)
    assert set(out["digests"]) == {D1}


# -- end-to-end: scan a real file, verdict drives the store ----------------------

def test_scan_pass_populates_store_and_fail_revokes(tmp_path, monkeypatch):
    from purser.admission import load_approved_digests

    path = tmp_path / "approved.txt"
    monkeypatch.setenv("PURSER_AUTO_APPROVE", "1")
    monkeypatch.setenv("PURSER_APPROVALS_PATH", str(path))
    monkeypatch.setenv("PURSER_ADMISSION_APPROVED_DIGESTS", str(path))

    benign = tmp_path / "model.safetensors"
    import struct
    header = b'{"w":{"dtype":"F32","shape":[1],"data_offsets":[0,4]}}'
    benign.write_bytes(struct.pack("<Q", len(header)) + header + b"\x00" * 4)
    report = scan_target(benign)
    approvals.maybe_record(report)
    assert report.verdict == Verdict.PASS
    digest = report.files[0].sha256
    assert digest in load_approved_digests()
    assert report.metadata["approvals"]["action"] == "approved"

    # the same artifact turning malicious (same store) gets revoked on FAIL
    evil = tmp_path / "evil" / "model.pkl"
    evil.parent.mkdir()
    evil.write_bytes(pickle.dumps(EvilOsSystem()))
    evil_report = scan_target(evil)
    approvals.maybe_record(evil_report)
    assert evil_report.verdict == Verdict.FAIL
    # pre-seed then re-record to exercise revocation of a known digest
    FileApprovals(str(path)).apply({evil_report.files[0].sha256: "stale"}, set())
    approvals.maybe_record(evil_report)
    assert evil_report.files[0].sha256 not in load_approved_digests()


# -- ConfigMap backend (mocked K8s API) -------------------------------------------

class FakeK8s:
    """Minimal ConfigMap API double for urllib."""

    def __init__(self, existing: dict | None = None):
        self.cm = existing
        self.requests: list[tuple[str, str]] = []

    def urlopen(self, req, timeout=0, context=None):
        self.requests.append((req.get_method(), req.full_url))
        method = req.get_method()

        class R:
            def __init__(self, body):
                self._body = json.dumps(body).encode()

            def read(self):
                return self._body

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        if method == "GET":
            if self.cm is None:
                import urllib.error
                raise urllib.error.HTTPError(req.full_url, 404, "nf", {}, None)
            return R(self.cm)
        body = json.loads(req.data.decode())
        if method == "PATCH":
            self.cm.setdefault("data", {}).update(body["data"])
        else:  # POST create
            self.cm = body
        return R(self.cm)


def test_configmap_backend_patch(monkeypatch, tmp_path):
    fake = FakeK8s(existing={"metadata": {"name": "purser-approvals"},
                             "data": {"approved.txt": f"sha256:{D1}\n"}})
    monkeypatch.setattr("purser.core.approvals.urllib.request.urlopen", fake.urlopen)
    monkeypatch.setenv("PURSER_APPROVALS_NAMESPACE", "ns1")
    store = ConfigMapApprovals("purser-approvals")
    store.apply({D2: "PASS m"}, set())
    text = fake.cm["data"]["approved.txt"]
    assert parse_digests(text) == {D1, D2}
    assert ("PATCH" in [m for m, _ in fake.requests])
    assert all("/namespaces/ns1/configmaps/purser-approvals" in u
               for _, u in fake.requests)


def test_configmap_backend_creates_when_missing(monkeypatch):
    fake = FakeK8s(existing=None)
    monkeypatch.setattr("purser.core.approvals.urllib.request.urlopen", fake.urlopen)
    monkeypatch.setenv("PURSER_APPROVALS_NAMESPACE", "ns1")
    ConfigMapApprovals("purser-approvals").apply({D1: ""}, set())
    assert parse_digests(fake.cm["data"]["approved.txt"]) == {D1}
    assert fake.requests[-1][0] == "POST"


def test_configmap_backend_revoke(monkeypatch):
    fake = FakeK8s(existing={"metadata": {"name": "x"},
                             "data": {"approved.txt": f"{D1}\n{D2}\n"}})
    monkeypatch.setattr("purser.core.approvals.urllib.request.urlopen", fake.urlopen)
    monkeypatch.setenv("PURSER_APPROVALS_NAMESPACE", "ns1")
    ConfigMapApprovals("x").apply({}, {D1})
    assert parse_digests(fake.cm["data"]["approved.txt"]) == {D2}
