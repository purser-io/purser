import pickle

import pytest
from fastapi.testclient import TestClient

from purser.api import app
from tests.conftest import EvilOsSystem


@pytest.fixture
def client(monkeypatch, tmp_path):
    monkeypatch.delenv("PURSER_POLICY", raising=False)
    monkeypatch.setenv("PURSER_SCAN_ROOT", str(tmp_path))
    return TestClient(app)


def test_healthz(client):
    r = client.get("/healthz")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_policy_endpoint(client):
    r = client.get("/v1/policy")
    assert r.status_code == 200
    assert r.json()["fail_on"]["severity"] == "HIGH"


def test_origins_endpoint(client):
    r = client.get("/v1/origins")
    assert r.status_code == 200
    assert r.json()["publishers"]["deepseek-ai"] == "CN"


def test_upload_scan_malicious(client):
    data = pickle.dumps(EvilOsSystem())
    r = client.post("/v1/scan/upload", files={"file": ("model.pkl", data)})
    assert r.status_code == 200
    body = r.json()
    assert body["verdict"] == "FAIL"
    assert body["severity_counts"]["CRITICAL"] >= 1


def test_upload_scan_benign(client):
    data = pickle.dumps({"w": [1.0]})
    r = client.post("/v1/scan/upload", files={"file": ("model.pkl", data)})
    assert r.status_code == 200
    assert r.json()["verdict"] in ("PASS", "WARN")


def test_path_scan_restricted(client):
    r = client.post("/v1/scan/path", json={"path": "/etc/passwd"})
    assert r.status_code == 403


def test_path_scan_allowed(client, tmp_path):
    target = tmp_path / "m.pkl"
    target.write_bytes(pickle.dumps({"ok": True}))
    r = client.post("/v1/scan/path", json={"path": str(target)})
    assert r.status_code == 200
    assert r.json()["verdict"] in ("PASS", "WARN")
