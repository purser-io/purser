"""Admission webhook: image digest pinning + model-approval enforcement."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from purser import admission
from purser.admission import app, evaluate

PINNED = "ghcr.io/acme/model@sha256:" + "a" * 64
FLOATING = "ghcr.io/acme/model:latest"
APPROVED = "b" * 64
UNAPPROVED = "c" * 64


def _review(uid="uid-1", kind="Pod", images=(PINNED,), labels=None, annotations=None):
    containers = [{"name": f"c{i}", "image": img} for i, img in enumerate(images)]
    meta = {"labels": labels or {}, "annotations": annotations or {}}
    if kind == "Pod":
        obj = {"kind": "Pod", "metadata": meta, "spec": {"containers": containers}}
    else:
        obj = {"kind": kind, "spec": {"template": {"metadata": meta,
                                                   "spec": {"containers": containers}}}}
    return {"request": {"uid": uid, "object": obj}}


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    # Deterministic defaults; individual tests override as needed.
    for k in ("REQUIRE_IMAGE_DIGEST", "APPROVED_DIGESTS", "MODEL_ANNOTATION",
              "VERDICT_ANNOTATION", "ENFORCE_LABEL", "FAIL_OPEN"):
        monkeypatch.delenv("PURSER_ADMISSION_" + k, raising=False)
    # Enforce on everything by default in tests (no opt-in label required).
    monkeypatch.setenv("PURSER_ADMISSION_ENFORCE_LABEL", "")


@pytest.fixture
def client():
    return TestClient(app)


def _resp(review):
    r = evaluate(review)["response"]
    return r["allowed"], r.get("status", {}).get("message", "")


def test_healthz(client):
    assert client.get("/healthz").json()["status"] == "ok"


def test_uid_is_echoed():
    assert evaluate(_review(uid="abc-123"))["response"]["uid"] == "abc-123"


def test_digest_pinned_allowed():
    allowed, _ = _resp(_review(images=(PINNED,)))
    assert allowed is True


def test_floating_tag_denied():
    allowed, msg = _resp(_review(images=(FLOATING,)))
    assert allowed is False
    assert "not pinned by digest" in msg


def test_mixed_images_denied_on_the_floating_one():
    allowed, msg = _resp(_review(images=(PINNED, FLOATING)))
    assert allowed is False
    assert FLOATING in msg


def test_require_digest_can_be_disabled(monkeypatch):
    monkeypatch.setenv("PURSER_ADMISSION_REQUIRE_IMAGE_DIGEST", "0")
    allowed, _ = _resp(_review(images=(FLOATING,)))
    assert allowed is True


def test_opt_in_label_skips_unlabeled(monkeypatch):
    # With an enforce label configured, an unlabeled pod is not enforced.
    monkeypatch.setenv("PURSER_ADMISSION_ENFORCE_LABEL", "purser.io/enforce")
    allowed, _ = _resp(_review(images=(FLOATING,)))
    assert allowed is True
    # …but a labeled pod is.
    allowed, _ = _resp(_review(images=(FLOATING,), labels={"purser.io/enforce": "true"}))
    assert allowed is False


def test_verdict_annotation_fail_denied():
    allowed, msg = _resp(_review(annotations={"purser.io/scan-verdict": "FAIL"}))
    assert allowed is False
    assert "FAIL" in msg


def test_verdict_annotation_pass_allowed():
    allowed, _ = _resp(_review(annotations={"purser.io/scan-verdict": "PASS"}))
    assert allowed is True


def _approved_file(tmp_path, *digests):
    f = tmp_path / "approved.txt"
    f.write_text("# approved model digests\n" + "\n".join("sha256:" + d for d in digests))
    return str(f)


def test_declared_model_must_be_approved(tmp_path, monkeypatch):
    monkeypatch.setenv("PURSER_ADMISSION_APPROVED_DIGESTS",
                       _approved_file(tmp_path, APPROVED))
    ann = {"purser.io/models": f"model-a=sha256:{APPROVED}"}
    assert _resp(_review(annotations=ann))[0] is True
    ann = {"purser.io/models": f"sha256:{UNAPPROVED}"}
    allowed, msg = _resp(_review(annotations=ann))
    assert allowed is False and UNAPPROVED in msg


def test_declared_model_without_approved_list_denied():
    # Fail closed: models declared but no approved source configured.
    allowed, msg = _resp(_review(annotations={"purser.io/models": f"sha256:{APPROVED}"}))
    assert allowed is False
    assert "no approved-digest list" in msg


def test_approved_digests_from_directory(tmp_path, monkeypatch):
    d = tmp_path / "cm"
    d.mkdir()
    (d / "digests").write_text(f"{APPROVED}\n")
    monkeypatch.setenv("PURSER_ADMISSION_APPROVED_DIGESTS", str(d))
    assert admission.load_approved_digests() == {APPROVED}


def test_deployment_template_is_inspected():
    allowed, msg = _resp(_review(kind="Deployment", images=(FLOATING,)))
    assert allowed is False
    assert "not pinned by digest" in msg


def test_validate_endpoint(client):
    r = client.post("/validate", json=_review(images=(FLOATING,)))
    assert r.status_code == 200
    body = r.json()["response"]
    assert body["uid"] == "uid-1"
    assert body["allowed"] is False


def test_validate_bad_body_fails_closed(client):
    r = client.post("/validate", content=b"not json")
    assert r.status_code == 200
    assert r.json()["response"]["allowed"] is False


def test_validate_bad_body_can_fail_open(client, monkeypatch):
    monkeypatch.setenv("PURSER_ADMISSION_FAIL_OPEN", "1")
    r = client.post("/validate", content=b"not json")
    assert r.json()["response"]["allowed"] is True
