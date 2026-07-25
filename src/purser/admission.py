"""Kubernetes ValidatingAdmissionWebhook — enforce scan verdicts at *deploy* time.

Scanning a model in CI proves it was safe *when scanned*; it does not stop a
different (unscanned or malicious) artifact — or a mutable image tag — from
reaching the cluster later. This webhook closes that scan→deploy TOCTOU gap by
gating admission of workloads on two invariants:

  1. **Image digest pinning.** Every container image must be pinned by
     `@sha256:` digest, not a floating tag a registry can repoint.
  2. **Model approval.** A workload that declares model artifacts (annotation
     ``purser.io/models``) must reference only digests on the approved list —
     the SHA-256s Purser recorded for models that passed policy. An explicit
     FAIL/BLOCKED verdict annotation is always rejected.

The webhook is fail-closed by default (a processing error denies admission);
set ``PURSER_ADMISSION_FAIL_OPEN=1`` to fail open. It is a pure function over
the AdmissionReview payload (`evaluate`), wrapped by a tiny FastAPI app so it is
trivially unit-testable without a cluster.

Run:  uvicorn purser.admission:app --host 0.0.0.0 --port 8443 \
        --ssl-keyfile /tls/tls.key --ssl-certfile /tls/tls.crt

Configuration (PURSER_ADMISSION_* env):
  REQUIRE_IMAGE_DIGEST  "1"/"0"  require @sha256: on every image (default 1)
  APPROVED_DIGESTS      path     file or dir of approved model SHA-256s
                                  (typically a mounted ConfigMap). Empty => the
                                  model-approval check is skipped (image pinning
                                  still applies).
  MODEL_ANNOTATION      key      pod annotation listing model digests
                                  (default purser.io/models)
  VERDICT_ANNOTATION    key      pod annotation carrying a scan verdict
                                  (default purser.io/scan-verdict)
  ENFORCE_LABEL         key      only enforce when this pod label == "true";
                                  empty => enforce on everything admitted
                                  (default purser.io/enforce)
  FAIL_OPEN             "1"/"0"  allow on internal error (default 0 = fail closed)
"""

from __future__ import annotations

import re
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from purser import __version__
from purser.core.env import env_get

app = FastAPI(title="Purser admission webhook", version=__version__,
              description="Enforces scan verdicts + image digest pinning at deploy time")

_HEX64 = re.compile(r"(?:sha256:)?([a-fA-F0-9]{64})")
_REJECT_VERDICTS = {"FAIL", "BLOCKED"}


# --- configuration ----------------------------------------------------------

def _flag(suffix: str, default: str) -> bool:
    return (env_get(suffix, default) or "").strip().lower() in ("1", "true", "yes")


def _require_image_digest() -> bool:
    return _flag("ADMISSION_REQUIRE_IMAGE_DIGEST", "1")


def _fail_open() -> bool:
    return _flag("ADMISSION_FAIL_OPEN", "0")


def _model_annotation() -> str:
    return env_get("ADMISSION_MODEL_ANNOTATION", "purser.io/models") or "purser.io/models"


def _verdict_annotation() -> str:
    return env_get("ADMISSION_VERDICT_ANNOTATION", "purser.io/scan-verdict") or "purser.io/scan-verdict"


def _enforce_label() -> str:
    v = env_get("ADMISSION_ENFORCE_LABEL", "purser.io/enforce")
    return "" if v is None else v.strip()


def load_approved_digests() -> set[str]:
    """Approved model SHA-256s from PURSER_ADMISSION_APPROVED_DIGESTS.

    Points at a file or a directory (a mounted ConfigMap is a directory of
    files). Lines may be bare hex or ``sha256:<hex>``; blanks and ``#`` comments
    are ignored. Returns lowercase hex digests.
    """
    from pathlib import Path

    path = env_get("ADMISSION_APPROVED_DIGESTS", "")
    if not path:
        return set()
    p = Path(path)
    files: list[Path] = []
    if p.is_dir():
        files = [f for f in p.iterdir() if f.is_file() and not f.name.startswith("..")]
    elif p.is_file():
        files = [p]
    out: set[str] = set()
    for f in files:
        try:
            text = f.read_text()
        except OSError:
            continue
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            m = _HEX64.search(line)
            if m:
                out.add(m.group(1).lower())
    return out


# --- pod extraction ---------------------------------------------------------

def _pod_template(obj: dict) -> tuple[dict, dict]:
    """Return (podSpec, podMetadata) for a Pod or any pod-template-bearing
    controller (Deployment/StatefulSet/DaemonSet/Job/ReplicaSet/...)."""
    kind = obj.get("kind", "")
    spec = obj.get("spec", {}) or {}
    if kind == "Pod":
        return spec, obj.get("metadata", {}) or {}
    tmpl = spec.get("template", {}) or {}
    return (tmpl.get("spec", {}) or {}), (tmpl.get("metadata", {}) or {})


def _images(pod_spec: dict) -> list[str]:
    out: list[str] = []
    for key in ("initContainers", "containers", "ephemeralContainers"):
        for c in pod_spec.get(key, []) or []:
            img = c.get("image")
            if img:
                out.append(img)
    return out


def _declared_model_digests(annotations: dict) -> list[str]:
    raw = annotations.get(_model_annotation(), "") or ""
    out: list[str] = []
    for token in re.split(r"[,\s]+", raw):
        token = token.strip()
        if not token:
            continue
        m = _HEX64.search(token)
        if m:
            out.append(m.group(1).lower())
    return out


# --- core decision ----------------------------------------------------------

def _decide(obj: dict) -> tuple[bool, list[str], list[str]]:
    """(allowed, deny_reasons, warnings) for one admitted object."""
    pod_spec, pod_meta = _pod_template(obj)
    labels = pod_meta.get("labels", {}) or {}
    annotations = pod_meta.get("annotations", {}) or {}

    enforce_label = _enforce_label()
    if enforce_label and str(labels.get(enforce_label, "")).lower() != "true":
        return True, [], []  # opted out

    reasons: list[str] = []
    warnings: list[str] = []

    if _require_image_digest():
        for img in _images(pod_spec):
            if "@sha256:" not in img:
                reasons.append(
                    f"image not pinned by digest: {img!r} (use image@sha256:<digest>)")

    verdict = str(annotations.get(_verdict_annotation(), "")).upper()
    if verdict in _REJECT_VERDICTS:
        reasons.append(f"declared scan verdict is {verdict}")

    declared = _declared_model_digests(annotations)
    if declared:
        approved = load_approved_digests()
        if not approved:
            reasons.append(
                "workload declares models but no approved-digest list is configured "
                "(PURSER_ADMISSION_APPROVED_DIGESTS)")
        else:
            for d in declared:
                if d not in approved:
                    reasons.append(f"model digest not approved: sha256:{d}")
    elif not _images(pod_spec):
        warnings.append("no containers found to validate")

    return (not reasons), reasons, warnings


def _response(uid: str, allowed: bool, message: str, warnings: list[str]) -> dict:
    status = {"code": 200 if allowed else 403}
    if message:
        status["message"] = message
    resp: dict[str, Any] = {"uid": uid, "allowed": allowed, "status": status}
    if warnings:
        resp["warnings"] = warnings
    return {
        "apiVersion": "admission.k8s.io/v1",
        "kind": "AdmissionReview",
        "response": resp,
    }


def evaluate(review: dict) -> dict:
    """Pure AdmissionReview(request) -> AdmissionReview(response)."""
    req = (review or {}).get("request", {}) or {}
    uid = req.get("uid", "")
    try:
        obj = req.get("object") or {}
        allowed, reasons, warnings = _decide(obj)
        if allowed:
            msg = "purser: admission checks passed"
        else:
            msg = "purser denied admission: " + "; ".join(reasons)
        return _response(uid, allowed, msg, warnings)
    except Exception as exc:  # pragma: no cover - defensive
        if _fail_open():
            return _response(uid, True, f"purser: check errored, failing open: {exc}", [])
        return _response(uid, False, f"purser: check errored, failing closed: {exc}", [])


# --- HTTP surface -----------------------------------------------------------

@app.get("/healthz")
def healthz() -> dict:
    return {"status": "ok", "version": __version__}


@app.post("/validate")
async def validate(request: Request) -> JSONResponse:
    try:
        review = await request.json()
    except Exception:
        # Unparseable body -> can't read uid; honor fail-open/closed explicitly
        # (don't fall through to evaluate(), which would treat {} as an empty,
        # allowable object).
        allowed = _fail_open()
        return JSONResponse(_response(
            "", allowed,
            "purser: could not parse AdmissionReview, failing "
            + ("open" if allowed else "closed"), []))
    return JSONResponse(evaluate(review))
