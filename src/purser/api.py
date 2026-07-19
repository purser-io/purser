"""Purser REST API.

Endpoints:
  GET  /healthz                 liveness/readiness (never authenticated)
  GET  /v1/policy               effective policy
  GET  /v1/origins              publisher -> country database
  POST /v1/scan/upload          multipart file upload scan
  POST /v1/scan/path            scan a path visible to the server (mounted volume)
  POST /v1/scan/huggingface     download + scan an HF repo (needs purser[hf])

The active policy is loaded from PURSER_POLICY (path to YAML); in
Kubernetes this is mounted from a ConfigMap so policy changes need no image
rebuild.

Security-relevant environment variables:
  PURSER_API_KEY            if set, all /v1 endpoints require this key via
                                `Authorization: Bearer <key>` or `X-API-Key`.
                                Multiple comma-separated keys are accepted.
  PURSER_MAX_CONCURRENT_SCANS  cap on in-flight scans (default 4); excess
                                requests get HTTP 429.
  PURSER_RATE_LIMIT_RPM     per-client (API key, else IP) requests/minute;
                                0 disables (default). Over-limit -> HTTP 429.
  PURSER_ENABLE_HF          "1"/"true" to enable the HuggingFace download
                                endpoint (disabled by default — it makes the
                                server fetch caller-chosen repos).
  PURSER_HF_ALLOWLIST       comma-separated org/repo prefixes permitted for
                                the HF endpoint (empty = any, once enabled).
  PURSER_METRICS_ENABLED    "0"/"false" to disable the /metrics endpoint
                                (Prometheus text format; enabled by default).
  PURSER_AUDIT              off | stdout | syslog — structured JSON audit log
                                per scan (default off). PURSER_SYSLOG_ADDRESS
                                ("/dev/log" or "host:port") targets a collector.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import shutil
import tempfile
import threading
import time
from pathlib import Path

from fastapi import Depends, FastAPI, File, Header, HTTPException, Request, UploadFile
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel

from purser import __version__
from purser.core import metrics
from purser.core.env import env_get
from purser.core.hf import HFNotAvailable, download_repo
from purser.core.policy import Policy, PolicyError
from purser.core.provenance import origin_db
from purser.core.scanner import scan_target

MAX_UPLOAD_BYTES = int(env_get("MAX_UPLOAD_MB", "10240")) * 1024 * 1024
MAX_CONCURRENT_SCANS = int(env_get("MAX_CONCURRENT_SCANS", "4"))

app = FastAPI(title="Purser", version=__version__,
              description="ML model security scanner with policy-based controls")

# Bounded concurrency: reject rather than queue so a flood of large uploads
# can't exhaust memory/disk. Non-blocking acquire -> HTTP 429 when full.
_scan_slots = threading.BoundedSemaphore(max(1, MAX_CONCURRENT_SCANS))


class _ScanSlot:
    def __enter__(self):
        if not _scan_slots.acquire(blocking=False):
            metrics.reject("capacity")
            raise HTTPException(status_code=429, detail="scanner at capacity; retry later")
        metrics.inc_inflight()
        return self

    def __exit__(self, *exc):
        metrics.dec_inflight()
        _scan_slots.release()


def _configured_keys() -> list[str]:
    raw = env_get("API_KEY", "")
    return [k.strip() for k in raw.split(",") if k.strip()]


# --- per-client rate limiting (token bucket) --------------------------------
# PURSER_RATE_LIMIT_RPM requests/minute per client (API key, else client
# IP); 0 disables. Burst capacity == the per-minute allowance.
_buckets: dict[str, tuple[float, float]] = {}
_bucket_lock = threading.Lock()
_MAX_BUCKETS = 10000


def _rate_limit_rpm() -> int:
    try:
        return int(env_get("RATE_LIMIT_RPM", "0"))
    except ValueError:
        return 0


def _client_id(request: Request, authorization: str | None, x_api_key: str | None) -> str:
    key = x_api_key
    if authorization and authorization.lower().startswith("bearer "):
        key = authorization[7:].strip()
    if key:
        return "k:" + hashlib.sha256(key.encode()).hexdigest()[:16]
    host = request.client.host if request.client else "unknown"
    return "ip:" + host


def rate_limit(
    request: Request,
    authorization: str | None = Header(default=None),
    x_api_key: str | None = Header(default=None),
) -> None:
    rpm = _rate_limit_rpm()
    if rpm <= 0:
        return
    rate = rpm / 60.0
    cid = _client_id(request, authorization, x_api_key)
    now = time.monotonic()
    with _bucket_lock:
        if len(_buckets) > _MAX_BUCKETS:  # crude prune to bound memory
            _buckets.clear()
        tokens, last = _buckets.get(cid, (float(rpm), now))
        tokens = min(float(rpm), tokens + (now - last) * rate)
        if tokens < 1.0:
            retry = int((1.0 - tokens) / rate) + 1
            metrics.reject("rate_limit")
            raise HTTPException(
                status_code=429, detail="rate limit exceeded",
                headers={"Retry-After": str(retry)},
            )
        _buckets[cid] = (tokens - 1.0, now)


def require_auth(
    authorization: str | None = Header(default=None),
    x_api_key: str | None = Header(default=None),
) -> None:
    """Dependency enforcing API-key auth when PURSER_API_KEY is set.

    No key configured => open (documented default for trusted networks).
    """
    keys = _configured_keys()
    if not keys:
        return
    presented = x_api_key
    if authorization and authorization.lower().startswith("bearer "):
        presented = authorization[7:].strip()
    # constant-time comparison against each accepted key
    if presented and any(hmac.compare_digest(presented, k) for k in keys):
        return
    metrics.reject("auth")
    raise HTTPException(status_code=401, detail="missing or invalid API key")


def get_policy() -> Policy:
    path = env_get("POLICY")
    if not path:
        return Policy.default()
    try:
        return Policy.load(path)
    except (OSError, PolicyError) as exc:
        raise HTTPException(status_code=500, detail=f"policy load failed: {exc}")


class PathScanRequest(BaseModel):
    path: str
    origin: str | None = None
    publisher: str | None = None


class HFScanRequest(BaseModel):
    repo_id: str
    revision: str | None = None
    origin: str | None = None


@app.get("/healthz")
def healthz() -> dict:
    return {"status": "ok", "version": __version__}


@app.get("/metrics")
def prometheus_metrics() -> PlainTextResponse:
    """Prometheus scrape endpoint. Unauthenticated by design (scrapers usually
    are); disable with PURSER_METRICS_ENABLED=0, and network-restrict it."""
    if (env_get("METRICS_ENABLED", "1") or "1").lower() in ("0", "false", "no"):
        raise HTTPException(status_code=404, detail="metrics disabled")
    return PlainTextResponse(metrics.render(),
                             media_type="text/plain; version=0.0.4; charset=utf-8")


@app.get("/v1/policy")
def policy(_: None = Depends(require_auth),
           __: None = Depends(rate_limit)) -> dict:
    return get_policy().to_dict()


@app.get("/v1/origins")
def origins(_: None = Depends(require_auth),
            __: None = Depends(rate_limit)) -> dict:
    return {"publishers": origin_db()}


@app.post("/v1/scan/upload")
async def scan_upload(
    file: UploadFile = File(...),
    origin: str | None = None,
    publisher: str | None = None,
    _: None = Depends(require_auth),
    __: None = Depends(rate_limit),
) -> dict:
    pol = get_policy()
    tmpdir = Path(tempfile.mkdtemp(prefix="purser-upload-"))
    try:
        # Never trust the client-provided filename for paths.
        safe_name = Path(file.filename or "upload.bin").name or "upload.bin"
        dest = tmpdir / safe_name
        written = 0
        with open(dest, "wb") as out:
            while chunk := await file.read(1024 * 1024):
                written += len(chunk)
                if written > MAX_UPLOAD_BYTES:
                    metrics.reject("upload_too_large")
                    raise HTTPException(status_code=413, detail="upload too large")
                out.write(chunk)
        with _ScanSlot():
            report = scan_target(dest, policy=pol, origin=origin, publisher=publisher)
        report.target = safe_name
        for fr in report.files:
            fr.path = Path(fr.path).name
        for f in report.all_findings:
            f.file = Path(f.file).name if f.file else ""
        return report.to_dict()
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


@app.post("/v1/scan/path")
def scan_path(req: PathScanRequest, _: None = Depends(require_auth),
              __: None = Depends(rate_limit)) -> dict:
    allowed_root = env_get("SCAN_ROOT", "/models")
    target = Path(req.path).resolve()
    root = Path(allowed_root).resolve()
    if target != root and root not in target.parents:
        raise HTTPException(
            status_code=403,
            detail=f"path scanning is restricted to {allowed_root}",
        )
    if not target.exists():
        raise HTTPException(status_code=404, detail="path not found")
    with _ScanSlot():
        report = scan_target(target, policy=get_policy(), origin=req.origin,
                             publisher=req.publisher)
    return report.to_dict()


def _hf_enabled() -> bool:
    return env_get("ENABLE_HF", "").lower() in ("1", "true", "yes")


def _hf_repo_allowed(repo_id: str) -> bool:
    raw = env_get("HF_ALLOWLIST", "")
    prefixes = [p.strip() for p in raw.split(",") if p.strip()]
    if not prefixes:
        return True
    return any(repo_id == p or repo_id.startswith(p.rstrip("/") + "/") for p in prefixes)


@app.post("/v1/scan/huggingface")
def scan_hf(req: HFScanRequest, _: None = Depends(require_auth),
            __: None = Depends(rate_limit)) -> dict:
    if not _hf_enabled():
        raise HTTPException(
            status_code=403,
            detail="HuggingFace scanning is disabled; set PURSER_ENABLE_HF=1",
        )
    if not _hf_repo_allowed(req.repo_id):
        raise HTTPException(
            status_code=403,
            detail="repo_id not permitted by PURSER_HF_ALLOWLIST",
        )
    try:
        with _ScanSlot():
            local = download_repo(req.repo_id, revision=req.revision,
                                  token=os.environ.get("HF_TOKEN"))
            try:
                report = scan_target(local, policy=get_policy(), origin=req.origin,
                                     repo_id=req.repo_id)
                report.target = f"hf://{req.repo_id}"
                return report.to_dict()
            finally:
                shutil.rmtree(local, ignore_errors=True)
    except HFNotAvailable as exc:
        raise HTTPException(status_code=501, detail=str(exc))
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"download failed: {exc}")
