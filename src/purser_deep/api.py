"""Purser Deep — standalone companion service.

A separate app/container. The core scanner calls it when deep analysis is
enabled (see PURSER_ENABLE_DEEP / PURSER_DEEP_URL in the core). Kept
separate so the heavier, higher-false-positive analyzers don't sit in the
core's hostile-input path.

Endpoints:
  GET  /healthz          liveness
  POST /v1/deep-scan     raw file bytes in the body; returns findings as JSON

Auth: shares the core's PURSER_API_KEY convention (Bearer or X-API-Key)
when that variable is set.
"""

from __future__ import annotations

import hmac
import tempfile
from pathlib import Path

from fastapi import FastAPI, Header, HTTPException, Request

from purser_deep import __version__
from purser_deep.scan import deep_scan_file
from purser.core.env import env_get

MAX_BODY_BYTES = int(env_get("DEEP_MAX_UPLOAD_MB", "10240")) * 1024 * 1024

app = FastAPI(title="Purser Deep", version=__version__,
              description="Companion deep analyzers (gadget-chain + weight tampering)")


def _require_auth(authorization: str | None, x_api_key: str | None) -> None:
    raw = env_get("API_KEY", "")
    keys = [k.strip() for k in raw.split(",") if k.strip()]
    if not keys:
        return
    presented = x_api_key
    if authorization and authorization.lower().startswith("bearer "):
        presented = authorization[7:].strip()
    if presented and any(hmac.compare_digest(presented, k) for k in keys):
        return
    raise HTTPException(status_code=401, detail="missing or invalid API key")


@app.get("/healthz")
def healthz() -> dict:
    return {"status": "ok", "version": __version__, "service": "purser-deep"}


@app.post("/v1/deep-scan")
async def deep_scan(
    request: Request,
    x_filename: str | None = Header(default=None),
    authorization: str | None = Header(default=None),
    x_api_key: str | None = Header(default=None),
) -> dict:
    _require_auth(authorization, x_api_key)
    body = await request.body()
    if len(body) > MAX_BODY_BYTES:
        raise HTTPException(status_code=413, detail="body too large")
    safe_name = Path(x_filename or "upload.bin").name or "upload.bin"
    tmpdir = Path(tempfile.mkdtemp(prefix="purser-deep-"))
    try:
        dest = tmpdir / safe_name
        dest.write_bytes(body)
        findings = deep_scan_file(dest)
        for f in findings:
            f.file = safe_name
        return {"findings": [f.to_dict() for f in findings]}
    finally:
        import shutil
        shutil.rmtree(tmpdir, ignore_errors=True)
