"""Core → deep-analysis integration.

The deep analyzers live in the separate `purser-deep` app/container. The
core delegates to them only when enabled by environment variable:

  PURSER_ENABLE_DEEP=1     master switch (off by default)
  PURSER_DEEP_URL=...      base URL of the purser-deep service; if set,
                              the core calls it over HTTP. If enabled but no URL
                              is set, the core runs the analyzers in-process
                              when the `purser_deep` package is importable.
  PURSER_DEEP_MAX_MB=1024  cap on bytes sent to the service per file.
  PURSER_API_KEY=...        forwarded to the deep service if it requires auth.

Failure is visible, not silent: if deep is enabled but unreachable, a
`DEEP_UNAVAILABLE` finding is added so the coverage gap shows up in the report.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from pathlib import Path

from purser.core.findings import Finding, Severity
from purser.core.env import env_get

# Formats the deep analyzers actually inspect — avoid pointless round trips.
DEEP_FORMATS = {
    "pickle", "pytorch", "pytorch_legacy", "joblib", "numpy", "paddle",
    "safetensors",
}


def deep_enabled() -> bool:
    return env_get("ENABLE_DEEP", "").lower() in ("1", "true", "yes")


def _finding_from_dict(d: dict) -> Finding:
    return Finding(
        rule_id=str(d.get("rule_id", "DEEP_UNKNOWN")),
        severity=Severity.parse(d.get("severity", "LOW")),
        title=str(d.get("title", "")),
        detail=str(d.get("detail", "")),
        file=str(d.get("file", "")),
        scanner=str(d.get("scanner", "deep")),
        tags=list(d.get("tags", [])),
        evidence=dict(d.get("evidence", {})),
    )


def _via_http(path: Path, url: str) -> list[Finding]:
    cap = int(env_get("DEEP_MAX_MB", "1024")) * 1024 * 1024
    size = path.stat().st_size
    with open(path, "rb") as fh:
        body = fh.read(cap)
    req = urllib.request.Request(
        url.rstrip("/") + "/v1/deep-scan", data=body, method="POST",
        headers={"Content-Type": "application/octet-stream", "X-Filename": path.name},
    )
    api_key = env_get("API_KEY", "").split(",")[0].strip()
    if api_key:
        req.add_header("X-API-Key", api_key)
    with urllib.request.urlopen(req, timeout=120) as resp:
        payload = json.loads(resp.read().decode())
    findings = [_finding_from_dict(d) for d in payload.get("findings", [])]
    if size > cap:
        findings.append(Finding(
            "DEEP_SCAN_TRUNCATED", Severity.LOW,
            "Deep analysis saw only the head of a large file",
            f"Sent {cap} of {size} bytes to the deep service.",
            scanner="deep", tags=["coverage-gap"],
        ))
    return findings


def _in_process(path: Path) -> list[Finding] | None:
    try:
        from purser_deep.scan import deep_scan_file
    except ImportError:
        return None
    return deep_scan_file(path)


def run_deep(path: Path) -> list[Finding]:
    """Run deep analysis for one file if enabled; never raises."""
    if not deep_enabled():
        return []
    path = Path(path)
    url = env_get("DEEP_URL", "").strip()
    try:
        if url:
            return _via_http(path, url)
        inproc = _in_process(path)
        if inproc is not None:
            return inproc
        return [Finding(
            "DEEP_UNAVAILABLE", Severity.MEDIUM,
            "Deep analysis enabled but unavailable",
            "PURSER_ENABLE_DEEP is set but no PURSER_DEEP_URL is "
            "configured and the purser_deep package is not importable.",
            scanner="deep", tags=["coverage-gap"],
        )]
    except (urllib.error.URLError, OSError, ValueError, json.JSONDecodeError) as exc:
        return [Finding(
            "DEEP_UNAVAILABLE", Severity.MEDIUM,
            "Deep analysis service unreachable",
            f"Could not reach the deep service: {exc}",
            scanner="deep", tags=["coverage-gap"],
        )]
