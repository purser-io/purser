"""Upstream HuggingFace Hub scan verdicts as a signal source.

The Hub runs several scanners over uploaded files (picklescan, ClamAV,
Protect AI Guardian, JFrog, VirusTotal) and exposes the results two ways
(both verified against the live API):

  GET {hub}/api/models/{repo}[/revision/{rev}]?securityStatus=true
      -> "securityRepoStatus": {"scansDone": bool,
                                "filesWithIssues": [{"path", "level"}]}

  POST {hub}/api/models/{repo}/paths-info/{rev}   {"paths": [...], "expand": true}
      -> per-file "securityFileStatus" with per-scanner sub-reports
         (protectAiScan / avScan / pickleImportScan / jFrogScan / ...)

This source uses the repo-level call as the verdict (one request, no
pagination) and, only when files are flagged, a best-effort paths-info call
to record *which* upstream scanner flagged them as evidence.

Ingesting these verdicts inherits the Hub's commercial scanners for free and
turns Purser from a competitor of those scanners into an aggregator of them.

Ground rule (non-negotiable): an upstream **unsafe** verdict is a
corroborating finding; an upstream **safe** verdict is NOT — upstream scanners
have documented false negatives (nullifAI, picklescan bypasses), so "safe"
must never downgrade or mask Purser's own analysis. This module therefore
only ever *emits* findings for flagged files and stays silent otherwise.

Network happens only when the artifact came from the Hub in the first place
(the `-hf` scan path — `hf://` CLI targets or `/v1/scan/huggingface`), so the
core's no-network posture for local scans is unchanged. Honors ``HF_ENDPOINT``
for enterprise/mirrored hubs and ``HF_TOKEN`` for private repos.
"""

from __future__ import annotations

import copy
import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from purser.core.env import env_get
from purser.core.findings import Finding, Severity
from purser.signals import SignalContext, unavailable_finding

DEFAULT_ENDPOINT = "https://huggingface.co"

# Observed `level` vocabulary: "unsafe", "caution". Parsed defensively — an
# unknown level still sits in *filesWithIssues*, so it is an issue by
# definition and defaults to MEDIUM rather than being dropped.
_UNSAFE = {"unsafe", "malicious", "dangerous", "blocked"}

_MAX_FINDINGS = 50       # cap per repo; the rest is summarized

# Per-process verdict cache. An immutable revision (a 40-hex commit sha) can
# never change, so it caches for the process lifetime; a mutable ref ("main",
# a tag) caches for PURSER_SIGNAL_CACHE_TTL seconds (default 300; 0 disables).
# Failures (SIGNAL_UNAVAILABLE) are never cached.
_COMMIT_SHA = re.compile(r"^[0-9a-f]{40}$")
_cache: dict[tuple[str, str, str], tuple[float | None, list[Finding]]] = {}


def _cache_ttl() -> float:
    return float(env_get("SIGNAL_CACHE_TTL", "300") or "300")


def _cache_get(key: tuple[str, str, str]) -> list[Finding] | None:
    hit = _cache.get(key)
    if hit is None:
        return None
    expiry, findings = hit
    if expiry is not None and time.monotonic() > expiry:
        _cache.pop(key, None)
        return None
    return copy.deepcopy(findings)  # never share Finding objects across reports


def _cache_put(key: tuple[str, str, str], revision: str,
               findings: list[Finding]) -> None:
    ttl = _cache_ttl()
    if ttl <= 0:
        return
    immutable = bool(_COMMIT_SHA.match(revision.lower()))
    expiry = None if immutable else time.monotonic() + ttl
    _cache[key] = (expiry, copy.deepcopy(findings))


def _hub_endpoint() -> str:
    return (os.environ.get("HF_ENDPOINT") or DEFAULT_ENDPOINT).rstrip("/")


def _timeout() -> float:
    return float(env_get("SIGNAL_TIMEOUT_SECONDS", "10") or "10")


def _request_json(url: str, payload: dict | None = None) -> Any:
    headers = {"Accept": "application/json"}
    data = None
    if payload is not None:
        data = json.dumps(payload).encode()
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers)
    token = os.environ.get("HF_TOKEN", "").strip()
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(req, timeout=_timeout()) as resp:  # nosec B310
        return json.loads(resp.read().decode())


def _statuses(node: Any) -> list[tuple[str, str]]:
    """Every (key-path, status-string) under a securityFileStatus blob.

    The blob nests per-scanner sub-reports (avScan, protectAiScan,
    pickleImportScan, and whatever the Hub adds next), so walk it rather
    than hard-coding a schema.
    """
    out: list[tuple[str, str]] = []

    def walk(obj: Any, path: str) -> None:
        if isinstance(obj, dict):
            for k, v in obj.items():
                kp = f"{path}.{k}" if path else str(k)
                if isinstance(v, str) and "status" in str(k).lower():
                    out.append((kp, v.strip().lower()))
                else:
                    walk(v, kp)
        elif isinstance(obj, list):
            for i, v in enumerate(obj):
                walk(v, f"{path}[{i}]")

    walk(node, "")
    return out


class HFVerdictsSource:
    """Surface the Hub's own per-file scan verdicts as corroborating findings."""

    name = "hf-verdicts"

    def available(self, ctx: SignalContext) -> bool:
        return ctx.source == "huggingface" and bool(ctx.repo_id)

    def _flagged_by(self, ctx: SignalContext, paths: list[str]) -> dict[str, list[str]]:
        """Best-effort detail: which upstream scanners flagged each path."""
        repo = urllib.parse.quote(ctx.repo_id or "", safe="/")
        rev = urllib.parse.quote(ctx.revision or "main", safe="")
        try:
            info = _request_json(
                f"{_hub_endpoint()}/api/models/{repo}/paths-info/{rev}",
                payload={"paths": paths, "expand": True})
        except (urllib.error.URLError, OSError, ValueError, json.JSONDecodeError):
            return {}
        out: dict[str, list[str]] = {}
        if not isinstance(info, list):
            return out
        for item in info:
            if not isinstance(item, dict):
                continue
            sec = item.get("securityFileStatus")
            if not sec:
                continue
            scanners = sorted({
                key_path.split(".")[0]
                for key_path, status in _statuses(sec)
                if "." in key_path and status not in ("safe", "innocuous", "queued")
            })
            if scanners:
                out[str(item.get("path", ""))] = scanners
        return out

    def collect(self, ctx: SignalContext) -> list[Finding]:
        revision = ctx.revision or "main"
        cache_key = (_hub_endpoint(), ctx.repo_id or "", revision)
        cached = _cache_get(cache_key)
        if cached is not None:
            return cached
        repo = urllib.parse.quote(ctx.repo_id or "", safe="/")
        url = f"{_hub_endpoint()}/api/models/{repo}"
        if ctx.revision:
            url += f"/revision/{urllib.parse.quote(ctx.revision, safe='')}"
        url += "?securityStatus=true"
        try:
            body = _request_json(url)
        except (urllib.error.URLError, OSError, ValueError,
                json.JSONDecodeError) as exc:
            return [unavailable_finding(
                self.name,
                f"could not fetch upstream scan verdicts for "
                f"{ctx.repo_id}: {exc}")]

        status = (body or {}).get("securityRepoStatus") if isinstance(body, dict) else None
        if not isinstance(status, dict):
            return [unavailable_finding(
                self.name,
                f"no securityRepoStatus in the Hub's response for {ctx.repo_id}")]

        findings: list[Finding] = []
        issues = [i for i in status.get("filesWithIssues") or []
                  if isinstance(i, dict)]
        detail_by_path = (
            self._flagged_by(ctx, [str(i.get("path", "")) for i in issues[:_MAX_FINDINGS]])
            if issues else {})
        for i, issue in enumerate(issues):
            if i >= _MAX_FINDINGS:
                findings.append(Finding(
                    rule_id="HF_UPSTREAM_UNSAFE",
                    severity=Severity.HIGH,
                    title=f"{len(issues) - _MAX_FINDINGS} additional files flagged "
                          "by HuggingFace Hub scanners (truncated)",
                    detail=f"Only the first {_MAX_FINDINGS} upstream-flagged "
                           "files are listed individually.",
                    scanner=f"signals.{self.name}",
                    tags=["upstream-intel"],
                    evidence={"repo_id": ctx.repo_id, "flagged_total": len(issues)},
                ))
                break
            fname = str(issue.get("path", ""))
            level = str(issue.get("level", "")).strip().lower()
            sev = Severity.HIGH if level in _UNSAFE else Severity.MEDIUM
            rule = ("HF_UPSTREAM_UNSAFE" if sev >= Severity.HIGH
                    else "HF_UPSTREAM_SUSPICIOUS")
            findings.append(Finding(
                rule_id=rule,
                severity=sev,
                title=f"HuggingFace Hub scanners flag `{fname}` as "
                      f"{level or 'an issue'}",
                detail="Upstream verdict from the Hub's scan pipeline "
                       "(picklescan / ClamAV / Protect AI / JFrog / "
                       "VirusTotal), corroborating independent analysis. An "
                       "upstream 'safe' is never used to downgrade Purser's "
                       "own verdict.",
                file=fname,
                scanner=f"signals.{self.name}",
                tags=["upstream-intel"],
                evidence={
                    "repo_id": ctx.repo_id,
                    "revision": ctx.revision or "main",
                    "level": level,
                    "reported_by": detail_by_path.get(fname, []),
                },
            ))
        if not status.get("scansDone", True):
            findings.append(unavailable_finding(
                self.name,
                f"the Hub has not finished scanning {ctx.repo_id}; upstream "
                "verdicts are incomplete"))
            return findings  # incomplete scans are never cached
        _cache_put(cache_key, revision, findings)
        return findings
