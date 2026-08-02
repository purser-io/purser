"""Upstream HuggingFace Hub scan verdicts as a signal source.

The Hub runs several scanners over uploaded files (picklescan, ClamAV,
Protect AI Guardian, JFrog) and exposes per-file verdicts on the tree API:

    GET {hub}/api/models/{repo_id}/tree/{revision}?recursive=true&expand=true
        -> [{"path": ..., "securityFileStatus": {...}}, ...]

Ingesting that verdict inherits the Hub's commercial scanners for free and
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

import json
import os
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from purser.core.env import env_get
from purser.core.findings import Finding, Severity
from purser.signals import SignalContext, unavailable_finding

DEFAULT_ENDPOINT = "https://huggingface.co"

# Upstream status vocabulary -> severity. Parsed defensively: the field is not
# formally documented, so unknown values are ignored rather than guessed at.
_UNSAFE = {"unsafe", "malicious", "dangerous", "blocked"}
_SUSPICIOUS = {"suspicious", "caution", "warning"}
# Not security verdicts: scan hasn't happened / didn't finish.
_NEUTRAL = {"safe", "innocuous", "clean", "ok", "queued", "pending", "none",
            "unscanned", "error", "skipped"}

_MAX_PAGES = 20          # tree API paginates via Link: rel="next"
_MAX_FINDINGS = 50       # cap per repo; the rest is summarized


def _hub_endpoint() -> str:
    return (os.environ.get("HF_ENDPOINT") or DEFAULT_ENDPOINT).rstrip("/")


def _timeout() -> float:
    return float(env_get("SIGNAL_TIMEOUT_SECONDS", "10") or "10")


def _fetch_json(url: str) -> tuple[Any, str | None]:
    """GET one page. Returns (parsed body, next-page URL or None)."""
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    token = os.environ.get("HF_TOKEN", "").strip()
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(req, timeout=_timeout()) as resp:  # nosec B310
        body = json.loads(resp.read().decode())
        link = resp.headers.get("Link", "")
    next_url = None
    for part in link.split(","):
        if 'rel="next"' in part and "<" in part:
            next_url = part[part.index("<") + 1:part.index(">")]
            break
    return body, next_url


def _statuses(node: Any) -> list[tuple[str, str]]:
    """Every (key-path, status-string) under a securityFileStatus blob.

    The blob nests per-scanner sub-reports (avScan, pickleImportScan, and
    whatever the Hub adds next), so walk it rather than hard-coding a schema.
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

    def collect(self, ctx: SignalContext) -> list[Finding]:
        repo = urllib.parse.quote(ctx.repo_id or "", safe="/")
        rev = urllib.parse.quote(ctx.revision or "main", safe="")
        url = (f"{_hub_endpoint()}/api/models/{repo}/tree/{rev}"
               "?recursive=true&expand=true")
        findings: list[Finding] = []
        flagged = 0
        pages = 0
        try:
            while url and pages < _MAX_PAGES:
                body, url = _fetch_json(url)
                pages += 1
                if not isinstance(body, list):
                    break
                for item in body:
                    if not isinstance(item, dict):
                        continue
                    fname = str(item.get("path", ""))
                    sec = item.get("securityFileStatus") or item.get("security")
                    if not sec:
                        continue
                    worst: tuple[Severity, str, str] | None = None
                    for key_path, status in _statuses(sec):
                        if status in _UNSAFE:
                            sev = Severity.HIGH
                        elif status in _SUSPICIOUS:
                            sev = Severity.MEDIUM
                        elif status in _NEUTRAL:
                            continue
                        else:
                            continue  # unknown vocabulary: ignore, never guess
                        if worst is None or sev > worst[0]:
                            worst = (sev, status, key_path)
                    if worst is None:
                        continue
                    flagged += 1
                    if flagged > _MAX_FINDINGS:
                        continue
                    sev, status, key_path = worst
                    rule = ("HF_UPSTREAM_UNSAFE" if sev >= Severity.HIGH
                            else "HF_UPSTREAM_SUSPICIOUS")
                    findings.append(Finding(
                        rule_id=rule,
                        severity=sev,
                        title=f"HuggingFace Hub scanners flag `{fname}` as {status}",
                        detail="Upstream verdict from the Hub's scan pipeline "
                               "(picklescan / ClamAV / Protect AI / JFrog), "
                               "corroborating independent analysis. An upstream "
                               "'safe' is never used to downgrade Purser's own "
                               "verdict.",
                        file=fname,
                        scanner=f"signals.{self.name}",
                        tags=["upstream-intel"],
                        evidence={
                            "repo_id": ctx.repo_id,
                            "revision": ctx.revision or "main",
                            "status": status,
                            "reported_by": key_path,
                        },
                    ))
        except (urllib.error.URLError, OSError, ValueError,
                json.JSONDecodeError) as exc:
            findings.append(unavailable_finding(
                self.name,
                f"could not fetch upstream scan verdicts for "
                f"{ctx.repo_id}: {exc}"))
            return findings
        if flagged > _MAX_FINDINGS:
            findings.append(Finding(
                rule_id="HF_UPSTREAM_UNSAFE",
                severity=Severity.HIGH,
                title=f"{flagged - _MAX_FINDINGS} additional files flagged by "
                      "HuggingFace Hub scanners (truncated)",
                detail=f"Only the first {_MAX_FINDINGS} upstream-flagged files "
                       "are listed individually.",
                scanner=f"signals.{self.name}",
                tags=["upstream-intel"],
                evidence={"repo_id": ctx.repo_id, "flagged_total": flagged},
            ))
        if url and pages >= _MAX_PAGES:
            findings.append(unavailable_finding(
                self.name,
                f"repo tree paginates beyond {_MAX_PAGES} pages; upstream "
                "verdicts beyond that were not fetched"))
        return findings
