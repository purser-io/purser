"""Approval store — the piece that closes the scan→approve→admit loop.

The admission webhook (`purser.admission`) enforces an approved-model-digest
list, but until now an operator had to maintain that list by hand (ConfigMap /
GitOps). This module lets a scan verdict *populate* it automatically:

  * a report whose verdict is in ``PURSER_AUTO_APPROVE_VERDICTS`` (default:
    ``PASS``) **approves** the SHA-256 of every scanned file;
  * a ``FAIL`` / ``BLOCKED`` verdict **revokes** those digests — a model that
    was approved once and later fails a re-scan loses its approval.

Two backends, selected by environment:

  ``PURSER_APPROVALS_PATH``       a plain text file (one digest per line, the
                                  exact format `admission.load_approved_digests`
                                  reads). Fits CI + GitOps: commit/sync the file
                                  into the webhook's ConfigMap.
  ``PURSER_APPROVALS_CONFIGMAP``  the name of a ConfigMap to patch in-cluster
                                  via the Kubernetes API (stdlib HTTP with the
                                  pod's ServiceAccount token — no client dep).
                                  The webhook mounts the same ConfigMap, so a
                                  PASS at `/v1/scan/*` becomes deployable
                                  without an operator hop.

Everything is **opt-in** (``PURSER_AUTO_APPROVE=1``): auto-approval is a policy
decision, not a default. Recording never raises — a store failure must not
break a scan — and every action is reported in the scan's
``metadata["approvals"]`` so it lands in the audit log.
"""

from __future__ import annotations

import json
import logging
import re
import ssl
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from purser.core.env import env_get
from purser.core.findings import ScanReport, Verdict

_log = logging.getLogger("purser.approvals")

_HEX64 = re.compile(r"(?:sha256:)?([a-fA-F0-9]{64})")

_SA_DIR = Path("/var/run/secrets/kubernetes.io/serviceaccount")

_REVOKE_VERDICTS = {Verdict.FAIL, Verdict.BLOCKED}


def parse_digests(text: str) -> set[str]:
    """Digests from approved-list text (same format the webhook reads)."""
    out: set[str] = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = _HEX64.search(line)
        if m:
            out.add(m.group(1).lower())
    return out


def render_digests(digests: dict[str, str]) -> str:
    """Render digest -> note as the file format the webhook reads."""
    lines = ["# Purser approved model digests — managed by auto-approval",
             "# (sha256 per line; comments record provenance)"]
    for d in sorted(digests):
        note = digests[d]
        lines.append(f"sha256:{d}" + (f"  # {note}" if note else ""))
    return "\n".join(lines) + "\n"


def _clean_note(s: str) -> str:
    return "".join(c for c in s.replace("\n", " ").replace("\r", " ")
                   if c.isprintable())[:120]


# --- backends -----------------------------------------------------------------

class FileApprovals:
    """Digest list in a plain file; atomic rewrite on change."""

    def __init__(self, path: str) -> None:
        self.path = Path(path)

    def describe(self) -> str:
        return f"file:{self.path}"

    def _load(self) -> dict[str, str]:
        if not self.path.exists():
            return {}
        out: dict[str, str] = {}
        for line in self.path.read_text().splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            m = _HEX64.search(stripped)
            if not m:
                continue
            note = ""
            if "#" in stripped:
                note = stripped.split("#", 1)[1].strip()
            out[m.group(1).lower()] = note
        return out

    def apply(self, approve: dict[str, str], revoke: set[str]) -> None:
        current = self._load()
        for d, note in approve.items():
            current[d] = note
        for d in revoke:
            current.pop(d, None)
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        tmp.parent.mkdir(parents=True, exist_ok=True)
        tmp.write_text(render_digests(current))
        tmp.replace(self.path)


class ConfigMapApprovals:
    """Digest list in one key of a ConfigMap, patched via the K8s API.

    Uses the pod's ServiceAccount credentials with stdlib HTTP — needs RBAC
    ``get`` + ``patch`` on that one ConfigMap (the Helm chart ships the Role).
    """

    def __init__(self, name: str) -> None:
        self.name = name
        self.key = env_get("APPROVALS_CONFIGMAP_KEY", "approved.txt") or "approved.txt"
        ns = env_get("APPROVALS_NAMESPACE", "")
        if not ns:
            try:
                ns = (_SA_DIR / "namespace").read_text().strip()
            except OSError:
                ns = "default"
        self.namespace = ns
        self.api_base = (env_get("K8S_API_URL", "") or
                         "https://kubernetes.default.svc").rstrip("/")

    def describe(self) -> str:
        return f"configmap:{self.namespace}/{self.name}[{self.key}]"

    def _request(self, method: str, url: str, body: dict | None = None,
                 content_type: str = "application/json") -> dict:
        token = ""
        try:
            token = (_SA_DIR / "token").read_text().strip()
        except OSError:
            pass
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, method=method,
                                     headers={"Accept": "application/json"})
        if data is not None:
            req.add_header("Content-Type", content_type)
        if token:
            req.add_header("Authorization", f"Bearer {token}")
        ca = _SA_DIR / "ca.crt"
        ctx = ssl.create_default_context(
            cafile=str(ca)) if ca.exists() else ssl.create_default_context()
        with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:  # nosec B310
            return json.loads(resp.read().decode() or "{}")

    def apply(self, approve: dict[str, str], revoke: set[str]) -> None:
        url = (f"{self.api_base}/api/v1/namespaces/{self.namespace}"
               f"/configmaps/{self.name}")
        try:
            cm = self._request("GET", url)
        except urllib.error.HTTPError as exc:
            if exc.code != 404:
                raise
            cm = {}
        text = ((cm.get("data") or {}).get(self.key)) or ""
        current: dict[str, str] = {d: "" for d in parse_digests(text)}
        # preserve existing notes where present
        for line in text.splitlines():
            m = _HEX64.search(line)
            if m and "#" in line and not line.strip().startswith("#"):
                current[m.group(1).lower()] = line.split("#", 1)[1].strip()
        for d, note in approve.items():
            current[d] = note
        for d in revoke:
            current.pop(d, None)
        patch = {"data": {self.key: render_digests(current)}}
        if cm:
            self._request("PATCH", url, patch,
                          content_type="application/merge-patch+json")
        else:
            create = {"apiVersion": "v1", "kind": "ConfigMap",
                      "metadata": {"name": self.name,
                                   "namespace": self.namespace}, **patch}
            self._request("POST",
                          f"{self.api_base}/api/v1/namespaces/{self.namespace}/configmaps",
                          create)


# --- recording ------------------------------------------------------------------

def auto_approve_enabled() -> bool:
    return (env_get("AUTO_APPROVE", "") or "").strip().lower() in ("1", "true", "yes", "on")


def approve_verdicts() -> set[str]:
    raw = env_get("AUTO_APPROVE_VERDICTS", "PASS") or "PASS"
    return {v.strip().upper() for v in raw.split(",") if v.strip()}


def _store() -> FileApprovals | ConfigMapApprovals | None:
    path = env_get("APPROVALS_PATH", "")
    if path:
        return FileApprovals(path)
    cm = env_get("APPROVALS_CONFIGMAP", "")
    if cm:
        return ConfigMapApprovals(cm)
    return None


def record_report(report: ScanReport) -> dict[str, Any] | None:
    """Approve/revoke the report's file digests per its verdict. Never raises.

    Returns a summary dict (also useful for `metadata["approvals"]`), or None
    when auto-approval is disabled / not configured / not applicable.
    """
    if not auto_approve_enabled():
        return None
    store = _store()
    if store is None:
        return {"error": "PURSER_AUTO_APPROVE=1 but no approvals store is "
                         "configured (PURSER_APPROVALS_PATH or "
                         "PURSER_APPROVALS_CONFIGMAP)"}
    digests = {fr.sha256.lower() for fr in report.files if fr.sha256 and not fr.error}
    if not digests:
        return None
    verdict = report.verdict
    stamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
    note = _clean_note(f"{verdict.value} {report.target} policy={report.policy_name} {stamp}")
    try:
        if verdict.value in approve_verdicts():
            store.apply({d: note for d in digests}, set())
            action = "approved"
        elif verdict in _REVOKE_VERDICTS:
            store.apply({}, digests)
            action = "revoked"
        else:
            return None
    except Exception as exc:
        # Detail goes to the server log only — the summary lands in the API
        # response via metadata.approvals, and exception text can leak paths
        # or backend error bodies to external clients.
        _log.warning("approvals store update failed (%s): %s",
                     store.describe(), exc)
        return {"error": "approvals store update failed (see server logs)",
                "store": store.describe()}
    return {"action": action, "digests": sorted(digests),
            "store": store.describe(), "verdict": verdict.value}


def maybe_record(report: ScanReport) -> None:
    """Record approvals and surface the outcome on the report metadata."""
    summary = record_report(report)
    if summary is not None:
        report.metadata["approvals"] = summary
