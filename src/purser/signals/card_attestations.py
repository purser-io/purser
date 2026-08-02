"""Model-card / eval-attestation gate — the first `purser-eval` slice.

Static "visibility into evaluation" **without computing it**: reads what the
publisher *declares* about a model (the model card and its `model-index`
eval results, from `GET {hub}/api/models/{repo}`) and surfaces the *absence*
of those attestations as findings a policy can act on:

    CARD_MISSING            LOW   no model card at all
    CARD_NO_EVAL_RESULTS    LOW   card exists but declares no eval results

This governs the **attestation, not the behavior** — a declared accuracy
number says nothing about backdoors, and this source makes no behavioral
claims. It exists so an organization can require "models entering our
environment must document themselves" and enforce it like any other policy:
the default is a WARN-level nudge, and policy `rules:` overrides can
`ignore` either rule or escalate with `deny` (making an undocumented model
BLOCKED). Presence of eval results is deliberately *not* a finding — a
positive attestation must not push a clean scan to WARN.

Opt-in: set ``PURSER_CARD_ATTESTATIONS=1``. Most scans don't want a
documentation gate, so unlike other sources this one is off by default.
Like every hub signal it runs only on the `-hf` path; local scans stay
offline. Honors ``HF_ENDPOINT`` / ``HF_TOKEN``.
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

_TRUTHY = ("1", "true", "yes", "on")


def _hub_endpoint() -> str:
    return (os.environ.get("HF_ENDPOINT") or DEFAULT_ENDPOINT).rstrip("/")


def _timeout() -> float:
    return float(env_get("SIGNAL_TIMEOUT_SECONDS", "10") or "10")


def _get_json(url: str) -> Any:
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    token = os.environ.get("HF_TOKEN", "").strip()
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(req, timeout=_timeout()) as resp:  # nosec B310
        return json.loads(resp.read().decode())


def _eval_results(card_data: dict, body: dict) -> list[dict]:
    """Declared eval results from the card's `model-index` block."""
    index = card_data.get("model-index") or body.get("model-index") or []
    results: list[dict] = []
    if isinstance(index, list):
        for entry in index:
            if isinstance(entry, dict):
                results.extend(r for r in entry.get("results") or []
                               if isinstance(r, dict))
    return results


class CardAttestationsSource:
    """Gate on what the publisher declares: card presence + eval attestations."""

    name = "card-attestations"

    def available(self, ctx: SignalContext) -> bool:
        opted_in = (env_get("CARD_ATTESTATIONS", "") or "").lower() in _TRUTHY
        return opted_in and ctx.source == "huggingface" and bool(ctx.repo_id)

    def collect(self, ctx: SignalContext) -> list[Finding]:
        repo = urllib.parse.quote(ctx.repo_id or "", safe="/")
        url = f"{_hub_endpoint()}/api/models/{repo}"
        if ctx.revision:
            url += f"/revision/{urllib.parse.quote(ctx.revision, safe='')}"
        try:
            body = _get_json(url)
        except (urllib.error.URLError, OSError, ValueError,
                json.JSONDecodeError) as exc:
            return [unavailable_finding(
                self.name,
                f"could not fetch the model card for {ctx.repo_id}: {exc}")]
        if not isinstance(body, dict):
            return [unavailable_finding(
                self.name, f"unexpected Hub response for {ctx.repo_id}")]

        card_data = body.get("cardData")
        has_readme = any(
            isinstance(s, dict) and s.get("rfilename") == "README.md"
            for s in body.get("siblings") or [])
        evidence = {"repo_id": ctx.repo_id, "revision": ctx.revision or "main"}

        if not card_data and not has_readme:
            return [Finding(
                rule_id="CARD_MISSING",
                severity=Severity.LOW,
                title="Model publishes no model card",
                detail="The repository has no README/model card, so nothing "
                       "about the model's training, evaluation, or intended "
                       "use is attested. Policy rules can escalate this "
                       "(action: deny) to require documented models.",
                scanner=f"signals.{self.name}",
                tags=["attestation"],
                evidence=evidence,
            )]

        results = _eval_results(card_data if isinstance(card_data, dict) else {},
                                body)
        if not results:
            return [Finding(
                rule_id="CARD_NO_EVAL_RESULTS",
                severity=Severity.LOW,
                title="Model card declares no evaluation results",
                detail="A model card exists but its metadata attests no eval "
                       "results (`model-index`). This gates the attestation, "
                       "not the behavior — declared metrics are claims, not "
                       "proof of safety.",
                scanner=f"signals.{self.name}",
                tags=["attestation"],
                evidence=evidence,
            )]

        # Attestations present: not a finding (a positive claim must not WARN
        # a clean scan). Nothing to report.
        return []
