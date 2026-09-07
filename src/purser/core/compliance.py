"""Compliance framework tagging — enrichment, not detection.

Tags findings with control identifiers from the frameworks enterprise reviewers
arrive with — OWASP ML Top 10, OWASP LLM Top 10, NIST AI RMF, EU AI Act Annex
IV — so a scan report answers "which control does this evidence serve?" without
a human re-deriving the mapping. Tags look like ``owasp-llm:LLM03`` and
``eu-ai-act:AnnexIV-2``.

Deliberately the same shape as :mod:`purser.core.atlas`: a vendored
data-driven map (`purser/data/compliance_map.yaml`), longest-prefix match,
purely additive (tags are appended, so ``tags[0]`` remains the metrics
category), and it can never fail a scan. Disable with ``PURSER_COMPLIANCE=0``.

Because the map is data, the same file also generates
``docs/compliance-mapping.md`` (`make compliance-doc`) — one source of truth,
so the tags a reviewer greps for and the table they read cannot drift apart.

**A mapping is an aid to an auditor, not a compliance claim.** Purser produces
evidence for these controls; it does not by itself satisfy them. Mapping
granularity — exact for OWASP, category-level for NIST AI RMF — is documented
in the YAML header rather than overstated here.
"""

from __future__ import annotations

from functools import lru_cache
from importlib import resources

import yaml

from purser.core.env import env_get
from purser.core.findings import Finding, ScanReport


def compliance_enabled() -> bool:
    return (env_get("COMPLIANCE", "1") or "").strip().lower() not in (
        "0", "false", "no", "off")


@lru_cache(maxsize=1)
def _mapping() -> tuple[dict, list[tuple[str, list[str], bool]], list[str]]:
    """(frameworks, [(prefix, controls, no_umbrella)] longest-first, umbrella)."""
    try:
        text = (resources.files("purser.data") / "compliance_map.yaml").read_text()
        doc = yaml.safe_load(text) or {}
    except Exception:
        return {}, [], []
    frameworks = doc.get("frameworks") or {}
    umbrella = [str(c) for c in (doc.get("umbrella") or [])]
    prefixes: list[tuple[str, list[str], bool]] = []
    for rule in doc.get("rules") or []:
        controls = [str(c) for c in (rule.get("controls") or [])]
        no_umbrella = bool(rule.get("no_umbrella"))
        for p in rule.get("prefixes") or []:
            prefixes.append((str(p).upper(), controls, no_umbrella))
    prefixes.sort(key=lambda x: -len(x[0]))
    return frameworks, prefixes, umbrella


def frameworks() -> dict:
    """The framework catalogue (id -> name/url/controls). For docs and tests."""
    return _mapping()[0]


def controls_for(rule_id: str) -> list[str]:
    """Control ids for one finding rule id, umbrella included (may be empty)."""
    _, prefixes, umbrella = _mapping()
    rid = rule_id.upper()
    for prefix, controls, no_umbrella in prefixes:
        if rid.startswith(prefix):
            out = list(controls)
            if not no_umbrella:
                out += [c for c in umbrella if c not in out]
            return out
    return []


def known_controls() -> set[str]:
    """Every control id declared in the framework catalogue."""
    return {
        f"{fid}:{cid}"
        for fid, spec in frameworks().items()
        for cid in ((spec or {}).get("controls") or {})
    }


def _tag(finding: Finding) -> None:
    for control in controls_for(finding.rule_id):
        if control not in finding.tags:
            finding.tags.append(control)  # append: tags[0] stays the category


def tag_report(report: ScanReport) -> None:
    """Append compliance control tags to every finding. Never raises."""
    if not compliance_enabled():
        return
    try:
        for f in report.all_findings:
            _tag(f)
    except Exception:
        pass  # enrichment must never break a scan
