"""MITRE ATLAS technique tagging — enrichment, not detection.

Tags findings with ATLAS technique ids (``atlas:AML.T####``) from a vendored
mapping (`purser/data/atlas_map.yaml`) so reports speak the adversary-ML
framework reviewers and SOC tooling expect. Purely additive: tags are
appended (never prepended — the first tag remains the metrics category), the
mapping is data-driven, and nothing about severities or verdicts changes.
Disable with ``PURSER_ATLAS=0``.
"""

from __future__ import annotations

from functools import lru_cache
from importlib import resources

import yaml

from purser.core.env import env_get
from purser.core.findings import Finding, ScanReport


def atlas_enabled() -> bool:
    return (env_get("ATLAS", "1") or "").strip().lower() not in ("0", "false", "no", "off")


@lru_cache(maxsize=1)
def _mapping() -> tuple[dict[str, str], list[tuple[str, str]], str]:
    """(technique_id -> name, [(prefix, technique_id)] longest-first, umbrella)."""
    try:
        text = (resources.files("purser.data") / "atlas_map.yaml").read_text()
        doc = yaml.safe_load(text) or {}
    except Exception:
        return {}, [], ""
    names: dict[str, str] = {}
    prefixes: list[tuple[str, str]] = []
    umbrella = doc.get("umbrella") or {}
    umbrella_id = str(umbrella.get("id", ""))
    if umbrella_id:
        names[umbrella_id] = str(umbrella.get("name", ""))
    for tid, spec in (doc.get("techniques") or {}).items():
        names[str(tid)] = str((spec or {}).get("name", ""))
        for p in (spec or {}).get("prefixes", []) or []:
            prefixes.append((str(p).upper(), str(tid)))
    prefixes.sort(key=lambda x: -len(x[0]))
    return names, prefixes, umbrella_id


def techniques_for(rule_id: str) -> list[str]:
    """ATLAS technique ids for one finding rule id (may be empty)."""
    _, prefixes, umbrella_id = _mapping()
    rid = rule_id.upper()
    out: list[str] = []
    for prefix, tid in prefixes:
        if rid.startswith(prefix):
            out.append(tid)
            break
    if out and umbrella_id and umbrella_id not in out:
        out.append(umbrella_id)
    return out


def _tag(finding: Finding) -> None:
    for tid in techniques_for(finding.rule_id):
        tag = f"atlas:{tid}"
        if tag not in finding.tags:
            finding.tags.append(tag)  # append: tags[0] stays the category


def tag_report(report: ScanReport) -> None:
    """Append ATLAS tags to every finding on the report. Never raises."""
    if not atlas_enabled():
        return
    try:
        for f in report.all_findings:
            _tag(f)
    except Exception:
        pass  # enrichment must never break a scan
