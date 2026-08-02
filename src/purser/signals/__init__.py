"""Pluggable signal sources feeding the policy engine.

Purser is a control plane: the verdict aggregates *signals* from many
analyzers. The built-in static scanners and the `purser-deep` companion are
two such signals; this package hosts the rest — external or third-party
intelligence about the artifact being scanned (upstream scan verdicts,
threat feeds, attestations).

A signal source is any object satisfying `SignalSource`:

    name        stable id — used in evidence, env gates, and logs
    available   cheap applicability check (no network)
    collect     gather findings; must NEVER raise — report trouble as a
                `SIGNAL_UNAVAILABLE` coverage-gap finding instead

Built-in sources are registered in `_BUILTIN_SOURCES`; third-party plugins
register via the ``purser.signals`` entry-point group (each entry point
resolves to a zero-arg callable returning a `SignalSource`).

Ground rules for every source:
  * Signals only ever ADD findings. A source that finds nothing contributes
    nothing — an upstream "safe"/"clean" verdict must never downgrade or mask
    what Purser's own analysis found.
  * Findings land on `ScanReport.signal_findings`, run through the same
    policy rule-overrides as scanner findings, and count toward the verdict.
  * Env gates: ``PURSER_SIGNALS=0`` disables all sources;
    ``PURSER_SIGNAL_<NAME>=0`` (name upper-cased, ``-``/``.`` -> ``_``)
    disables one.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from importlib import metadata as importlib_metadata
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

from purser.core.env import env_get
from purser.core.findings import Finding, Severity

ENTRY_POINT_GROUP = "purser.signals"

_FALSY = ("0", "false", "no", "off")


@dataclass
class SignalContext:
    """What a signal source is allowed to know about the scan.

    Deliberately small: sources see where the artifact came from and what is
    on disk, not the in-progress report — a signal cannot depend on (or
    suppress) other findings.
    """

    target: Path | None = None
    repo_id: str | None = None          # logical model id, e.g. "org/name"
    revision: str | None = None         # upstream revision, if known
    source: str | None = None           # artifact origin: "huggingface", None for local
    extra: dict[str, Any] = field(default_factory=dict)


@runtime_checkable
class SignalSource(Protocol):
    name: str

    def available(self, ctx: SignalContext) -> bool: ...

    def collect(self, ctx: SignalContext) -> list[Finding]: ...


def unavailable_finding(source: str, reason: str) -> Finding:
    """The standard 'this signal could not be gathered' coverage-gap finding."""
    return Finding(
        rule_id="SIGNAL_UNAVAILABLE",
        severity=Severity.LOW,
        title=f"Signal source '{source}' unavailable",
        detail=reason,
        scanner=f"signals.{source}",
        tags=["coverage-gap"],
        evidence={"signal": source},
    )


def signals_enabled() -> bool:
    return (env_get("SIGNALS", "1") or "").lower() not in _FALSY


def source_enabled(name: str) -> bool:
    key = "SIGNAL_" + name.upper().replace("-", "_").replace(".", "_")
    return (env_get(key, "1") or "").lower() not in _FALSY


def _builtin_sources() -> list[SignalSource]:
    from purser.signals.hf_verdicts import HFVerdictsSource

    return [HFVerdictsSource()]


def _plugin_sources() -> list[SignalSource]:
    """Third-party sources from the `purser.signals` entry-point group.

    A broken plugin must not break a scan: load failures surface as a
    coverage-gap finding via `collect_signals`, not an exception.
    """
    sources: list[SignalSource] = []
    try:
        eps = importlib_metadata.entry_points(group=ENTRY_POINT_GROUP)
    except Exception:
        return sources
    for ep in eps:
        try:
            factory = ep.load()
            src = factory()
            if isinstance(src, SignalSource):
                sources.append(src)
            else:
                sources.append(_BrokenSource(ep.name, "factory did not return a SignalSource"))
        except Exception as exc:
            sources.append(_BrokenSource(ep.name, f"failed to load plugin: {exc}"))
    return sources


class _BrokenSource:
    """Placeholder so a plugin that fails to load is visible in the report."""

    def __init__(self, name: str, reason: str) -> None:
        self.name = name
        self._reason = reason

    def available(self, ctx: SignalContext) -> bool:
        return True

    def collect(self, ctx: SignalContext) -> list[Finding]:
        return [unavailable_finding(self.name, self._reason)]


def iter_sources() -> list[SignalSource]:
    return _builtin_sources() + _plugin_sources()


def collect_signals(ctx: SignalContext) -> list[Finding]:
    """Run every enabled, applicable signal source. Never raises."""
    if not signals_enabled():
        return []
    findings: list[Finding] = []
    for src in iter_sources():
        try:
            if not source_enabled(src.name) or not src.available(ctx):
                continue
            findings.extend(src.collect(ctx))
        except Exception as exc:  # a signal source must never break a scan
            findings.append(unavailable_finding(
                getattr(src, "name", "unknown"), f"signal source raised: {exc}"))
    return findings
