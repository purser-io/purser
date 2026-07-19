"""Scanner base class."""

from __future__ import annotations

from pathlib import Path

from purser.core.findings import Finding, Severity


class Scanner:
    """Base class for format scanners. Subclasses implement scan()."""

    name: str = "base"

    def scan(self, path: Path) -> list[Finding]:  # pragma: no cover - interface
        raise NotImplementedError

    def finding(
        self,
        rule_id: str,
        severity: Severity,
        title: str,
        detail: str = "",
        tags: list[str] | None = None,
        evidence: dict | None = None,
    ) -> Finding:
        return Finding(
            rule_id=rule_id,
            severity=severity,
            title=title,
            detail=detail,
            scanner=self.name,
            tags=tags or [],
            evidence=evidence or {},
        )
