"""Core result types shared by all scanners and the policy engine."""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any


class Severity(enum.IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: "str | int | Severity") -> "Severity":
        if isinstance(value, Severity):
            return value
        if isinstance(value, int):
            return cls(value)
        return cls[value.strip().upper()]

    def __str__(self) -> str:  # noqa: D105
        return self.name


class Verdict(str, enum.Enum):
    PASS = "PASS"
    WARN = "WARN"
    FAIL = "FAIL"
    BLOCKED = "BLOCKED"  # rejected by policy before/independent of content findings
    ERROR = "ERROR"


@dataclass
class Finding:
    """A single security finding produced by a scanner or the policy engine."""

    rule_id: str
    severity: Severity
    title: str
    detail: str = ""
    file: str = ""
    scanner: str = ""
    tags: list[str] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity.name,
            "title": self.title,
            "detail": self.detail,
            "file": self.file,
            "scanner": self.scanner,
            "tags": self.tags,
            "evidence": self.evidence,
        }


@dataclass
class FileResult:
    """Per-file scan outcome."""

    path: str
    format: str
    size: int
    sha256: str
    findings: list[Finding] = field(default_factory=list)
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "format": self.format,
            "size": self.size,
            "sha256": self.sha256,
            "findings": [f.to_dict() for f in self.findings],
            "error": self.error,
        }


@dataclass
class ScanReport:
    """Aggregate report for one scan target (file, directory, or remote repo)."""

    target: str
    files: list[FileResult] = field(default_factory=list)
    policy_findings: list[Finding] = field(default_factory=list)
    signature_findings: list[Finding] = field(default_factory=list)
    deep_findings: list[Finding] = field(default_factory=list)
    verdict: Verdict = Verdict.PASS
    policy_name: str = ""
    origin: str | None = None
    publisher: str | None = None
    provenance_verified: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)
    started_at: str = ""
    duration_seconds: float = 0.0

    @property
    def all_findings(self) -> list[Finding]:
        out = list(self.policy_findings) + list(self.signature_findings) + list(self.deep_findings)
        for fr in self.files:
            out.extend(fr.findings)
        return out

    @property
    def max_severity(self) -> Severity | None:
        findings = self.all_findings
        if not findings:
            return None
        return max(f.severity for f in findings)

    def severity_counts(self) -> dict[str, int]:
        counts = {s.name: 0 for s in Severity}
        for f in self.all_findings:
            counts[f.severity.name] += 1
        return counts

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "verdict": self.verdict.value,
            "policy": self.policy_name,
            "origin": self.origin,
            "publisher": self.publisher,
            "provenance_verified": self.provenance_verified,
            "severity_counts": self.severity_counts(),
            "policy_findings": [f.to_dict() for f in self.policy_findings],
            "signature_findings": [f.to_dict() for f in self.signature_findings],
            "deep_findings": [f.to_dict() for f in self.deep_findings],
            "files": [fr.to_dict() for fr in self.files],
            "metadata": self.metadata,
            "started_at": self.started_at,
            "duration_seconds": round(self.duration_seconds, 3),
        }
