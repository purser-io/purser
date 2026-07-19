"""User-defined policy engine.

Policies are YAML documents controlling:
  * fail thresholds (which finding severity fails a scan)
  * allowed/blocked model formats ("model types")
  * allowed/blocked countries of origin (ISO 3166-1 alpha-2)
  * allowed/blocked publishers (e.g. HuggingFace orgs)
  * allowed/blocked model names (glob patterns on repo id / name)
  * per-rule overrides (deny / warn / ignore)
  * size limits

Example:

    version: 1
    name: corporate-default
    fail_on:
      severity: HIGH
    formats:
      mode: blocklist           # blocklist | allowlist | off
      list: [pickle, joblib]
    origin:
      mode: blocklist           # blocklist | allowlist | off
      countries: [CN, RU, KP, IR]
      unknown_origin: warn      # allow | warn | deny
    publishers:
      blocked: [some-org]
      allowed: []
    models:
      mode: blocklist           # blocklist | allowlist | off
      patterns:                 # glob, case-insensitive; matched against the
        - "evilcorp/*"          #   repo id (full + last component) and the
        - "*-backdoor"          #   scan target's basename
        - "known-cve-model"
    max_file_size_mb: 20000
    rules:
      - id: PICKLE_UNKNOWN_IMPORT
        action: warn            # deny | warn | ignore
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from purser.core.findings import Finding, ScanReport, Severity, Verdict


class PolicyError(ValueError):
    """Raised for invalid policy documents."""


def _model_names(report: ScanReport) -> set[str]:
    """Lowercased identifiers a model-name policy matches against: the repo id
    (full and last component) and the scan target's basename."""
    names: set[str] = set()
    repo_id = str(report.metadata.get("repo_id") or "")
    if repo_id:
        names.add(repo_id.lower())
        names.add(repo_id.rsplit("/", 1)[-1].lower())
    target = report.target or ""
    if target.startswith("hf://"):
        target = target[len("hf://"):]
        names.add(target.lower())
        names.add(target.rsplit("/", 1)[-1].lower())
    if target:
        names.add(Path(target).name.lower())
    return {n for n in names if n}


@dataclass
class RuleOverride:
    rule_id: str
    action: str  # deny | warn | ignore


@dataclass
class Policy:
    name: str = "default"
    fail_on_severity: Severity = Severity.HIGH
    formats_mode: str = "off"            # off | allowlist | blocklist
    formats_list: list[str] = field(default_factory=list)
    origin_mode: str = "off"             # off | allowlist | blocklist
    origin_countries: list[str] = field(default_factory=list)
    unknown_origin: str = "warn"         # allow | warn | deny
    require_signed: bool = False         # require cryptographically verified provenance
    publishers_blocked: list[str] = field(default_factory=list)
    publishers_allowed: list[str] = field(default_factory=list)
    models_mode: str = "off"             # off | allowlist | blocklist
    models_patterns: list[str] = field(default_factory=list)
    max_file_size_mb: int = 0            # 0 = unlimited
    rule_overrides: dict[str, str] = field(default_factory=dict)
    raw: dict[str, Any] = field(default_factory=dict)

    # ------------------------------------------------------------------ load
    @classmethod
    def load(cls, path: Path | str) -> "Policy":
        with open(path) as fh:
            doc = yaml.safe_load(fh) or {}
        return cls.from_dict(doc)

    @classmethod
    def from_dict(cls, doc: dict[str, Any]) -> "Policy":
        if not isinstance(doc, dict):
            raise PolicyError("policy document must be a mapping")
        p = cls(raw=doc)
        p.name = str(doc.get("name", "default"))

        fail_on = doc.get("fail_on") or {}
        try:
            p.fail_on_severity = Severity.parse(fail_on.get("severity", "HIGH"))
        except KeyError as exc:
            raise PolicyError(f"invalid fail_on.severity: {exc}") from exc

        def _mode(value: Any) -> str:
            # YAML parses a bare `off` as boolean False — normalize it back.
            if value is False:
                return "off"
            return str(value).lower()

        formats = doc.get("formats") or {}
        p.formats_mode = _mode(formats.get("mode", "off"))
        if p.formats_mode not in ("off", "allowlist", "blocklist"):
            raise PolicyError(f"formats.mode must be off|allowlist|blocklist, got {p.formats_mode}")
        p.formats_list = [str(f).lower() for f in formats.get("list", [])]

        origin = doc.get("origin") or {}
        p.origin_mode = _mode(origin.get("mode", "off"))
        if p.origin_mode not in ("off", "allowlist", "blocklist"):
            raise PolicyError(f"origin.mode must be off|allowlist|blocklist, got {p.origin_mode}")
        p.origin_countries = [str(c).upper() for c in origin.get("countries", [])]
        p.unknown_origin = str(origin.get("unknown_origin", "warn")).lower()
        if p.unknown_origin not in ("allow", "warn", "deny"):
            raise PolicyError("origin.unknown_origin must be allow|warn|deny")
        p.require_signed = bool(origin.get("require_signed", False))

        publishers = doc.get("publishers") or {}
        p.publishers_blocked = [str(x).lower() for x in publishers.get("blocked", [])]
        p.publishers_allowed = [str(x).lower() for x in publishers.get("allowed", [])]

        models = doc.get("models") or {}
        p.models_mode = _mode(models.get("mode", "off"))
        if p.models_mode not in ("off", "allowlist", "blocklist"):
            raise PolicyError(f"models.mode must be off|allowlist|blocklist, got {p.models_mode}")
        p.models_patterns = [str(x).lower() for x in models.get("patterns", [])]
        if p.models_mode != "off" and not p.models_patterns:
            raise PolicyError("models.patterns must be non-empty when models.mode is set")

        p.max_file_size_mb = int(doc.get("max_file_size_mb", 0))

        for rule in doc.get("rules", []) or []:
            rid = str(rule.get("id", "")).upper()
            action = str(rule.get("action", "warn")).lower()
            if not rid:
                raise PolicyError("rule override missing id")
            if action not in ("deny", "warn", "ignore"):
                raise PolicyError(f"rule {rid}: action must be deny|warn|ignore")
            p.rule_overrides[rid] = action
        return p

    @classmethod
    def default(cls) -> "Policy":
        return cls()

    # -------------------------------------------------------------- evaluate
    def evaluate(self, report: ScanReport) -> ScanReport:
        """Apply this policy to a report: add policy findings, set verdict."""
        policy_findings: list[Finding] = []
        blocked = False

        # -- signed-provenance requirement
        # When set, only a cryptographically verified origin/publisher is
        # trusted; a self-asserted flag or sidecar does not satisfy it. This is
        # what makes country-of-origin a control rather than a label.
        if self.require_signed and not report.provenance_verified:
            blocked = True
            policy_findings.append(self._pf(
                "POLICY_SIGNATURE_REQUIRED", Severity.CRITICAL,
                "Policy requires cryptographically verified provenance, but the "
                "model is not validly signed by a trusted key",
                f"signature status: {report.metadata.get('signature_status', 'unknown')}",
            ))

        # -- origin restrictions
        origin = (report.origin or "").upper() or None
        if self.origin_mode != "off":
            if origin is None:
                if self.unknown_origin == "deny":
                    blocked = True
                    policy_findings.append(self._pf(
                        "POLICY_ORIGIN_UNKNOWN", Severity.HIGH,
                        "Model origin could not be determined and policy denies unknown origins",
                    ))
                elif self.unknown_origin == "warn":
                    policy_findings.append(self._pf(
                        "POLICY_ORIGIN_UNKNOWN", Severity.MEDIUM,
                        "Model origin could not be determined",
                        "Provide --origin or a provenance file, or map the "
                        "publisher in the origin database.",
                    ))
            else:
                in_list = origin in self.origin_countries
                if (self.origin_mode == "blocklist" and in_list) or (
                    self.origin_mode == "allowlist" and not in_list
                ):
                    blocked = True
                    policy_findings.append(self._pf(
                        "POLICY_ORIGIN_BLOCKED", Severity.CRITICAL,
                        f"Model origin `{origin}` is not permitted by policy `{self.name}`",
                        f"origin.mode={self.origin_mode}, countries={self.origin_countries}",
                    ))

        # -- publisher restrictions
        publisher = (report.publisher or "").lower() or None
        if publisher:
            if publisher in self.publishers_blocked:
                blocked = True
                policy_findings.append(self._pf(
                    "POLICY_PUBLISHER_BLOCKED", Severity.CRITICAL,
                    f"Publisher `{publisher}` is blocked by policy `{self.name}`",
                ))
            elif self.publishers_allowed and publisher not in self.publishers_allowed:
                blocked = True
                policy_findings.append(self._pf(
                    "POLICY_PUBLISHER_NOT_ALLOWED", Severity.CRITICAL,
                    f"Publisher `{publisher}` is not on the policy allowlist",
                ))

        # -- model-name restrictions (glob patterns against repo id / name)
        if self.models_mode != "off":
            names = _model_names(report)
            matched = sorted(
                p for p in self.models_patterns
                if any(fnmatch.fnmatch(n, p) for n in names)
            )
            if self.models_mode == "blocklist" and matched:
                blocked = True
                policy_findings.append(self._pf(
                    "POLICY_MODEL_BLOCKED", Severity.CRITICAL,
                    f"Model name is blocked by policy `{self.name}`",
                    f"matched pattern(s): {matched}; names checked: {sorted(names)}",
                ))
            elif self.models_mode == "allowlist" and not matched:
                blocked = True
                policy_findings.append(self._pf(
                    "POLICY_MODEL_NOT_ALLOWED", Severity.CRITICAL,
                    f"Model name is not on the allowlist for policy `{self.name}`",
                    f"names checked: {sorted(names)}",
                ))

        # -- format restrictions
        if self.formats_mode != "off":
            for fr in report.files:
                fmt = fr.format.lower()
                # Auxiliary files (unknown blobs, archives, bundled source, and
                # config) are judged by their findings, not format-allowlisted —
                # otherwise every repo's modeling.py would trip an allowlist.
                if fmt in ("unknown", "archive", "python_source", "hf_config"):
                    continue
                in_list = fmt in self.formats_list
                if (self.formats_mode == "blocklist" and in_list) or (
                    self.formats_mode == "allowlist" and not in_list
                ):
                    blocked = True
                    policy_findings.append(self._pf(
                        "POLICY_FORMAT_BLOCKED", Severity.CRITICAL,
                        f"Model format `{fmt}` is not permitted by policy `{self.name}`",
                        f"file: {fr.path}",
                    ))

        # -- size limits
        if self.max_file_size_mb > 0:
            limit = self.max_file_size_mb * 1024 * 1024
            for fr in report.files:
                if fr.size > limit:
                    policy_findings.append(self._pf(
                        "POLICY_FILE_TOO_LARGE", Severity.MEDIUM,
                        f"File exceeds policy size limit ({fr.size // (1024 * 1024)} MB "
                        f"> {self.max_file_size_mb} MB)",
                        f"file: {fr.path}",
                    ))

        # -- rule overrides on content findings (and signature findings)
        effective: list[Finding] = []

        def apply_overrides(findings: list[Finding]) -> list[Finding]:
            nonlocal blocked
            kept: list[Finding] = []
            for f in findings:
                action = self.rule_overrides.get(f.rule_id.upper())
                if action == "ignore":
                    continue
                if action == "warn" and f.severity >= self.fail_on_severity:
                    f = Finding(**{**f.__dict__, "severity": Severity.LOW})
                    f.tags = list(f.tags) + ["downgraded-by-policy"]
                elif action == "deny":
                    blocked = True
                kept.append(f)
                effective.append(f)
            return kept

        for fr in report.files:
            fr.findings = apply_overrides(fr.findings)
        report.signature_findings = apply_overrides(report.signature_findings)
        report.deep_findings = apply_overrides(report.deep_findings)

        report.policy_findings = policy_findings
        report.policy_name = self.name

        # -- verdict
        if blocked:
            report.verdict = Verdict.BLOCKED
        elif any(f.severity >= self.fail_on_severity for f in effective):
            report.verdict = Verdict.FAIL
        elif effective or policy_findings:
            report.verdict = Verdict.WARN
        else:
            report.verdict = Verdict.PASS
        return report

    def _pf(self, rule_id: str, severity: Severity, title: str, detail: str = "") -> Finding:
        return Finding(rule_id=rule_id, severity=severity, title=title,
                       detail=detail, scanner="policy")

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "fail_on": {"severity": self.fail_on_severity.name},
            "formats": {"mode": self.formats_mode, "list": self.formats_list},
            "origin": {
                "mode": self.origin_mode,
                "countries": self.origin_countries,
                "unknown_origin": self.unknown_origin,
                "require_signed": self.require_signed,
            },
            "publishers": {
                "blocked": self.publishers_blocked,
                "allowed": self.publishers_allowed,
            },
            "models": {
                "mode": self.models_mode,
                "patterns": self.models_patterns,
            },
            "max_file_size_mb": self.max_file_size_mb,
            "rules": [{"id": k, "action": v} for k, v in self.rule_overrides.items()],
        }
