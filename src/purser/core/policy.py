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
    denylist:                   # known-bad IOCs, refreshable like AV signatures
      hashes: ["sha256:<hex>"]  # content digests — always BLOCKED on match
      publishers: ["evil-*"]    # publisher globs
      models: ["*/nullif-ai*"]  # repo/name globs
      files: [/feeds/bad.txt]   # external hash feeds, re-read every evaluation
    max_file_size_mb: 20000
    rules:
      - id: PICKLE_UNKNOWN_IMPORT
        action: warn            # deny | warn | ignore
"""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from purser.core.findings import Finding, ScanReport, Severity, Verdict

_HEX64 = re.compile(r"(?:sha256:)?([a-fA-F0-9]{64})")


class PolicyError(ValueError):
    """Raised for invalid policy documents."""


def _id_match(value: str | None, patterns: list[str]) -> bool:
    """True if a Sigstore issuer/SAN matches any pattern (exact or fnmatch glob)."""
    if not value or not patterns:
        return False
    return any(value == p or fnmatch.fnmatch(value, p) for p in patterns)


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
    identity_mode: str = "off"           # off | allowlist | blocklist (Sigstore identity)
    identity_issuers: list[str] = field(default_factory=list)   # OIDC issuers (globs ok)
    identity_patterns: list[str] = field(default_factory=list)  # SAN globs
    models_mode: str = "off"             # off | allowlist | blocklist
    models_patterns: list[str] = field(default_factory=list)
    denylist_hashes: set[str] = field(default_factory=set)      # SHA-256 hex
    denylist_publishers: list[str] = field(default_factory=list)  # globs
    denylist_models: list[str] = field(default_factory=list)      # repo/name globs
    denylist_files: list[str] = field(default_factory=list)       # external hash feeds
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

        identity = doc.get("identity") or {}
        p.identity_mode = _mode(identity.get("mode", "off"))
        if p.identity_mode not in ("off", "allowlist", "blocklist"):
            raise PolicyError(f"identity.mode must be off|allowlist|blocklist, got {p.identity_mode}")
        p.identity_issuers = [str(x) for x in identity.get("issuers", [])]
        p.identity_patterns = [str(x) for x in identity.get("identities", [])]
        if p.identity_mode != "off" and not (p.identity_issuers or p.identity_patterns):
            raise PolicyError(
                "identity.issuers or identity.identities must be non-empty when identity.mode is set")

        models = doc.get("models") or {}
        p.models_mode = _mode(models.get("mode", "off"))
        if p.models_mode not in ("off", "allowlist", "blocklist"):
            raise PolicyError(f"models.mode must be off|allowlist|blocklist, got {p.models_mode}")
        p.models_patterns = [str(x).lower() for x in models.get("patterns", [])]
        if p.models_mode != "off" and not p.models_patterns:
            raise PolicyError("models.patterns must be non-empty when models.mode is set")

        denylist = doc.get("denylist") or {}
        for h in denylist.get("hashes", []) or []:
            m = _HEX64.search(str(h))
            if not m:
                raise PolicyError(f"denylist.hashes entry is not a SHA-256: {h!r}")
            p.denylist_hashes.add(m.group(1).lower())
        p.denylist_publishers = [str(x).lower() for x in denylist.get("publishers", []) or []]
        p.denylist_models = [str(x).lower() for x in denylist.get("models", []) or []]
        p.denylist_files = [str(x) for x in denylist.get("files", []) or []]

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

        # -- verified-identity restrictions (Sigstore external root)
        # Applies only to a model that carries a *verified* signer identity;
        # whether an identity must be present at all is governed by
        # `require_signed`. allowlist => issuer AND SAN must match; blocklist =>
        # issuer OR SAN match is denied.
        if self.identity_mode != "off":
            ident = report.metadata.get("identity")
            issuer = report.metadata.get("identity_issuer")
            if ident is not None or issuer is not None:
                if self.identity_mode == "allowlist":
                    permitted = (
                        (not self.identity_issuers or _id_match(issuer, self.identity_issuers))
                        and (not self.identity_patterns or _id_match(ident, self.identity_patterns))
                    )
                else:  # blocklist
                    permitted = not (
                        _id_match(issuer, self.identity_issuers)
                        or _id_match(ident, self.identity_patterns)
                    )
                if not permitted:
                    blocked = True
                    policy_findings.append(self._pf(
                        "POLICY_IDENTITY_BLOCKED", Severity.HIGH,
                        f"Verified signer identity is not permitted by policy `{self.name}`",
                        f"issuer: {issuer or '—'} · identity: {ident or '—'}",
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

        # -- known-bad denylist (content hashes + publisher/model globs).
        # The AV-signature analogue: refreshable offline via `denylist.files`
        # (re-read at evaluate time, so dropping an updated feed file — e.g. a
        # remounted ConfigMap — takes effect without a policy reload).
        bad_hashes = self._denylist_hashes()
        if bad_hashes:
            for fr in report.files:
                if fr.sha256 and fr.sha256.lower() in bad_hashes:
                    blocked = True
                    policy_findings.append(self._pf(
                        "POLICY_DENYLIST_HASH", Severity.CRITICAL,
                        "File content is on the known-bad denylist",
                        f"file: {fr.path} sha256:{fr.sha256.lower()}",
                    ))
        if self.denylist_publishers and publisher:
            matched = sorted(p for p in self.denylist_publishers
                             if fnmatch.fnmatch(publisher, p))
            if matched:
                blocked = True
                policy_findings.append(self._pf(
                    "POLICY_DENYLIST_PUBLISHER", Severity.CRITICAL,
                    f"Publisher `{publisher}` is on the known-bad denylist",
                    f"matched pattern(s): {matched}",
                ))
        if self.denylist_models:
            names = _model_names(report)
            matched = sorted(p for p in self.denylist_models
                             if any(fnmatch.fnmatch(n, p) for n in names))
            if matched:
                blocked = True
                policy_findings.append(self._pf(
                    "POLICY_DENYLIST_MODEL", Severity.CRITICAL,
                    "Model name/repo is on the known-bad denylist",
                    f"matched pattern(s): {matched}; names checked: {sorted(names)}",
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
        report.signal_findings = apply_overrides(report.signal_findings)

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

    def _denylist_hashes(self) -> set[str]:
        """Inline hashes + external feed files (re-read per evaluation).

        Feed files use the same line format as the admission approved list
        (bare hex or ``sha256:<hex>``; ``#`` comments). An unreadable feed is
        skipped — the inline entries still apply.
        """
        out = set(self.denylist_hashes)
        for path in self.denylist_files:
            try:
                text = Path(path).read_text()
            except OSError:
                continue
            for line in text.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                m = _HEX64.search(line)
                if m:
                    out.add(m.group(1).lower())
        return out

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
            "identity": {
                "mode": self.identity_mode,
                "issuers": self.identity_issuers,
                "identities": self.identity_patterns,
            },
            "models": {
                "mode": self.models_mode,
                "patterns": self.models_patterns,
            },
            "denylist": {
                "hashes": sorted(self.denylist_hashes),
                "publishers": self.denylist_publishers,
                "models": self.denylist_models,
                "files": self.denylist_files,
            },
            "max_file_size_mb": self.max_file_size_mb,
            "rules": [{"id": k, "action": v} for k, v in self.rule_overrides.items()],
        }
