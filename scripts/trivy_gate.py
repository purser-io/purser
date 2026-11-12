#!/usr/bin/env python3
"""Decide what a Trivy image scan means for the thing that triggered it.

A fixable HIGH/CRITICAL finding appears in an image for one of two reasons:

  * the change under test put it there (a new dependency, an older pin), or
  * the world moved — upstream published a fix for something the pinned base
    image, apk packages or lockfile already contained.

The second kind is unrelated to the change, yet a plain `exit-code: 1` gate
fails on both, so every PR opened between "fix published" and "pins refreshed"
goes red for a reason its author cannot act on. This script separates them:

    report        strict — exit 1 on any finding. For the questions "is main
                  clean today?" (the scheduled refresh) and "may this ship?".
    diff          exit 1 only for findings the head image has and the base
                  image does not. For "did this change make it worse?" (CI).
    lock-upgrades print the Python packages whose findings a lockfile bump
                  would fix, for `make lock LOCK_UPGRADE="..."`.

Inputs are `trivy image --format json` reports. A report that does not exist
means the image was never scanned (it failed to build), which is never clean.

Usage:
    python scripts/trivy_gate.py report trivy/*.json
    python scripts/trivy_gate.py diff --base base.json --head head.json
    python scripts/trivy_gate.py lock-upgrades trivy/*.json
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path

# Trivy's `Type` for packages found via installed Python metadata.
PYTHON_TYPES = {"python-pkg", "pip", "poetry", "uv"}

# A name is passed on to `uv pip compile -P`; anything that is not a plain
# distribution name is dropped rather than quoted.
_SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


@dataclass(frozen=True)
class Finding:
    pkg: str
    vuln: str
    severity: str
    installed: str
    fixed: str
    kind: str

    @property
    def key(self) -> tuple[str, str]:
        """Identity across two scans: the same advisory against the same
        package is the same finding, whichever version happens to be installed."""
        return (self.pkg, self.vuln)

    def line(self) -> str:
        return (
            f"{self.severity:<8} {self.pkg} {self.installed} -> {self.fixed}  "
            f"{self.vuln} ({self.kind})"
        )


def load(path: Path) -> list[Finding]:
    """Every finding in one Trivy JSON report, de-duplicated by key."""
    data = json.loads(path.read_text())
    seen: dict[tuple[str, str], Finding] = {}
    for result in data.get("Results") or []:
        for vuln in result.get("Vulnerabilities") or []:
            finding = Finding(
                pkg=vuln.get("PkgName", "?"),
                vuln=vuln.get("VulnerabilityID", "?"),
                severity=vuln.get("Severity", "UNKNOWN"),
                installed=vuln.get("InstalledVersion", "?"),
                fixed=vuln.get("FixedVersion", "") or "?",
                kind=result.get("Type", "?"),
            )
            seen.setdefault(finding.key, finding)
    return sorted(seen.values(), key=lambda f: (f.kind, f.pkg, f.vuln))


def new_findings(base: list[Finding], head: list[Finding]) -> list[Finding]:
    """Findings in `head` that `base` does not already have."""
    known = {f.key for f in base}
    return [f for f in head if f.key not in known]


def lock_upgrades(findings: list[Finding]) -> list[str]:
    """Python distributions with a fixable finding, normalized and de-duplicated."""
    names = {
        re.sub(r"[-_.]+", "-", f.pkg).lower()
        for f in findings
        if f.kind in PYTHON_TYPES and _SAFE_NAME.match(f.pkg)
    }
    return sorted(names)


def _annotate(level: str, message: str) -> None:
    """A GitHub Actions annotation when running there, a plain line otherwise."""
    if os.environ.get("GITHUB_ACTIONS") == "true":
        print(f"::{level}::{message}")
    else:
        print(f"{level}: {message}", file=sys.stderr)


def cmd_report(args: argparse.Namespace) -> int:
    dirty = False
    for raw in args.reports:
        path = Path(raw)
        if not path.exists():
            print(f"{path.stem}: NOT SCANNED (no report — the image did not build)")
            dirty = True
            continue
        findings = load(path)
        if not findings:
            print(f"{path.stem}: clean")
            continue
        dirty = True
        print(f"{path.stem}: {len(findings)} fixable HIGH/CRITICAL")
        for finding in findings:
            print(f"  {finding.line()}")
    return 1 if dirty else 0


def cmd_diff(args: argparse.Namespace) -> int:
    head_path = Path(args.head)
    if not head_path.exists():
        print(f"no head report at {head_path}: the image was never scanned")
        return 1
    head = load(head_path)
    if not head:
        print("clean: no fixable HIGH/CRITICAL findings")
        return 0

    base_path = Path(args.base)
    if not base_path.exists():
        # No baseline to excuse anything against, so nothing is excused.
        print(f"no base report at {base_path}; treating every finding as new")
        base: list[Finding] = []
    else:
        base = load(base_path)

    fresh = new_findings(base, head)
    inherited = [f for f in head if f not in fresh]

    if inherited:
        print(f"{len(inherited)} finding(s) already present on the base — not caused by this change:")
        for finding in inherited:
            print(f"  {finding.line()}")
        _annotate(
            "warning",
            f"{args.name}: {len(inherited)} fixable HIGH/CRITICAL finding(s) inherited "
            "from the base branch. The scheduled Wolfi refresh fixes these; "
            "this change did not introduce them.",
        )
    if fresh:
        print(f"{len(fresh)} finding(s) introduced by this change:")
        for finding in fresh:
            print(f"  {finding.line()}")
        _annotate(
            "error",
            f"{args.name}: this change introduces {len(fresh)} fixable "
            "HIGH/CRITICAL finding(s): "
            + ", ".join(f"{f.pkg} {f.vuln}" for f in fresh),
        )
        return 1
    return 0


def cmd_lock_upgrades(args: argparse.Namespace) -> int:
    findings: list[Finding] = []
    for raw in args.reports:
        path = Path(raw)
        if path.exists():
            findings.extend(load(path))
    print(" ".join(lock_upgrades(findings)))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    sub = parser.add_subparsers(dest="command", required=True)

    report = sub.add_parser("report", help="exit 1 on any finding")
    report.add_argument("reports", nargs="+")
    report.set_defaults(func=cmd_report)

    diff = sub.add_parser("diff", help="exit 1 only on findings new in --head")
    diff.add_argument("--base", required=True)
    diff.add_argument("--head", required=True)
    diff.add_argument("--name", default="image", help="label for annotations")
    diff.set_defaults(func=cmd_diff)

    upgrades = sub.add_parser("lock-upgrades", help="python packages to bump")
    upgrades.add_argument("reports", nargs="+")
    upgrades.set_defaults(func=cmd_lock_upgrades)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
