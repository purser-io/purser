#!/usr/bin/env python3
"""Refresh the vendored loader-CVE dataset from OSV.dev — model-scoped only.

Queries OSV for the *tracked loader packages* (the frameworks whose versions a
model artifact can declare), filters to vulnerabilities that apply **at model
load time** (deserialization / code-exec / path-traversal / resource-bomb CWEs
and load-time keywords — not the package's web UI, CLI, or ReDoS noise), maps
OSV affected ranges into the dataset's version-spec format, and regenerates
`src/purser/data/loader_cves.yaml`.

Human-in-the-loop by design: run via `make loader-cves` (or the weekly
`loader-cve-refresh.yml` workflow, which opens a PR on drift). Entries marked
`curated: true` in the existing dataset are preserved verbatim; everything
else is regenerated. Excluded vulns are listed on stderr with the reason so a
reviewer can spot filter mistakes.

Usage:
    python scripts/refresh_loader_cves.py [--dry-run] [--dataset PATH]
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.request
from datetime import date
from pathlib import Path

import yaml

OSV_API = "https://api.osv.dev/v1/query"
DATASET = Path(__file__).resolve().parents[1] / "src/purser/data/loader_cves.yaml"

# The tracked loader packages. A package earns a row here only when a model
# artifact DECLARES its version (the "channel") — otherwise a match can never
# fire and the entry would be dead weight.
PACKAGES: dict[str, dict] = {
    "keras": {
        "ecosystem": "PyPI",
        "channel": "keras_version",
        "formats": ["keras_v3", "keras_h5"],
    },
    "transformers": {
        "ecosystem": "PyPI",
        "channel": "transformers_version",
        "formats": ["hf_config"],
    },
}

# Load-time relevance filter. CWEs that describe what a malicious/crafted
# artifact can do to the LOADER; keywords back them up for records without
# CWE ids (e.g. PYSEC mirrors).
LOAD_CWES = {
    "CWE-502",  # deserialization of untrusted data
    "CWE-94",   # code injection
    "CWE-95",   # eval injection
    "CWE-96",   # static code injection
    "CWE-913",  # improper control of dynamically-managed code resources
    "CWE-22",   # path traversal (crafted archive writes/reads outside target)
    "CWE-73",   # external control of file name (load-time file disclosure)
    "CWE-918",  # SSRF triggered by loading a crafted artifact
    "CWE-770",  # resource exhaustion (shape bombs) at load
}
LOAD_KEYWORDS = (
    "load_model", "load a model", "loading a model", "model loading",
    "deserial", "safe_mode", "arbitrary code", "code execution",
    "crafted model", "malicious model", "crafted keras", "crafted archive",
    "from_pretrained", "trust_remote_code", "pickle",
    "path traversal", "directory traversal", "arbitrary file",
)
EXCLUDE_KEYWORDS = ("redos", "regular expression denial",)


def fetch_vulns(package: str, ecosystem: str) -> list[dict]:
    vulns: list[dict] = []
    page_token = None
    while True:
        body: dict = {"package": {"name": package, "ecosystem": ecosystem}}
        if page_token:
            body["page_token"] = page_token
        req = urllib.request.Request(
            OSV_API, data=json.dumps(body).encode(),
            headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode())
        vulns.extend(data.get("vulns") or [])
        page_token = data.get("next_page_token")
        if not page_token:
            return vulns


def text_of(vuln: dict) -> str:
    return f"{vuln.get('summary', '')} {vuln.get('details', '')}".lower()


def is_load_relevant(vuln: dict) -> tuple[bool, str]:
    """(relevant, reason). Model-scoped: does this bite when LOADING an artifact?"""
    text = text_of(vuln)
    for kw in EXCLUDE_KEYWORDS:
        if kw in text:
            return False, f"excluded keyword: {kw}"
    cwes = set((vuln.get("database_specific") or {}).get("cwe_ids") or [])
    hit_cwe = cwes & LOAD_CWES
    hit_kw = [k for k in LOAD_KEYWORDS if k in text]
    if hit_cwe:
        return True, f"cwe: {','.join(sorted(hit_cwe))}"
    if hit_kw:
        return True, f"keywords: {','.join(hit_kw[:3])}"
    return False, f"no load-time CWE/keyword (cwes={sorted(cwes) or '-'})"


def cve_of(vuln: dict) -> str:
    for alias in vuln.get("aliases") or []:
        if alias.startswith("CVE-"):
            return alias
    return vuln.get("id", "")


def specs_from_affected(vuln: dict, package: str) -> list[str]:
    """OSV affected ranges -> ['>=a,<b', ...] (any-of semantics)."""
    specs: list[str] = []
    for aff in vuln.get("affected") or []:
        pkg = (aff.get("package") or {}).get("name", "").lower()
        if pkg != package:
            continue
        for rng in aff.get("ranges") or []:
            if rng.get("type") not in ("ECOSYSTEM", "SEMVER"):
                continue
            intro, fixed = "0", None
            for ev in rng.get("events") or []:
                if "introduced" in ev:
                    intro = ev["introduced"]
                if "fixed" in ev:
                    fixed = ev["fixed"]
                    parts = []
                    if intro not in ("0", ""):
                        parts.append(f">={intro}")
                    parts.append(f"<{fixed}")
                    specs.append(",".join(parts))
                    intro, fixed = "0", None  # multiple windows per range
            if fixed is None and intro not in ("0", ""):
                specs.append(f">={intro}")  # introduced, not yet fixed
    # dedupe, keep order
    seen: set[str] = set()
    return [s for s in specs if not (s in seen or seen.add(s))]


def dedupe_by_cve(vulns: list[dict]) -> list[dict]:
    """One record per CVE; prefer GHSA (richer CWE metadata) over PYSEC."""
    best: dict[str, dict] = {}
    for v in vulns:
        key = cve_of(v)
        cur = best.get(key)
        if cur is None or (v.get("id", "").startswith("GHSA")
                           and not cur.get("id", "").startswith("GHSA")):
            best[key] = v
    return list(best.values())


def build_entries() -> tuple[list[dict], list[str]]:
    entries: list[dict] = []
    report: list[str] = []
    for package, cfg in PACKAGES.items():
        vulns = dedupe_by_cve(fetch_vulns(package, cfg["ecosystem"]))
        report.append(f"{package}: {len(vulns)} unique CVEs from OSV")
        for v in sorted(vulns, key=cve_of):
            relevant, reason = is_load_relevant(v)
            cve = cve_of(v)
            if not relevant:
                report.append(f"  - skip {cve}: {reason}")
                continue
            specs = specs_from_affected(v, package)
            if not specs:
                report.append(f"  - skip {cve}: no mappable affected range")
                continue
            summary = (v.get("summary") or v.get("details") or "").strip()
            entries.append({
                "cve": cve,
                "framework": package,
                "channel": cfg["channel"],
                "formats": list(cfg["formats"]),
                "affected": specs if len(specs) > 1 else specs[0],
                "summary": summary[:300],
                "reference": f"https://osv.dev/vulnerability/{v.get('id', cve)}",
                "source": f"osv ({reason})",
            })
            report.append(f"  + keep {cve}: {reason} · affected {specs}")
    return entries, report


HEADER = """\
# Curated loader-CVE dataset for the `loader-cves` signal source.
#
# Model-scoped by construction: entries exist only for packages whose version
# a model artifact can DECLARE (the `channel`), and only for vulnerabilities
# that bite at MODEL LOAD TIME (deserialization / code-exec / path-traversal /
# load-bomb CWEs). The signal fires only when a scanned artifact declares a
# version inside an affected range — never as blanket per-format noise.
#
# REFRESH: `make loader-cves` regenerates this file from OSV.dev (see
# scripts/refresh_loader_cves.py for the relevance filter); the weekly
# `loader-cve-refresh.yml` workflow opens a PR when it drifts. Entries with
# `curated: true` are preserved verbatim across refreshes. Operators can point
# PURSER_LOADER_CVES at their own copy without upgrading.
#
# Last refreshed: {today} (source: OSV.dev; human-reviewed via PR)
"""


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset", default=str(DATASET))
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()
    path = Path(args.dataset)

    curated: list[dict] = []
    if path.exists():
        for e in yaml.safe_load(path.read_text()) or []:
            if isinstance(e, dict) and e.get("curated"):
                curated.append(e)

    auto, report = build_entries()
    print("\n".join(report), file=sys.stderr)

    curated_cves = {e.get("cve") for e in curated}
    auto = [e for e in auto if e["cve"] not in curated_cves]
    merged = curated + auto
    merged.sort(key=lambda e: (e.get("framework", ""), e.get("cve", "")))

    text = HEADER.format(today=date.today().isoformat()) + "\n" + yaml.safe_dump(
        merged, sort_keys=False, allow_unicode=True, width=78)
    if args.dry_run:
        print(text)
        return 0
    path.write_text(text)
    print(f"\nwrote {len(merged)} entries ({len(curated)} curated preserved) "
          f"-> {path}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
