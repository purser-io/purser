#!/usr/bin/env python3
"""Generate a CycloneDX 1.5 SBOM from a hash-pinned uv/pip lockfile.

Deterministic by design — no timestamps or random serial numbers — so the SBOM
is reproducible from the lockfile and can be committed / diffed / attested.

Usage:
    python scripts/gen_sbom.py requirements.lock sbom/purser-core.cdx.json \
        --name purser --version 0.1.0
"""

from __future__ import annotations

import argparse
import importlib.metadata as _md
import json
import re
import sys
from pathlib import Path

PKG_RE = re.compile(r"^([A-Za-z0-9._-]+)==([^\s\\]+)")
HASH_RE = re.compile(r"--hash=sha256:([0-9a-f]{64})")


# Normalize the varied metadata spellings to SPDX identifiers so the same
# license doesn't appear under three names.
_SPDX = {
    "mit license": "MIT",
    "mit": "MIT",
    "mit no attribution license (mit-0)": "MIT-0",
    "apache software license": "Apache-2.0",
    "apache license 2.0": "Apache-2.0",
    "bsd license": "BSD-3-Clause",
    "isc license (iscl)": "ISC",
    "mozilla public license 2.0 (mpl 2.0)": "MPL-2.0",
    "the unlicense (unlicense)": "Unlicense",
    "python software foundation license": "PSF-2.0",
}


def _spdxify(value: str) -> str:
    """Map a single metadata license token to an SPDX-ish id (idempotent)."""
    return _SPDX.get(value.strip().lower(), value.strip())


def resolve_license(name: str) -> str | None:
    """Best-effort SPDX license for an installed distribution.

    Prefers the modern License-Expression (already SPDX), then license
    classifiers, then the free-text License field — normalizing each to SPDX.
    Returns None if the package isn't installed (SBOM generation stays usable
    offline; the enrichment is just skipped).
    """
    try:
        meta = _md.metadata(name)
    except _md.PackageNotFoundError:
        return None
    expr = meta.get("License-Expression")
    if expr:
        return expr.strip()  # already an SPDX expression
    classifiers = [c for c in meta.get_all("Classifier") or [] if c.startswith("License ::")]
    if classifiers:
        parts = sorted({_spdxify(c.split("::")[-1]) for c in classifiers})
        return " OR ".join(parts)
    lic = (meta.get("License") or "").strip()
    if lic and "\n" not in lic and len(lic) <= 60:
        return _spdxify(lic)
    return None


def parse_lock(text: str) -> list[dict]:
    """Return [{name, version, hashes:[...]}] parsed from a lockfile."""
    components: list[dict] = []
    current: dict | None = None
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("#") or not stripped:
            continue
        m = PKG_RE.match(stripped)
        if m:
            current = {"name": m.group(1).lower(), "version": m.group(2), "hashes": []}
            components.append(current)
        hm = HASH_RE.search(stripped)
        if hm and current is not None:
            current["hashes"].append(hm.group(1))
    return components


def build_sbom(components: list[dict], name: str, version: str) -> dict:
    comps = []
    for c in sorted(components, key=lambda x: x["name"]):
        entry = {
            "type": "library",
            "name": c["name"],
            "version": c["version"],
            "purl": f"pkg:pypi/{c['name']}@{c['version']}",
            "bom-ref": f"pkg:pypi/{c['name']}@{c['version']}",
        }
        if c["hashes"]:
            entry["hashes"] = [
                {"alg": "SHA-256", "content": h} for h in sorted(c["hashes"])
            ]
        lic = resolve_license(c["name"])
        if lic:
            entry["licenses"] = [{"license": {"name": lic}}]
        comps.append(entry)
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "name": name,
                "version": version,
                "purl": f"pkg:pypi/{name}@{version}",
                "bom-ref": f"pkg:pypi/{name}@{version}",
                "licenses": [{"license": {"id": "Apache-2.0"}}],
            }
        },
        "components": comps,
    }


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("lockfile")
    ap.add_argument("output")
    ap.add_argument("--name", default="purser")
    ap.add_argument("--version", default="0.1.0")
    args = ap.parse_args(argv)

    text = Path(args.lockfile).read_text()
    components = parse_lock(text)
    if not components:
        print(f"error: no packages parsed from {args.lockfile}", file=sys.stderr)
        return 1
    sbom = build_sbom(components, args.name, args.version)
    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(sbom, indent=2, sort_keys=False) + "\n")
    print(f"wrote {out} — {len(components)} components")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
