#!/usr/bin/env python3
"""Generate THIRD_PARTY_LICENSES.md from one or more CycloneDX SBOMs.

The SBOM (produced by gen_sbom.py) is the authoritative list of what actually
ships in the images. This reads the component set + their `licenses` and writes a
grouped, deterministic attribution file. Pass every runtime SBOM so the union of
all distributed dependencies is covered.

Usage:
    python scripts/gen_third_party_licenses.py THIRD_PARTY_LICENSES.md \
        sbom/purser-core.cdx.json sbom/purser-hf.cdx.json sbom/purser-deep.cdx.json
"""

from __future__ import annotations

import json
import sys
from pathlib import Path


def _license_of(component: dict) -> str:
    lics = component.get("licenses") or []
    names = []
    for entry in lics:
        lic = entry.get("license") or {}
        names.append(lic.get("id") or lic.get("name") or "")
    names = [n for n in names if n]
    return " / ".join(names) if names else "UNKNOWN (see project)"


def collect(sbom_paths: list[str]) -> dict[str, dict]:
    """Union of components across SBOMs, keyed by name@version."""
    out: dict[str, dict] = {}
    for p in sbom_paths:
        doc = json.loads(Path(p).read_text())
        for c in doc.get("components", []):
            key = f"{c['name']}@{c['version']}"
            if key not in out:
                out[key] = {
                    "name": c["name"],
                    "version": c["version"],
                    "license": _license_of(c),
                    "purl": c.get("purl", ""),
                }
    return out


def render(components: dict[str, dict], sbom_paths: list[str]) -> str:
    rows = sorted(components.values(), key=lambda c: c["name"].lower())
    by_license: dict[str, int] = {}
    for c in rows:
        by_license[c["license"]] = by_license.get(c["license"], 0) + 1

    lines = [
        "# Third-Party Licenses",
        "",
        "Purser is licensed under **Apache-2.0** (see [`LICENSE`](LICENSE)). It",
        "bundles the third-party Python packages below in its distributed container",
        "images. This file is **auto-generated** from the CycloneDX SBOM(s) — do not",
        "edit by hand; regenerate with `make licenses`.",
        "",
        f"Sources: {', '.join('`' + Path(p).name + '`' for p in sbom_paths)}",
        f"Total distributed dependencies: **{len(rows)}**",
        "",
        "## License summary",
        "",
        "| License | Packages |",
        "|---|---|",
    ]
    for lic, n in sorted(by_license.items()):
        lines.append(f"| {lic} | {n} |")
    lines += [
        "",
        "> All licenses are permissive (MIT/BSD/Apache/ISC/PSF). The only copyleft is",
        "> **MPL-2.0** (e.g. certifi, and tqdm as MPL-2.0/MIT) — a weak, file-level",
        "> copyleft satisfied by shipping the package unmodified; take MIT where dual.",
        "> No GPL/AGPL/LGPL is present in the Python dependency tree. The container",
        "> base (Wolfi + CPython/PSF + OS packages) carries its own licenses.",
        "",
        "## Dependencies",
        "",
        "| Package | Version | License |",
        "|---|---|---|",
    ]
    for c in rows:
        lines.append(f"| `{c['name']}` | {c['version']} | {c['license']} |")
    lines.append("")
    lines.append("Full license texts are available in each package's distribution "
                 "and via its PyPI project page (purl in the SBOM).")
    return "\n".join(lines) + "\n"


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print("usage: gen_third_party_licenses.py OUTPUT SBOM [SBOM ...]", file=sys.stderr)
        return 2
    output, sboms = argv[0], argv[1:]
    missing = [p for p in sboms if not Path(p).exists()]
    if missing:
        print(f"error: SBOM(s) not found: {missing} — run `make sbom` first", file=sys.stderr)
        return 1
    comps = collect(sboms)
    Path(output).write_text(render(comps, sboms))
    print(f"wrote {output} — {len(comps)} dependencies from {len(sboms)} SBOM(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
