#!/usr/bin/env python3
"""Re-pin the Wolfi apk package versions in the Dockerfiles.

Pinning the base image by digest is *not* enough to make a build reproducible:
`apk add` resolves against the live Wolfi package repo at build time, so the
toolchain (python, pip, build-base) floats even while the digest stays fixed.
That is how a vulnerable pip once reached a "pinned" image — the buildx cache
was the only thing holding the old resolution, and a cache miss silently pulled
a newer one.

So every package the Dockerfiles install carries an explicit `name=version`
pin. This script resolves what the *current* base digest would install and
rewrites those pins to match. It is the apk analogue of `make base-digest`.

The pins are refreshed together with the digest by `wolfi-base-check.yml`, so
security updates still arrive weekly — they just arrive as a reviewable diff
instead of appearing mid-build.

Usage:
    python scripts/repin_apk.py                 # rewrite pins to match the digest
    python scripts/repin_apk.py --check         # exit 1 if any pin is stale
    python scripts/repin_apk.py --digest sha256:...   # resolve against a specific base
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

DOCKERFILES = ("Dockerfile", "Dockerfile.hf", "Dockerfile.deep")
BASE_REPO = "cgr.dev/chainguard/wolfi-base"

# A pinned package on its own continuation line, e.g. "      py3.14-pip=26.2.1-r0 \".
# Keeping one package per line is what makes this rewrite line-local and safe.
PIN_RE = re.compile(
    r"^(?P<indent>\s+)(?P<name>[a-z0-9][a-z0-9._+-]*)=(?P<version>[^\s\\]+)(?P<tail>\s*\\?)$"
)

DIGEST_RE = re.compile(r"sha256:[a-f0-9]{64}")

# Dumps "name=version" for every installed package. Parsing apk's own db avoids
# `apk info -v`, which prints descriptions rather than versions.
_DUMP_INSTALLED = (
    "awk -v RS='' -F'\\n' '{n=\"\";v=\"\";"
    'for(i=1;i<=NF;i++){if($i~/^P:/)n=substr($i,3);if($i~/^V:/)v=substr($i,3)}'
    ";if(n!=\"\")print n\"=\"v}' /lib/apk/db/installed"
)


def read_digest(root: Path) -> str:
    """The base digest currently pinned in Dockerfile."""
    text = (root / "Dockerfile").read_text()
    match = DIGEST_RE.search(text)
    if not match:
        sys.exit("error: no sha256 base digest found in Dockerfile")
    return match.group(0)


def pin_lines(lines: list[str]):
    """Yield (index, match) for pinned packages inside `RUN apk add` blocks only.

    Scoping to the block matters: a bare `name=value` regex also matches LABEL
    continuation lines such as `org.opencontainers.image.licenses="Apache-2.0"`.
    """
    in_block = False
    for i, line in enumerate(lines):
        stripped = line.rstrip("\n")
        if not in_block:
            if re.match(r"^\s*RUN\s+apk\s+add\b", stripped):
                in_block = True
        else:
            match = PIN_RE.match(stripped)
            if match:
                yield i, match
        if in_block and not stripped.rstrip().endswith("\\"):
            in_block = False


def pinned_packages(root: Path) -> dict[str, set[str]]:
    """Map package name -> the versions currently pinned across the Dockerfiles."""
    found: dict[str, set[str]] = {}
    for name in DOCKERFILES:
        lines = (root / name).read_text().splitlines()
        for _, match in pin_lines(lines):
            found.setdefault(match["name"], set()).add(match["version"])
    return found


def resolve_versions(digest: str, packages: list[str]) -> dict[str, str]:
    """Ask the base image what `apk add <packages>` resolves to today."""
    script = (
        f"apk add --no-cache {' '.join(packages)} >/dev/null 2>&1 || exit 1\n"
        f"{_DUMP_INSTALLED}\n"
    )
    proc = subprocess.run(
        [
            "docker", "run", "--rm", "--platform", "linux/amd64",
            "--entrypoint", "sh", f"{BASE_REPO}@{digest}", "-c", script,
        ],
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        sys.exit(f"error: could not resolve apk versions on {digest}\n{proc.stderr}")

    installed = dict(
        line.split("=", 1) for line in proc.stdout.splitlines() if "=" in line
    )
    missing = [p for p in packages if p not in installed]
    if missing:
        sys.exit(f"error: not installed on the base image: {', '.join(missing)}")
    return {p: installed[p] for p in packages}


def rewrite(root: Path, versions: dict[str, str]) -> list[tuple[str, str, str, str]]:
    """Rewrite pins in place. Returns (file, package, old, new) for each change."""
    changes: list[tuple[str, str, str, str]] = []
    for name in DOCKERFILES:
        path = root / name
        lines = path.read_text().splitlines(keepends=True)
        for i, match in pin_lines(lines):
            newest = versions.get(match["name"])
            if not newest or newest == match["version"]:
                continue
            changes.append((name, match["name"], match["version"], newest))
            rebuilt = f"{match['indent']}{match['name']}={newest}{match['tail']}"
            lines[i] = rebuilt + ("\n" if lines[i].endswith("\n") else "")
        path.write_text("".join(lines))
    return changes


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--digest", help="base digest to resolve against")
    parser.add_argument(
        "--check",
        action="store_true",
        help="report stale pins and exit 1 without writing",
    )
    parser.add_argument("--root", default=".", help="repository root")
    args = parser.parse_args()

    root = Path(args.root)
    digest = args.digest or read_digest(root)

    pins = pinned_packages(root)
    if not pins:
        sys.exit(
            "error: no `name=version` apk pins found — expected one package per "
            "line inside the `apk add` blocks"
        )

    # A package pinned to different versions in different Dockerfiles is a bug;
    # they all build on the same base.
    for pkg, seen in sorted(pins.items()):
        if len(seen) > 1:
            print(
                f"warning: {pkg} pinned inconsistently: {', '.join(sorted(seen))}",
                file=sys.stderr,
            )

    packages = sorted(pins)
    print(f"base:     {digest}")
    print(f"packages: {', '.join(packages)}")

    versions = resolve_versions(digest, packages)

    if args.check:
        stale = [
            (pkg, ver, versions[pkg])
            for pkg, seen in sorted(pins.items())
            for ver in sorted(seen)
            if ver != versions[pkg]
        ]
        if stale:
            print("\nstale apk pins:", file=sys.stderr)
            for pkg, old, new in stale:
                print(f"  {pkg}: {old} -> {new}", file=sys.stderr)
            print(
                "\nrun `make apk-pins` to refresh them.",
                file=sys.stderr,
            )
            return 1
        print("\napk pins are current.")
        return 0

    changes = rewrite(root, versions)
    if not changes:
        print("\napk pins already current — nothing to do.")
        return 0

    print()
    for fname, pkg, old, new in changes:
        print(f"{fname}: {pkg} {old} -> {new}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
