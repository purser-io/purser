"""Loader-CVE mapping — known load-time RCEs as an offline signal source.

There is no feed of malicious *models*, but framework/parser CVEs are public:
a `.keras` archive that declares `keras_version: 3.9.0` is telling you which
loader family the publisher used — and Keras < 3.11.3 has documented
`safe_mode` bypasses (CVE-2025-9906/-9905). This source maps a **detected
format + the framework version the artifact itself declares** to a curated,
vendored dataset of load-time CVEs (`purser/data/loader_cves.yaml`, sourced
from OSV/GHSA) and emits an advisory finding when the declared version falls
in an affected range.

Honesty rules:
  * The CVE is in the **loader**, not the artifact — the finding says
    "environments loading this with <framework> <range> are exposed", it does
    not call the artifact malicious. Severity LOW, policy-escalatable.
  * Fires **only on a declared in-range version** — never as blanket
    per-format noise (an unversioned artifact produces nothing).
  * Fully **offline**: the dataset is vendored; this source runs on local
    scans too (it is the first signal that does — network-using sources
    still gate themselves to hub scans).
"""

from __future__ import annotations

import json
import re
import zipfile
from importlib import resources
from pathlib import Path

import yaml

from purser.core.findings import Finding, Severity
from purser.signals import SignalContext

_VERSION_RE = re.compile(r"(\d+(?:\.\d+)+)")
_H5_HEAD = 256 * 1024  # keras_version lives in the attribute block near the top

_KERAS_EXTS = {".keras", ".h5", ".hdf5"}


def _dataset() -> list[dict]:
    text = (resources.files("purser.data") / "loader_cves.yaml").read_text()
    data = yaml.safe_load(text) or []
    return [e for e in data if isinstance(e, dict)]


def _vtuple(version: str) -> tuple[int, ...]:
    m = _VERSION_RE.search(version)
    if not m:
        return ()
    return tuple(int(x) for x in m.group(1).split("."))


def _in_range(version: str, spec: str) -> bool:
    """True when `version` satisfies every comma-separated comparator."""
    v = _vtuple(version)
    if not v:
        return False
    for part in spec.split(","):
        part = part.strip()
        m = re.match(r"(>=|<=|==|<|>)\s*([\d.]+)", part)
        if not m:
            return False
        op, bound = m.group(1), _vtuple(m.group(2))
        # compare on a common length so 3.11 vs 3.11.3 behaves numerically
        width = max(len(v), len(bound))
        a = v + (0,) * (width - len(v))
        b = bound + (0,) * (width - len(bound))
        ok = {"<": a < b, "<=": a <= b, ">": a > b, ">=": a >= b,
              "==": a == b}[op]
        if not ok:
            return False
    return True


def _keras_version_from_zip(path: Path) -> str | None:
    """`keras_version` from a .keras v3 archive's metadata/config (no load)."""
    try:
        with zipfile.ZipFile(path) as zf:
            for member in ("metadata.json", "config.json"):
                if member in zf.namelist():
                    with zf.open(member) as fh:
                        doc = json.loads(fh.read(1024 * 1024).decode(errors="replace"))
                    v = doc.get("keras_version")
                    if isinstance(v, str) and _VERSION_RE.search(v):
                        return v
    except (OSError, zipfile.BadZipFile, json.JSONDecodeError, KeyError):
        return None
    return None


def _keras_version_from_h5(path: Path) -> str | None:
    """Byte-level heuristic: the `keras_version` attribute near the H5 head."""
    try:
        with open(path, "rb") as fh:
            head = fh.read(_H5_HEAD)
    except OSError:
        return None
    idx = head.find(b"keras_version")
    if idx < 0:
        return None
    m = _VERSION_RE.search(head[idx:idx + 256].decode("latin1"))
    return m.group(1) if m else None


def _declared_keras_version(path: Path) -> str | None:
    if path.suffix.lower() == ".keras":
        return _keras_version_from_zip(path)
    if path.suffix.lower() in (".h5", ".hdf5"):
        return _keras_version_from_h5(path)
    # a .keras archive renamed — try both cheaply
    return _keras_version_from_zip(path) or _keras_version_from_h5(path)


class LoaderCVEsSource:
    """Advise when an artifact declares a framework version with load-time RCEs."""

    name = "loader-cves"

    def available(self, ctx: SignalContext) -> bool:
        return ctx.target is not None  # offline: applies to every scan

    def collect(self, ctx: SignalContext) -> list[Finding]:
        target = Path(ctx.target) if ctx.target else None
        if target is None:
            return []
        files = [target] if target.is_file() else [
            p for p in sorted(target.rglob("*"))
            if p.is_file() and p.suffix.lower() in _KERAS_EXTS
        ]
        entries = [e for e in _dataset() if e.get("framework") == "keras"]
        findings: list[Finding] = []
        for path in files:
            if path.suffix.lower() not in _KERAS_EXTS and target.is_dir():
                continue
            version = _declared_keras_version(path)
            if not version:
                continue
            for e in entries:
                if not _in_range(version, str(e.get("affected", ""))):
                    continue
                cve = str(e.get("cve", ""))
                findings.append(Finding(
                    rule_id="LOADER_CVE",
                    severity=Severity.LOW,
                    title=f"Declared {e['framework']} {version} is in the "
                          f"affected range of {cve}",
                    detail=f"{e.get('summary', '').strip()} Environments "
                           f"loading this artifact with {e['framework']} "
                           f"{e.get('affected')} are exposed; the artifact "
                           "itself is not thereby malicious. "
                           f"Ref: {e.get('reference', '')}",
                    file=str(path),
                    scanner=f"signals.{self.name}",
                    tags=["loader-cve", "advisory"],
                    evidence={"cve": cve, "framework": e.get("framework"),
                              "declared_version": version,
                              "affected": e.get("affected"),
                              "reference": e.get("reference")},
                ))
        return findings
