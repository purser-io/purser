"""Loader-CVE mapping — known load-time RCEs as an offline signal source.

There is no feed of malicious *models*, but framework/parser CVEs are public:
a `.keras` archive that declares `keras_version: 3.9.0` — or an HF
`config.json` that declares `transformers_version` — is telling you which
loader family the publisher used, and those loaders have documented
load-time vulnerabilities. This source maps a **declared framework version**
to a vendored, model-scoped dataset (`purser/data/loader_cves.yaml`,
regenerated from OSV.dev by `make loader-cves` / the weekly refresh
workflow) and emits an advisory finding when the version falls in an
affected range.

Version channels (how an artifact declares a version):
  * ``keras_version``        — `.keras` v3 archive metadata, or the H5
                                attribute block (byte heuristic)
  * ``transformers_version`` — HF `config.json`

Honesty rules:
  * The CVE is in the **loader**, not the artifact — the finding says
    "environments loading this with <framework> <range> are exposed", it does
    not call the artifact malicious. Severity LOW, policy-escalatable.
  * Fires **only on a declared in-range version** — never as blanket
    per-format noise (an unversioned artifact produces nothing).
  * Fully **offline**: the dataset is vendored (override with
    ``PURSER_LOADER_CVES=/path/to/dataset.yaml`` to refresh without
    upgrading); this source runs on local scans too.
"""

from __future__ import annotations

import json
import re
import zipfile
from importlib import resources
from pathlib import Path

import yaml

from purser.core.env import env_get
from purser.core.findings import Finding, Severity
from purser.signals import SignalContext

_VERSION_RE = re.compile(r"(\d+(?:\.\d+)+)")
_H5_HEAD = 256 * 1024  # keras_version lives in the attribute block near the top

_KERAS_EXTS = {".keras", ".h5", ".hdf5"}
_MAX_JSON = 1024 * 1024


def _dataset() -> list[dict]:
    """Resolution order: PURSER_LOADER_CVES → user-updated file → vendored.

    The user file is written by `purser update-intel` (`core/intel.py`) so a
    pip/container user can refresh intel without upgrading Purser.
    """
    override = env_get("LOADER_CVES", "")
    try:
        if override:
            text = Path(override).read_text()
        else:
            from purser.core.intel import user_intel_path

            user = user_intel_path()
            if user.exists():
                text = user.read_text()
            else:
                text = (resources.files("purser.data") / "loader_cves.yaml").read_text()
        data = yaml.safe_load(text) or []
    except (OSError, yaml.YAMLError):
        return []
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


def _affected(version: str, spec: "str | list") -> bool:
    """`affected` may be one spec or a list of specs (any-of)."""
    specs = spec if isinstance(spec, list) else [spec]
    return any(_in_range(version, str(s)) for s in specs)


# --- version channels -----------------------------------------------------------

def _keras_version_from_zip(path: Path) -> str | None:
    """`keras_version` from a .keras v3 archive's metadata/config (no load)."""
    try:
        with zipfile.ZipFile(path) as zf:
            for member in ("metadata.json", "config.json"):
                if member in zf.namelist():
                    with zf.open(member) as fh:
                        doc = json.loads(fh.read(_MAX_JSON).decode(errors="replace"))
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


def _keras_channel(path: Path) -> str | None:
    if path.suffix.lower() == ".keras":
        return _keras_version_from_zip(path)
    if path.suffix.lower() in (".h5", ".hdf5"):
        return _keras_version_from_h5(path)
    return _keras_version_from_zip(path) or _keras_version_from_h5(path)


def _transformers_channel(path: Path) -> str | None:
    """`transformers_version` from an HF config.json."""
    if path.name.lower() != "config.json":
        return None
    try:
        if path.stat().st_size > _MAX_JSON:
            return None
        doc = json.loads(path.read_text(errors="replace"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(doc, dict):
        return None
    v = doc.get("transformers_version")
    if isinstance(v, str) and _VERSION_RE.search(v):
        return v
    return None


# channel name -> (file filter, version extractor)
_CHANNELS: dict = {
    "keras_version": (
        lambda p: p.suffix.lower() in _KERAS_EXTS,
        _keras_channel,
    ),
    "transformers_version": (
        lambda p: p.name.lower() == "config.json",
        _transformers_channel,
    ),
}


def _entry_channel(entry: dict) -> str:
    # older entries carried only `framework: keras`
    return str(entry.get("channel") or f"{entry.get('framework', '')}_version")


def _clear_at(matched: list[dict]) -> str:
    """The smallest version that clears every matched range: the max `<bound`."""
    best: tuple[int, ...] = ()
    best_str = ""
    for e in matched:
        spec = e.get("affected", "")
        for s in (spec if isinstance(spec, list) else [spec]):
            for part in str(s).split(","):
                part = part.strip()
                if part.startswith("<") and not part.startswith("<="):
                    bound = _vtuple(part[1:])
                    if bound > best:
                        best, best_str = bound, part[1:].strip()
    return best_str


class LoaderCVEsSource:
    """Advise when an artifact declares a framework version with load-time CVEs."""

    name = "loader-cves"

    def available(self, ctx: SignalContext) -> bool:
        return ctx.target is not None  # offline: applies to every scan

    def collect(self, ctx: SignalContext) -> list[Finding]:
        target = Path(ctx.target) if ctx.target else None
        if target is None:
            return []
        entries_by_channel: dict[str, list[dict]] = {}
        for e in _dataset():
            ch = _entry_channel(e)
            if ch in _CHANNELS:
                entries_by_channel.setdefault(ch, []).append(e)
        if not entries_by_channel:
            return []

        candidates = [target] if target.is_file() else [
            p for p in sorted(target.rglob("*")) if p.is_file()
        ]
        findings: list[Finding] = []
        for path in candidates:
            for channel, entries in entries_by_channel.items():
                file_filter, extractor = _CHANNELS[channel]
                if target.is_dir() and not file_filter(path):
                    continue
                version = extractor(path)
                if not version:
                    continue
                matched = [e for e in entries
                           if _affected(version, e.get("affected", ""))]
                if not matched:
                    continue
                # ONE aggregated finding per file+framework — an old artifact
                # can match many CVEs, and nine findings for one fact is noise.
                framework = str(matched[0].get("framework", ""))
                clear_at = _clear_at(matched)
                sample = "; ".join(
                    f"{e.get('cve')} ({str(e.get('summary', '')).strip()[:80]})"
                    for e in matched[:3])
                more = f" (+{len(matched) - 3} more)" if len(matched) > 3 else ""
                findings.append(Finding(
                    rule_id="LOADER_CVE",
                    severity=Severity.LOW,
                    title=f"Declared {framework} {version} matches "
                          f"{len(matched)} known load-time CVE"
                          f"{'s' if len(matched) != 1 else ''}",
                    detail=f"{sample}{more}. Loading this artifact with the "
                           f"declared {framework} version is exposed to known "
                           "load-time vulnerabilities; the artifact itself is "
                           "not thereby malicious."
                           + (f" A loader at {framework} >= {clear_at} clears "
                              "every matched range." if clear_at else ""),
                    file=str(path),
                    scanner=f"signals.{self.name}",
                    tags=["loader-cve", "advisory"],
                    evidence={"framework": framework,
                              "declared_version": version,
                              "clear_at": clear_at,
                              "cves": [{"cve": e.get("cve"),
                                        "affected": e.get("affected"),
                                        "reference": e.get("reference")}
                                       for e in matched]},
                ))
        return findings
