"""Head-to-head comparison of Purser vs peer OSS model scanners (roadmap #1,
Phase 2).

Runs each available scanner over the same inert known-answer corpus (`kat.py`)
and reports, per tool: how many malicious samples it **detected**, how many it
**missed** (scanned but flagged nothing), how many it **did not attempt** (a
format it can't parse), and its **false positives** on the synthetic-benign set.
Purser is always measured; peer tools are best-effort — a tool that isn't
installed is simply omitted, so the harness runs offline and in CI alike.

    pip install picklescan modelscan fickling modelaudit   # the peers
    python benchmarks/compare.py                            # -> results/comparison.md

Adapters shell out to each tool's CLI and interpret its native verdict (exit
code + structured output), calibrated against each tool's real behavior. Recall
is computed only over samples a tool actually attempts, so pickle-only scanners
aren't scored as "missing" a format they never claim to read. Exact numbers
depend on the installed peer versions; the point is a reproducible, fair table.
"""
from __future__ import annotations

import json
import re
import shutil
import os

import subprocess
import tempfile
from pathlib import Path

import kat
from purser.core.policy import Policy
from purser.core.scanner import scan_target

HERE = Path(__file__).parent
WORK = HERE / "work"
RESULTS = HERE / "results"

# Peers are invoked with absolute sample paths, so run them from a scratch dir —
# some (e.g. fickling) drop a `safety_results.json` in the working directory.
_SCRATCH = tempfile.mkdtemp(prefix="purser-compare-")

# A tool's verdict on one sample.
FLAG = "flag"      # tool flagged it as dangerous
CLEAN = "clean"    # tool scanned it and found nothing
NA = "n/a"         # tool cannot parse this format — excluded from its rates

TIMEOUT = 120
_REAL_SEV = {"critical", "high", "medium", "warning", "error"}


def _run(cmd: list[str]) -> tuple[int, str]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=TIMEOUT,
                           cwd=_SCRATCH)
        return p.returncode, (p.stdout + p.stderr)
    except (subprocess.TimeoutExpired, OSError) as e:
        return -1, str(e)


def _extract_json(out: str) -> dict | None:
    try:
        return json.loads(out[out.index("{"):out.rindex("}") + 1])
    except (ValueError, json.JSONDecodeError):
        return None


# --- adapters: each returns FLAG / CLEAN / NA for one path -------------------

def _purser(path: str, policy: Policy) -> str:
    r = scan_target(path, policy=policy)
    ms = r.max_severity
    return FLAG if (ms and ms.name in ("MEDIUM", "HIGH", "CRITICAL")) else CLEAN


def _picklescan(path: str) -> str:
    # Prints "Dangerous globals: N" / "Infected files: N"; rc=1 when infected.
    rc, out = _run(["picklescan", "--path", path])
    d = re.search(r"Dangerous globals:\s*(\d+)", out)
    inf = re.search(r"Infected files:\s*(\d+)", out)
    if d is None and inf is None:
        return NA  # no summary emitted -> could not process
    danger = int(d.group(1)) if d else 0
    infected = int(inf.group(1)) if inf else 0
    return FLAG if (rc == 1 or danger or infected) else CLEAN


def _fickling(path: str) -> str:
    # Pickle-only. rc=2 / "No pickle files detected" => not a pickle => n/a.
    rc, out = _run(["fickling", "--check-safety", path])
    low = out.lower()
    if rc == 2 or "no pickle" in low or "failed to parse" in low:
        return NA
    return FLAG if rc != 0 else CLEAN


def _modelscan(path: str) -> str:
    rc, out = _run(["modelscan", "--path", path, "-r", "json"])
    doc = _extract_json(out)
    if not doc:
        return NA
    summary = doc.get("summary", {})
    scanned = (summary.get("scanned") or {}).get("total_scanned")
    if not scanned:  # nothing scanned -> format unsupported / errored
        return NA
    return FLAG if summary.get("total_issues") else CLEAN


def _modelaudit(path: str) -> str:
    rc, out = _run(["modelaudit", "scan", path, "--format", "json"])
    doc = _extract_json(out)
    if doc is None:
        return NA
    issues = doc.get("issues")
    if not isinstance(issues, list):
        return NA
    real = [i for i in issues if str(i.get("severity", "")).lower() in _REAL_SEV]
    return FLAG if real else CLEAN


PEERS = {  # display name -> (cli binary, adapter)
    "picklescan": ("picklescan", _picklescan),
    "ModelScan": ("modelscan", _modelscan),
    "Fickling": ("fickling", _fickling),
    "ModelAudit": ("modelaudit", _modelaudit),
}


def _row(name: str, mal_v: list[str], ben_v: list[str]) -> str:
    detected = sum(v == FLAG for v in mal_v)
    missed = sum(v == CLEAN for v in mal_v)
    not_attempted = sum(v == NA for v in mal_v)
    attempted = detected + missed
    recall = f"{detected}/{attempted}" + (f" ({detected / attempted * 100:.0f}%)"
                                          if attempted else " (n/a)")
    fp = sum(v == FLAG for v in ben_v)
    fp_n = sum(v != NA for v in ben_v)
    fp_s = f"{fp}/{fp_n}" if fp_n else "n/a"
    return f"| {name} | {recall} | {missed} | {not_attempted} | {fp_s} |"


def build_table() -> str:
    corpus = kat.build(WORK / "kat")
    mal = [e for e in corpus if e["label"] == "malicious"]
    ben = [e for e in corpus if e["label"] == "benign"]
    policy = Policy.default()

    rows = [_row("**Purser**",
                 [_purser(e["path"], policy) for e in mal],
                 [_purser(e["path"], policy) for e in ben])]
    installed = []
    for name, (binary, fn) in PEERS.items():
        if not shutil.which(binary):
            continue
        installed.append(name)
        rows.append(_row(name, [fn(e["path"]) for e in mal],
                         [fn(e["path"]) for e in ben]))

    classes = sorted({e["format"] for e in mal})
    return "\n".join([
        "# Purser vs peer scanners (known-answer corpus)",
        "",
        f"- Corpus: {len(mal)} inert malicious · {len(ben)} synthetic benign.",
        f"- Malicious formats: {', '.join(classes)}.",
        f"- Peers on PATH: {', '.join(installed) or 'none — install them for a full comparison'}.",
        "",
        "| Scanner | Detected (of attempted) | Missed | Not attempted | Benign FP |",
        "|---|---|---|---|---|",
        *rows,
        "",
        "> **Detected** is recall over the samples a tool actually parses. "
        "**Not attempted** = the tool can't read that format (e.g. the pickle-only "
        "scanners picklescan/Fickling on GGUF/Keras/TF/ONNX); those are excluded "
        "from recall rather than scored as misses — a tool isn't penalized for a "
        "format it never claims to scan. Breadth is visible in the *Not attempted* "
        "column: the higher it is, the narrower the tool. **Missed** = scanned but "
        "flagged nothing (a real gap). Numbers depend on installed peer versions.",
        "",
    ])


def main() -> None:
    table = build_table()
    RESULTS.mkdir(parents=True, exist_ok=True)
    (RESULTS / "comparison.md").write_text(table)
    print(table)


if __name__ == "__main__":
    # Measure the static core only: keep external signal sources out
    # of the published numbers (see benchmarks/README.md).
    os.environ.setdefault("PURSER_SIGNALS", "0")
    main()
