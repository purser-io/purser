"""Purser validation harness (Phase 1).

Scans a labeled corpus and reports detection (TPR) on inert known-answer
malicious samples, false-positive rate on benign models, per-attack-class and
per-format breakdowns, and scan latency. Writes results/results.json and
results/report.md.

    python benchmarks/run.py                 # KAT + any fetched benign models
    python benchmarks/run.py --policy policies/strict.yaml

Real benign models (the meaningful FPR signal) are added by first running
`benchmarks/fetch_benign.py` (needs the [hf] extra). The known-answer recall is
~100% by construction — it guards the detectors against regressions; the FPR and
(Phase 3) evasion numbers are the ones that measure real strength.
"""
from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

import kat
from purser.core.policy import Policy
from purser.core.scanner import scan_target

HERE = Path(__file__).parent
WORK = HERE / "work"
RESULTS = HERE / "results"
DETECTED = {"MEDIUM", "HIGH", "CRITICAL"}   # max_severity that counts as "flagged"
HARD_REJECT = {"FAIL", "BLOCKED"}


def _pct(xs: list[float], p: float) -> float:
    if not xs:
        return 0.0
    xs = sorted(xs)
    k = (len(xs) - 1) * p
    lo = int(k)
    if lo == len(xs) - 1:
        return xs[lo]
    return xs[lo] + (xs[lo + 1] - xs[lo]) * (k - lo)


def _scan(entry: dict, policy: Policy) -> dict:
    t = time.perf_counter()
    r = scan_target(entry["path"], policy=policy)
    dt = time.perf_counter() - t
    ms = r.max_severity
    return {
        **entry,
        "verdict": r.verdict.name,
        "max_severity": ms.name if ms else None,
        "rules": sorted({f.rule_id for f in r.all_findings}),
        "seconds": round(dt, 4),
        "files_scanned": len(r.files),
    }


def _gather_benign_models() -> list[dict]:
    lock = HERE / "benign_models.lock.json"
    cache = WORK / "benign"
    out: list[dict] = []
    if lock.exists():
        for m in json.loads(lock.read_text()).get("models", []):
            p = cache / m["id"]
            if p.exists():
                out.append({"id": "real:" + m["id"], "path": str(p), "label": "benign",
                            "format": m.get("format", "mixed"), "attack_class": "-"})
    return out


def _detected(r: dict) -> bool:
    return r["max_severity"] in DETECTED


def _report(results: list[dict], policy_name: str) -> str:
    mal = [r for r in results if r["label"] == "malicious"]
    ben = [r for r in results if r["label"] == "benign"]
    tp = sum(_detected(r) for r in mal)
    fn = [r for r in mal if not _detected(r)]
    fp = [r for r in ben if r["verdict"] in HARD_REJECT]
    warn = [r for r in ben if r["verdict"] == "WARN"]
    tpr = tp / len(mal) * 100 if mal else 0.0
    fpr = len(fp) / len(ben) * 100 if ben else 0.0
    lat = [r["seconds"] for r in results]

    # per attack-class (malicious) and per-format detection
    by_class: dict[str, list[dict]] = {}
    for r in mal:
        by_class.setdefault(r["attack_class"], []).append(r)

    L = [
        "# Purser validation report (Phase 1)",
        "",
        f"- Policy: `{policy_name}`",
        f"- Corpus: {len(mal)} malicious (known-answer) · {len(ben)} benign "
        f"({sum(1 for r in ben if r['id'].startswith('real:'))} real models)",
        "",
        "## Headline",
        "",
        "| Metric | Value |",
        "|---|---|",
        f"| Detection (TPR) on known-answer set | **{tpr:.1f}%** ({tp}/{len(mal)}) |",
        f"| False-positive rate (benign hard-failed) | **{fpr:.1f}%** ({len(fp)}/{len(ben)}) |",
        f"| Benign flagged WARN (advisory) | {len(warn)}/{len(ben)} |",
        f"| Scan latency p50 / p95 | {_pct(lat, .5)*1000:.0f} ms / {_pct(lat, .95)*1000:.0f} ms |",
        "",
        "> Known-answer recall is ~100% by construction — it guards the detectors "
        "against regressions. The FPR (on real models) is the meaningful quality "
        "signal; evasion resistance is measured in Phase 3.",
        "",
        "## Detection by attack class",
        "",
        "| Attack class | Detected | Example rules |",
        "|---|---|---|",
    ]
    for cls in sorted(by_class):
        rs = by_class[cls]
        d = sum(_detected(r) for r in rs)
        rules = sorted({x for r in rs for x in r["rules"]})[:3]
        L.append(f"| {cls} | {d}/{len(rs)} | {', '.join(rules) or '—'} |")

    if fn:
        L += ["", "## ⚠️ Missed malicious (investigate)", ""]
        L += [f"- `{r['id']}` ({r['attack_class']}) → verdict {r['verdict']}, "
              f"max severity {r['max_severity']}" for r in fn]
    if fp:
        L += ["", "## ⚠️ False positives (benign hard-failed)", ""]
        L += [f"- `{r['id']}` → {r['verdict']}; rules: {', '.join(r['rules'])}" for r in fp]
    if not _gather_benign_models():
        L += ["", "_No real benign models present — run `benchmarks/fetch_benign.py` "
              "(needs the `[hf]` extra) for a meaningful FPR._"]
    L.append("")
    return "\n".join(L)


def main() -> None:
    ap = argparse.ArgumentParser(description="Purser validation harness")
    ap.add_argument("--policy", default=None, help="policy YAML (default: built-in default)")
    args = ap.parse_args()
    policy = Policy.load(args.policy) if args.policy else Policy.default()
    policy_name = args.policy or "default"

    corpus = kat.build(WORK / "kat") + _gather_benign_models()
    results = [_scan(e, policy) for e in corpus]

    RESULTS.mkdir(parents=True, exist_ok=True)
    (RESULTS / "results.json").write_text(json.dumps(
        {"policy": policy_name, "results": results}, indent=2))
    report = _report(results, policy_name)
    (RESULTS / "report.md").write_text(report)
    print(report)


if __name__ == "__main__":
    main()
