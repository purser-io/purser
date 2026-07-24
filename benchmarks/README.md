# Purser validation benchmark

Measures Purser's detection efficacy and — the number that actually matters —
its **false-positive rate on real models**, plus scan latency. Addresses roadmap
item #1 (*real-world validation + published benchmark*).

**Phase 1** (this): a known-answer test (KAT) corpus of **inert** malicious
samples across the claimed attack classes, a **synthetic-benign** set, and an
optional **real-model** negative set pulled from HuggingFace. No live malware is
generated or committed.

Later phases (see `ROADMAP.md`): head-to-head comparison vs picklescan / Fickling
/ ModelScan / ModelAudit (Phase 2), an adversarial evasion suite (Phase 3), and
scheduled-CI publication with regression gates (Phase 4).

## Run it

```bash
uv pip install -e ".[dev,sign]"          # scanner + deps
python benchmarks/run.py                 # KAT + any fetched benign models

# add the real-model negative set (recommended; needs the HF extra):
uv pip install -e ".[hf]"
python benchmarks/fetch_benign.py        # pins commit shas -> benign_models.lock.json
python benchmarks/run.py
```

Outputs `benchmarks/results/report.md` and `results.json` (both gitignored).

## What it measures

| Metric | Meaning |
|---|---|
| **TPR (known-answer)** | Fraction of inert malicious samples flagged (`max severity ≥ MEDIUM`). ~100% *by construction* — it guards the detectors against regressions, not a claim of strength. |
| **False-positive rate** | Benign models hard-failed (`FAIL`/`BLOCKED`). **The meaningful quality signal** — any FP is a bug to fix. `WARN` is tracked separately (advisory). |
| **Latency p50/p95** | Per-target scan time. |
| Per-attack-class / per-format | Where detection fires (and where it doesn't). |

## Corpus

- **KAT malicious** (`kat.py`): pickle (`os.system`/`eval`/network), pytorch zip,
  numpy object-array, Keras `Lambda`, GGUF SSTI, TF `PyFunc`, archive zip-slip,
  embedded + base64/gzip exfil, and `trust_remote_code`. Inert payloads
  (`os.system("true")`), regenerated each run into `work/` — never committed.
- **Benign**: synthetic clean artifacts + real HuggingFace models pinned by
  commit SHA (`benign_models.yaml` → `benign_models.lock.json`). Grow the list
  for a stronger FPR estimate.

## Scope & honesty

- Labels the benign set "benign by reputation" — this does **not** cover trained
  **behavioral backdoors / poisoning**, which are out of scope for a static
  content scanner (see `SECURITY.md`).
- KAT recall is by-construction; treat the FPR and (Phase 3) evasion rate as the
  real measures. Report any misses/FPs as issues — they feed the roadmap.
