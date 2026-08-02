# Purser validation benchmark

Measures Purser's detection efficacy and — the number that actually matters —
its **false-positive rate on real models**, plus scan latency. Addresses the
(now-complete) *real-world validation + published benchmark* roadmap arc.

Scope note: the corpus is scanned as **local directories**, so these numbers
measure the static core's detection/FPR. Signal sources (upstream Hub
verdicts, the attestation gate) are not exercised here — they only run on
`hf://`-path scans.

**Phase 1** (this): a known-answer test (KAT) corpus of **inert** malicious
samples across the claimed attack classes, a **synthetic-benign** set, and an
optional **real-model** negative set pulled from HuggingFace. No live malware is
generated or committed.

**Phase 2** (this): a head-to-head comparison vs picklescan / Fickling /
ModelScan / ModelAudit over the same corpus (`compare.py`). **Phase 3** (this):
an adversarial **evasion suite** (`evasion.py`) — malicious payloads wrapped in
spoofed extensions, nested archives, `STACK_GLOBAL`/`posix` pickles, and
encoded/obfuscated exfil — measuring evasion recall and surfacing known-open
gaps. **Phase 4** (this): scheduled CI (`.github/workflows/benchmark.yml`) runs
the corpus weekly and **gates on regression** — a drop in known-answer
detection, a rise in the benign FPR, or an evasion-recall regression fails the
job. Remaining: a growing real-model corpus.

## Run it

```bash
uv pip install -e ".[dev,sign]"          # scanner + deps
python benchmarks/run.py                 # KAT + any fetched benign models

# add the real-model negative set (recommended; needs the HF extra):
uv pip install -e ".[hf]"
python benchmarks/fetch_benign.py        # pins commit shas -> benign_models.lock.json
python benchmarks/run.py

# regression gate (what scheduled CI runs):
python benchmarks/run.py --min-tpr 100 --max-fpr 0   # exit 1 on regression

# head-to-head vs peers (install any subset; missing ones show n/a):
pip install picklescan modelscan fickling modelaudit
python benchmarks/compare.py             # -> results/comparison.md

# adversarial evasion resistance (Phase 3), gated on the resisted set:
python benchmarks/evasion.py --min-recall 100   # -> results/evasion.md
```

Outputs `benchmarks/results/{report,comparison}.md` and `results.json` (all gitignored).

## What it measures

| Metric | Meaning |
|---|---|
| **TPR (known-answer)** | Fraction of inert malicious samples flagged (`max severity ≥ MEDIUM`). ~100% *by construction* — it guards the detectors against regressions, not a claim of strength. |
| **False-positive rate** | Benign models hard-failed (`FAIL`/`BLOCKED`). **The meaningful quality signal** — any FP is a bug to fix. `WARN` is tracked separately (advisory). |
| **Latency p50/p95** | Per-target scan time. |
| Per-attack-class / per-format | Where detection fires (and where it doesn't). |

## Latest measured

Snapshot from a local run on **2026-07-27** (default policy, 12 known-answer
malicious + 79 benign incl. **75 real HuggingFace models** — a broad architecture
sweep: encoders, causal/seq2seq LMs, vision, audio, multimodal; pickle /
safetensors / ONNX / Keras, incl. int8-quantized ONNX). Reproduce with the
commands above; the scheduled CI job re-measures weekly.

| Metric | Value |
|---|---|
| Detection (TPR) on known-answer set | **100%** (12/12) |
| False-positive rate (benign hard-failed) | **0%** (0/79) |
| Benign flagged WARN (advisory) | 0/79 |
| Scan latency p50 / p95 | 267 ms / 22 s (large real models dominate the tail) |

Head-to-head over the known-answer corpus (`compare.py`, peer versions
picklescan 1.0.5 · ModelScan 0.8.8 · Fickling 0.1.12 · ModelAudit):

| Scanner | Detected (of attempted) | Missed | Not attempted | Benign FP |
|---|---|---|---|---|
| **Purser** | 12/12 (100%) | 0 | 0 | 0/4 |
| picklescan | 5/12 (42%) | 7 | 0 | 0/4 |
| ModelScan | 2/3 (67%) | 1 | 9 | 0/2 |
| Fickling | 7/7 (100%) | 0 | 5 | 1/2 |
| ModelAudit | 7/12 (58%) | 5 | 0 | 0/4 |

*Detected* is recall over the samples a tool parses; *Not attempted* counts
formats a tool can't read (pickle-only scanners on GGUF/Keras/TF), so a tool is
never penalized for a format it never claims to scan. Purser is the only tool
that attempts every format **and** flags every malicious sample with zero false
positives. Peer numbers depend on installed versions and available deps (e.g.
ModelScan skips Keras/TF here without those runtimes) — re-run `compare.py` in
your environment for authoritative figures.

Adversarial evasion resistance (`evasion.py`):

| Set | Result |
|---|---|
| Evasion recall on techniques Purser claims to resist | **100%** (17/17) — gated |
| Known-open residuals (ROADMAP) exercised | 1 evaded (packed-binary endpoint) |

The resisted set spans spoofed extensions, doc-name disguise, nested archives,
`.npz`-embedded pickles, `STACK_GLOBAL`/`posix` pickles, base32/hex/zlib/base85/UTF-16
and single-byte-XOR exfil, encoded/obfuscated `trust_remote_code` source,
aliased/dynamically-resolved dangerous callables (taint pass), and a
protocol-0 ASCII pickle under a structured extension. The one known-open
residual is reported (not gated) so the frontier stays measured.

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
