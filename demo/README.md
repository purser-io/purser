# Purser demo

A self-contained sandbox for trying the Purser CLI: a handful of tiny sample
models and a **country-of-origin policy that blocks China**. Nothing here is ever
executed — the models are scanned at the byte/opcode level.

## Setup

```bash
pip install "purser[sign]"        # or run from source / the container image
python demo/gen_samples.py        # materialize the sample models (see note below)
```

`gen_samples.py` writes into `demo/models/`:

| File | What it is | Expected |
|---|---|---|
| `clean-model.safetensors` | valid safetensors header, no tensors | **PASS** |
| `config.json` | benign HuggingFace config | **PASS** |
| `benign.pkl` | a plain `dict` pickle | **PASS** |
| `suspicious.pkl` | pickle that resolves `os.system` on load* | **FAIL** |
| `exfil-sample.bin` | text with a fake Slack webhook + example AWS key | **FAIL** |

\* The payload is a harmless `echo`, and Purser **never unpickles** — it reads the
opcodes statically. The benign files are committed; the two intentionally-malicious
ones are gitignored, so run the generator to create them locally.

## 1 — Scan the models (content detection)

```bash
purser scan demo/models
```
Finds `posix.system` in the pickle plus the webhook / AWS key / URL in the exfil
sample → **Verdict: FAIL** (exit `1`). The clean files pass.

Scan individually to see the contrast:
```bash
purser scan demo/models/clean-model.safetensors   # PASS  (exit 0)
purser scan demo/models/suspicious.pkl            # FAIL  (exit 1)
```

## 2 — Block models from China (policy)

`block-china.yaml` blocklists origin `CN`. Origin is resolved from a verified
signature, from Purser's publisher→country database, or from the self-asserted
`--origin` flag.

```bash
# same clean model, two different origins:
purser scan demo/models/clean-model.safetensors --origin US -p demo/block-china.yaml   # PASS    (exit 0)
purser scan demo/models/clean-model.safetensors --origin CN -p demo/block-china.yaml   # BLOCKED (exit 2)
```
The `CN` run reports `POLICY_ORIGIN_BLOCKED — Model origin \`CN\` is not permitted`.

### Automatic origin (no flag)

Purser ships a publisher→country map, so a real Chinese-published model is
recognized without `--origin`:

```bash
purser origins qwen           # qwen -> CN
purser origins deepseek-ai    # deepseek-ai -> CN

# needs the HF extra: pip install "purser[hf]"
purser scan hf://Qwen/Qwen2.5-0.5B-Instruct -p demo/block-china.yaml   # BLOCKED
```
22 Chinese publishers are pre-mapped (`deepseek-ai`, `qwen`, `THUDM`, `01-ai`,
`baichuan-inc`, `zhipuai`, `tencent`, `bytedance`, …). To make CN an *enforced*
fact rather than a claim, set `require_signed: true` in the policy.

## Exit codes
`0` pass/warn · `1` findings · `2` policy-blocked · `3` error — so any of these
gate a CI pipeline directly.

## More small models to try (via `hf://`, needs `[hf]`)
- `hf://hf-internal-testing/tiny-random-gpt2` — pickle `.bin` + safetensors + config (KB)
- `hf://hf-internal-testing/tiny-random-bert`
- ONNX Model Zoo `mnist-8.onnx` (~26 KB) — `.onnx`
- `hf://ggml-org/models` → `tinyllamas/stories260K.gguf` (~1 MB) — `.gguf`

## Cleanup
```bash
rm -f demo/models/suspicious.pkl demo/models/exfil-sample.bin
```
