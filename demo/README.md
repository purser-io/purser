# Try Purser in 5 minutes

Purser checks machine-learning model files for **hidden dangerous code** and
**leaked secrets** *before* anyone loads them. It reads each file without ever
running it, then gives a one-word result: **PASS**, **WARN**, **FAIL**, or
**BLOCKED**.

This folder has a few tiny sample files and a rule that **blocks models from a
chosen country** (China, in this example), so you can see both kinds of check.

## Setup

```bash
pip install "purser[sign]"        # or use the Docker image / run from source
python demo/gen_samples.py        # creates the sample files in demo/models/
```

The generator writes five small files:

| File | What it is | What Purser should say |
|---|---|---|
| `clean-model.safetensors` | a normal (empty) model file | **PASS** — nothing wrong |
| `config.json` | an ordinary model settings file | **PASS** |
| `benign.pkl` | a harmless saved Python object | **PASS** |
| `suspicious.pkl` | a file rigged to run a command when it's loaded | **FAIL** — dangerous |
| `exfil-sample.bin` | a file with a fake webhook + fake cloud key inside | **FAIL** — leaks secrets |

The two risky files are only dangerous if *some other tool* opens them. Purser
just reads them, so nothing here ever runs. (They're created on your machine by
the generator and kept out of version control.)

## 1. Scan the files

```bash
purser scan demo/models
```

Purser spots the rigged pickle (it would run a shell command if something
loaded it) and the fake webhook + cloud key in the other file. Because it found
something dangerous, the overall result is **FAIL**. The three clean files pass.

Scan one at a time to see the difference:

```bash
purser scan demo/models/clean-model.safetensors   # PASS
purser scan demo/models/suspicious.pkl             # FAIL
```

## 2. Block models from a country

`block-china.yaml` is a rule file that says: *don't allow models from China.*
You tell Purser where a model is from (or it works it out — see below), and it
blocks the ones you've disallowed.

```bash
# the same clean model, labelled with two different countries:
purser scan demo/models/clean-model.safetensors --origin US -p demo/block-china.yaml   # PASS
purser scan demo/models/clean-model.safetensors --origin CN -p demo/block-china.yaml   # BLOCKED
```

The China run comes back **BLOCKED**, with a clear reason:
*"Model origin `CN` is not permitted."*

### Working out the country automatically

Purser knows the home country of many well-known model publishers, so it can
often tell on its own — no `--origin` needed:

```bash
purser origins qwen           # qwen -> CN
purser origins deepseek-ai    # deepseek-ai -> CN
```

So a real model from a Chinese publisher gets blocked without you labelling it:

```bash
pip install "purser[hf]"      # adds the Hugging Face download helper
purser scan hf://Qwen/Qwen2.5-0.5B-Instruct -p demo/block-china.yaml   # BLOCKED
```

22 Chinese publishers are recognised out of the box (deepseek-ai, qwen, THUDM,
01-ai, baichuan-inc, zhipuai, tencent, bytedance, …). A country label can be
faked, so to require *proof* you can add `require_signed: true` to the rule —
then only a cryptographically **signed** model is trusted.

## What the results mean (handy for CI)

Every scan ends with an exit code your pipeline can act on:

| Exit code | Meaning |
|---|---|
| `0` | clean (PASS or WARN) |
| `1` | dangerous content found (FAIL) |
| `2` | blocked by a rule, e.g. wrong country (BLOCKED) |
| `3` | couldn't scan (bad path, etc.) |

So a dangerous or disallowed model fails your build on its own — no extra
scripting needed.

## More models to try

Real models from Hugging Face (needs `pip install "purser[hf]"` — Purser
downloads and scans them for you):

- `hf://hf-internal-testing/tiny-random-gpt2` — a few KB
- `hf://hf-internal-testing/tiny-random-bert`
- `hf://Qwen/Qwen2.5-0.5B-Instruct` — a real Chinese-published model: the file
  is clean, but `block-china.yaml` blocks it on origin

Or point Purser at any model file you already have:

```bash
purser scan path/to/your-model.safetensors
```

## Clean up

```bash
rm -f demo/models/suspicious.pkl demo/models/exfil-sample.bin
```
