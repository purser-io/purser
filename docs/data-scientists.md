# Purser for Data Scientists & ML Engineers

**Audience:** you download, share, or run machine-learning models and want a
quick safety check first. No security background needed.

---

## Why bother scanning a model?

Some model file formats can carry **hidden code that runs automatically the
instant you load the model** — before you ever call `predict`. A tampered model
from the internet can quietly:

- read your environment variables and API keys,
- send data to a server you don't control,
- run shell commands on your machine.

This isn't hypothetical — it's a known attack on the popular "pickle" format
(used by many PyTorch and scikit-learn files). Purser reads the file
**without loading it** and tells you if something looks wrong. Think of it like
antivirus for model files.

**Rule of thumb:** scan any model you didn't create yourself before loading it.

---

## Install (one time)

You need Python 3.11+.

```bash
pip install ".[sign]"        # from this repo
# or, if your team publishes it:  pip install purser[sign]
```

Check it works:

```bash
purser version
```

Prefer not to install anything? Use the container instead:

```bash
docker run --rm -v "$PWD:/data:ro" purser scan /data/your-model.pkl
```

---

## Scan something

**A single file:**

```bash
purser scan ./model.pkl
```

**A whole folder** (e.g. a downloaded model with many files):

```bash
purser scan ./my-model-directory
```

**A model on Hugging Face** (downloads it to a temp folder, scans, deletes it):

```bash
pip install ".[hf]"          # one-time, adds Hugging Face support
purser scan hf://openai-community/gpt2
```

---

## Reading the result

At the bottom of the output you'll see a **verdict**:

| Verdict | Meaning | What to do |
|---|---|---|
| **PASS** | Nothing concerning found. | Safe to proceed. |
| **WARN** | Minor or low-confidence findings. | Skim them; usually fine. |
| **FAIL** | Something dangerous was found. | **Do not load it.** See below. |
| **BLOCKED** | A team rule rejected it (e.g. banned source or file type). | Use an approved model instead. |

Each finding has a **severity** — `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO` —
and a short title like *"Pickle imports dangerous callable `os.system`"*. Higher
severity = more likely to be genuinely harmful.

Example (trimmed):

```
Verdict:  FAIL
CRITICAL  PICKLE_DANGEROUS_IMPORT   Pickle imports dangerous callable `os.system`
HIGH      EXFIL_URL                 Non-allowlisted URL embedded in model data
```

That first line means the file will run an operating-system command when
loaded — a strong sign it's malicious.

---

## "My model got flagged — now what?"

1. **Don't load it.** Especially anything `CRITICAL` or `HIGH`.
2. **Check where it came from.** Official/verified publisher, or a random
   re-upload? Prefer the original source.
3. **Prefer a safer format.** If a `.pkl`, `.bin`, `.pt`, or `.ckpt` version is
   flagged, look for a **`.safetensors`** version of the same model —
   safetensors *cannot* carry code, so it's the safest choice.
4. **If you think it's a false alarm**, get details as JSON and share it with
   your security team:
   ```bash
   purser scan ./model.pkl --format json --output report.json
   ```
5. **When in doubt, ask.** A flagged model is not worth a compromised laptop.

---

## Good habits

- **Choose safetensors** when a model offers it. It holds only numbers (weights),
  never code.
- **Scan before you load**, not after.
- **Be extra careful with `trust_remote_code=True`** (a Hugging Face option).
  It lets a model run its own bundled Python — Purser checks that code, but
  it's a genuinely risky feature; only enable it for models you trust.
- **Watch for surprises in "config" files.** Purser flags model configs that
  quietly wire in code to run on load.

---

## Optional: prove a model is genuine (signing)

If your team signs approved models, you can verify a model is untampered and
from a trusted source:

```bash
purser verify ./model.safetensors
```

A `VERIFIED` result means the file matches a signature from a key your
organization trusts (and tells you the publisher and country of origin). Ask
your DevSecOps team whether signing is set up — they own the
[setup](devsecops-gitlab.md).

---

## FAQ

**Does scanning change or run my model?** No. It only reads the bytes. Your file
is untouched and never executed.

**Is a PASS a guarantee it's safe?** No — it means no *known* danger was found.
It can't detect a model that was maliciously *trained* to misbehave (that's a
different problem). Treat PASS as "clear of hidden code," not "certified safe."

**It says a big file was "truncated."** Very large files are scanned up to a
limit; the tail wasn't checked. Ask your team to raise the limit
(`PURSER_MAX_SCAN_MB`) if you need full coverage.

**Which formats can it check?** Pickle/PyTorch, safetensors, GGUF, ONNX, Keras,
TensorFlow, NumPy, TFLite, CoreML, and more — plus bundled Python and config
files. See the [main README](../README.md#what-it-detects).
