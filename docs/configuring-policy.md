# Configuring a Policy

**Audience:** anyone who wants to control which models Purser allows. No
security background needed. A *policy* is a short YAML file with your team's
rules — like "only allow safe file types" or "block models from these sources."

If there's no policy, Purser still scans and flags dangerous content; a
policy adds **your** rules on top and decides pass/fail.

---

## Fastest start

1. Copy an example from [`policies/`](../policies/) — `default.yaml` (lenient),
   `strict.yaml`, `allowlist-us-eu.yaml`, or `signed-only.yaml`.
2. Check it's valid:
   ```bash
   purser policy-check my-policy.yaml
   ```
3. Use it in a scan:
   ```bash
   purser scan ./model --policy my-policy.yaml
   ```

That's it. Everything below is how to customize the rules.

---

## The one idea to understand: allowlist vs blocklist

Several settings use a **mode**. It has three values:

| Mode | Meaning |
|---|---|
| `off` | This rule is not applied. |
| `blocklist` | Everything is allowed **except** the things you list. |
| `allowlist` | **Only** the things you list are allowed; everything else is blocked. |

- Use **blocklist** to ban a few specific bad things ("block pickle files").
- Use **allowlist** to permit only a known-good set ("only these file types").
  Allowlist is stricter and safer, but remember: **anything you forget to list
  gets blocked.**

---

## The settings

### 1. How strict to be — `fail_on`

Sets the point at which findings make a scan **FAIL**. Findings have a severity:
`INFO` < `LOW` < `MEDIUM` < `HIGH` < `CRITICAL`.

```yaml
fail_on:
  severity: HIGH      # anything HIGH or worse fails the scan
```

Use `HIGH` for a sensible default; `MEDIUM` to be stricter; `CRITICAL` to only
fail on the most serious findings.

### 2. Which file types are allowed — `formats`

Controls "model types." Some formats (like `pickle`) can carry code; others
(like `safetensors`) can't.

```yaml
formats:
  mode: allowlist
  list: [safetensors, gguf, onnx]     # only these are allowed
```

**When to use:** allowlisting the safe formats (`safetensors`, `gguf`, `onnx`) is
the single most effective rule you can set — it side-steps the whole class of
code-in-model attacks.

<details>
<summary>Valid format names</summary>

`pickle`, `pytorch`, `pytorch_legacy`, `pt2`, `executorch`, `joblib`, `numpy`,
`keras_h5`, `keras_v3`, `tf_savedmodel`, `tflite`, `tfjs`, `onnx`,
`safetensors`, `gguf`, `ggml`, `coreml`, `skops`, `flax_msgpack`, `paddle`,
`mxnet`, `openvino`, `pmml`, `gbm_native`, `python_source`, `hf_config`.
</details>

### 3. Country of origin — `origin`

Restrict models by the country they come from (two-letter codes like `US`,
`CN`, `FR`).

```yaml
origin:
  mode: blocklist
  countries: [CN, RU, KP, IR]
  unknown_origin: warn        # what to do when the country is unknown
  require_signed: false       # see "trust" below
```

- `unknown_origin` can be `allow`, `warn`, or `deny`.
- Where does the country come from? In order: a **verified signature** →
  the `--origin` flag → a `provenance.yaml` file next to the model → a built-in
  lookup of ~90 known publishers. See the country database with
  `purser origins`.

> **Important:** without signing (below), the country is a *claim*, not proof.
> For a real guarantee, add `require_signed: true`.

### 4. Trust — `require_signed`

Set inside `origin`. When `true`, a model must carry a valid cryptographic
signature from a key your team trusts, or it is **BLOCKED**.

```yaml
origin:
  require_signed: true
```

This is what turns country-of-origin from a label into an enforced rule. Setup
is in the [DevSecOps guide](devsecops-gitlab.md#step-7--enforce-trusted-models-optional-advanced).

### 5. Who published it — `publishers`

Block or allow by publisher (e.g. a Hugging Face organization).

```yaml
publishers:
  blocked: [evilcorp]     # never allow these publishers
  allowed: []             # if non-empty, ONLY these are allowed
```

### 6. Block by model name — `models`

Block or allow specific models by name pattern (`*` matches anything). Matches
against the model's repo id (e.g. `org/name`) and the file/folder name.

```yaml
models:
  mode: blocklist
  patterns:
    - "evilcorp/*"          # any model from this org
    - "*-backdoor"          # any name ending in -backdoor
    - "known-bad-model"     # one exact model
```

For a local file, tag it so the rule can match: `purser scan ./m.pkl
--repo-id org/name`.

### 7. Size limit — `max_file_size_mb`

```yaml
max_file_size_mb: 51200     # 0 (default) = no limit
```

Flags unusually large files. Useful for catching junk or zip-bomb-style files.

### 8. Fine-tuning individual findings — `rules`

Change how one specific finding is treated. Each finding has an ID (shown in
scan output, e.g. `PICKLE_UNKNOWN_IMPORT`).

```yaml
rules:
  - id: PICKLE_UNKNOWN_IMPORT
    action: deny            # deny | warn | ignore
```

- `deny` — always block if this finding appears.
- `warn` — downgrade it so it won't fail the scan.
- `ignore` — hide it entirely (use sparingly).

---

## What the scan decides

Your policy produces one **verdict**, which also sets the command's exit code
(handy for CI):

| Verdict | Meaning | Exit code |
|---|---|:---:|
| PASS | No concerns. | 0 |
| WARN | Minor findings only. | 0 |
| FAIL | A finding at/above your `fail_on` severity. | 1 |
| BLOCKED | A rule (format / origin / publisher / name / signing) rejected it. | 2 |
| ERROR | Couldn't scan (bad path, etc.). | 3 |

---

## Ready-made recipes

**A. Gentle default (good for getting started / CI warnings):**
```yaml
version: 1
name: gentle
fail_on:
  severity: HIGH
```

**B. Strict (block code-carrying formats, fail on medium+):**
```yaml
version: 1
name: strict
fail_on:
  severity: MEDIUM
formats:
  mode: allowlist
  list: [safetensors, gguf, onnx]
models:
  mode: blocklist
  patterns: ["*-backdoor"]
```

**C. Trusted only (US/EU, signed, safe formats):**
```yaml
version: 1
name: trusted-only
fail_on:
  severity: HIGH
formats:
  mode: allowlist
  list: [safetensors, gguf, onnx]
origin:
  mode: allowlist
  countries: [US, CA, GB, FR, DE, NL, SE, IE, IL, JP, KR, AU, NZ]
  unknown_origin: deny
  require_signed: true
```

---

## Common mistakes

- **Allowlist blocks something you wanted.** Remember allowlist blocks anything
  not listed. Add the missing format/country/name, or switch to blocklist.
- **Turning a rule "off".** Write `mode: off` — but note plain `off` in YAML can
  be read as a boolean; Purser handles that, so both work.
- **Empty allowlist/blocklist patterns.** If you set `models.mode` you must give
  at least one pattern, or the policy is rejected.
- **Expecting country rules to be proof.** They're advisory unless you set
  `require_signed: true`.
- **Not validating.** Always run `purser policy-check my-policy.yaml` before
  shipping — it catches typos and prints the effective settings.

---

## Full annotated reference

```yaml
version: 1
name: example                 # a label for this policy

fail_on:
  severity: HIGH              # INFO | LOW | MEDIUM | HIGH | CRITICAL

formats:
  mode: allowlist            # off | allowlist | blocklist
  list: [safetensors, gguf, onnx]

origin:
  mode: blocklist            # off | allowlist | blocklist
  countries: [CN, RU]        # ISO 3166-1 alpha-2 codes
  unknown_origin: warn       # allow | warn | deny
  require_signed: false      # true = must be validly signed

publishers:
  blocked: [some-org]
  allowed: []                # non-empty => only these allowed

models:
  mode: blocklist            # off | allowlist | blocklist
  patterns: ["evilcorp/*"]   # glob, case-insensitive

max_file_size_mb: 0          # 0 = unlimited

rules:                       # per-finding overrides
  - id: PICKLE_UNKNOWN_IMPORT
    action: warn             # deny | warn | ignore
```

---

## Where to go next

- Set this up in a pipeline: [DevSecOps + GitLab guide](devsecops-gitlab.md).
- Understand scan results: [Data scientist guide](data-scientists.md).
- Full option list: [main README](../README.md#policy-engine).
