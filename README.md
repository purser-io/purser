<div align="center">

<img src="https://raw.githubusercontent.com/purser-io/purser/main/assets/brand/purser-mark.png" alt="" width="88" />

# Purser

**The open-source model supply-chain control plane: policy, provenance, and
enforcement for ML model artifacts — from CI to Kubernetes admission.**

[![CI](https://github.com/purser-io/purser/actions/workflows/ci.yml/badge.svg)](https://github.com/purser-io/purser/actions/workflows/ci.yml)
&nbsp;[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
&nbsp;![Version](https://img.shields.io/badge/version-0.2.1-informational.svg)
&nbsp;![Python](https://img.shields.io/badge/python-3.11%2B-3776AB.svg?logo=python&logoColor=white)
&nbsp;![Tests](https://img.shields.io/badge/tests-292%20passing-brightgreen.svg)
&nbsp;![Lint](https://img.shields.io/badge/lint-ruff-000000.svg)
&nbsp;![Status](https://img.shields.io/badge/status-pre--1.0-orange.svg)
&nbsp;[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/13900/badge)](https://www.bestpractices.dev/projects/13900)

</div>

Purser is the **clearance desk** for models entering your environment: it
gathers signals about a model artifact, evaluates them against a
**user-defined policy**, and renders one verdict — `PASS` / `WARN` / `FAIL` /
`BLOCKED` — that it **enforces in CI and at Kubernetes admission**. Policy can
restrict models by **country of origin**, **publisher**, **name**, **model
format/type**, or **signer identity**, and require verified provenance
(`require_signed`). Ships as a CLI, a REST API, container images, a Helm
chart, and a `ValidatingAdmissionWebhook`.

Scanning is one *input* to that verdict, not the product. Signals feeding the
policy engine today:

- a built-in **static scanner** — malicious code and data-exfiltration
  indicators across ~35 model formats, taking the best-of-breed techniques
  from open-source scanners (modelscan, picklescan) and extending them;
- **verified provenance** — Ed25519 model signing with a trust store and
  revocation, plus offline **Sigstore** (Fulcio/Rekor) identity verification;
- the optional **deep-analysis companion** (`purser-deep`) — pickle
  gadget-chain heuristics and weight tampering/steganography;
- **upstream & third-party signals** — the HuggingFace Hub's own scan
  verdicts, an opt-in model-card/eval-attestation gate, and any feed you
  plug in via the `purser.signals` interface (an upstream *safe* never
  downgrades Purser's own verdict — see
  [Signal sources](#signal-sources-upstream-intelligence)).

The core never loads a model: nothing is deserialized or executed, all
analysis is byte- and opcode-level. Format is detected by **content (magic
bytes), not the filename**, so renaming a payload to a benign-looking
extension doesn't evade the scan — a pickle disguised as `model.onnx`, or
hidden under a `README.md`, is still caught.

> [!TIP]
> **New here?** Start with the plain-language [user guides](docs/): one for
> [setting up scanning in GitLab](docs/devsecops-gitlab.md), one for
> [data scientists checking models](docs/data-scientists.md).

> [!NOTE]
> Pre-1.0. Published to **PyPI** — `pip install purser` — with signed container
> images and a Helm chart on GHCR (see below). The name is pending trademark
> clearance ([`BRAND.md`](BRAND.md)).

## Contents

- [Using Purser](#using-purser) · [What it detects](#what-it-detects) · [How Purser compares](#how-purser-compares)
- [Policy engine](#policy-engine) · [Verified provenance](#verified-provenance-model-signing) · [Authentication](#authentication-and-api-keys)
- [Install & CLI](#install-and-cli-usage) · [REST API](#rest-api) · [Observability](#observability)
- [Docker](#docker) · [Deep analysis](#deep-analysis-optional-companion) · [Signal sources](#signal-sources-upstream-intelligence) · [Supply chain](#supply-chain-of-purser-itself) · [Kubernetes](#kubernetes)
- [Security model](#security-model) · [Development](#development) · [Docs & security](#roadmap-and-security-posture) · [Contributing](#contributing) · [License](#license)

## Using Purser

**In Kubernetes** — deploy once with the [Helm chart](deploy/helm/purser/), then
scan models against the in-cluster service (rules change via `helm upgrade`, no
rebuild). Two patterns:

```bash
helm install purser oci://ghcr.io/purser-io/charts/purser --version 0.2.1 \
  -n purser --create-namespace
KEY=$(kubectl -n purser get secret purser-auth -o jsonpath='{.data.api-key}' | base64 -d)

# 1) push a model to it — read the verdict (PASS / WARN / FAIL / BLOCKED)
curl -s -H "X-API-Key: $KEY" -F "file=@model.safetensors" \
  http://purser.purser.svc/v1/scan/upload | jq .verdict

# 2) scan a model already on a mounted store (modelStore.enabled=true)
curl -s -H "X-API-Key: $KEY" -H 'Content-Type: application/json' \
  -d '{"path":"/models/vendor-drop/llama-3.safetensors"}' \
  http://purser.purser.svc/v1/scan/path | jq .verdict
```

A common placement is a **pre-load gate**: call `/v1/scan/upload` from CI or a
model-registry hook and only promote a model whose verdict is `PASS`/`WARN`. To
enforce this at *deploy* time in Kubernetes, enable the bundled
[admission webhook](#kubernetes) (`admission.enabled=true`), which rejects pods
that reference unpinned images or unapproved model digests.

**In a GitLab pipeline** — run the image as a CI job; the **exit code gates the
pipeline** (`0` pass/warn · `1` findings · `2` policy-blocked · `3` error), so a
bad model fails the build on its own:

```yaml
scan-models:
  stage: security
  image: ghcr.io/purser-io/purser:latest
  script:
    - purser scan ./models --policy .purser/policy.yaml --format sarif --output purser.sarif
  artifacts: { when: always, paths: [purser.sarif] }
```

**In GitHub Actions** — the [`purser-io/purser`](action.yml) action does the same in one step and fails the job on findings/blocked:

```yaml
- uses: purser-io/purser@v0.2.1   # or pin a commit SHA
  with:
    path: ./models
    policy: .purser/policy.yaml   # optional; sarif written to purser.sarif
```

Use the `-hf` image and `purser scan hf://org/model` to pull + scan a
HuggingFace model (add `HF_TOKEN` as a masked variable for private repos); add
`allow_failure: true` while tuning the policy. Full walkthrough:
[`docs/devsecops-gitlab.md`](docs/devsecops-gitlab.md).

## What it detects

*This table is the built-in static scanner's surface — one signal. See
[Deep analysis](#deep-analysis-optional-companion) and
[Signal sources](#signal-sources-upstream-intelligence) for the others.*

| Engine | Formats | Detections |
|---|---|---|
| Pickle opcode analysis | `.pkl` `.pt` `.pth` `.bin` `.ckpt` `.joblib` `.dill` `.pdparams` | Dangerous imports (`os`, `subprocess`, `eval`, `socket`, `requests`, …) via GLOBAL **and** STACK_GLOBAL resolution, multi-pickle streams, REDUCE invoked-on-load tracking, unknown-import safelist tier, unparseable/evasive pickles |
| PyTorch | zip + legacy checkpoints, `.pt2` (torch.export) | All embedded pickles scanned; `torch.package` embedded Python source flagged |
| ExecuTorch | `.pte` | Flatbuffer identifier validation (extension spoofing) |
| Keras | `.h5`, `.keras` v3 | `Lambda` / `TFOpLambda` layers (marshaled-bytecode execution) **and non-builtin custom layers** (external code runs on load — config walked for layer classes outside the Keras/TF namespaces); works without h5py via byte heuristic |
| OpenVINO IR | `.xml` (+ `.bin`) | XXE / DOCTYPE-entity declarations, and graph references to host shared libraries (`.so`/`.dll`) or absolute paths (custom-extension code-load / host-access); XML parsed safely |
| TensorFlow | SavedModel `.pb` | `PyFunc`/`EagerPyFunc` (code execution), `ReadFile`/`WriteFile`/`MatchingFiles` and queue-based file readers (host file access) graph ops |
| TFLite | `.tflite` | Flex-delegate ops: `FlexPyFunc` (code execution), file-access kernels, full-TF attack surface; magic validation |
| TF.js | `model.json` | Weight-shard path traversal / remote shard references |
| ONNX | `.onnx` | Custom Python operator domains, external-data path traversal |
| safetensors | `.safetensors` | Header validation (spoofed/malformed headers used against parser bugs) |
| GGUF | `.gguf` | **Chat-template (Jinja SSTI) injection** — `__subclasses__`, `os.` access, dynamic code in templates |
| CoreML | `.mlmodel` `.mlpackage` | `CustomModel` backend and custom-layer markers (developer-supplied native code) |
| skops | `.skops` | Schema types run through the pickle dangerous/safe classifier; pickle-fallback loader nodes |
| PaddlePaddle | `.pdmodel` `.pdparams` | `py_func`/`py_layer` ops (code execution); param files scanned as pickles |
| TorchServe | `.mar` | Bundled `handler.py` that TorchServe imports/executes on serve; embedded model recursed |
| MLflow | `MLmodel` dir | `python_function` flavor `loader_module`/bundled `code/` (arbitrary code on load) |
| Caffe | `.prototxt` `.caffemodel` | `type: "Python"` (PythonLayer) runs arbitrary Python at inference |
| PMML | `.pmml` | XXE entity declarations, Extension elements with script content |
| Bundled Python | `*.py` (`modeling_*.py`, …) | **AST analysis of `trust_remote_code` source** — exec/eval, os/subprocess, sockets & HTTP clients, dynamic import, native code, marshal/pickle, base64/hex deobfuscation, `os.environ` harvesting; module-scope calls escalated (run on import). **Dataflow/taint** additionally catches payloads assembled at runtime — a dangerous callable aliased to a variable then invoked, or resolved from a decoded/char-assembled name, and deobfuscated data reaching an exec/os sink |
| HF config | `config.json`, `*_config.json` | `auto_map` / `custom_pipelines` / `trust_remote_code` keys that arm remote-code execution, linked to the referenced source files |
| NumPy | `.npy` `.npz` | Object-dtype arrays (embedded pickles) — payload scanned recursively |
| Archives | `.zip` `.tar` `.gz` | Zip-slip path traversal, zip bombs, recursive member scanning (depth-capped) |
| Identified for policy + exfil scan | legacy GGML, Flax/msgpack, MXNet `.params`, XGBoost `.ubj`, CatBoost `.cbm`, TensorRT `.engine`/`.plan`/`.trt`, Darknet `.weights`, LightGBM native, Torch7 `.t7`, NeMo `.nemo`, H2O MOJO | Data-only/opaque formats: named for format allowlists; full exfiltration scan applies (NeMo/MOJO archives recursed) |
| **Exfiltration engine** | *all files* | Webhook endpoints (Slack/Discord/Telegram), hard-coded IP:port, non-allowlisted URLs, cloud/API credentials (AWS, GitHub, HF, OpenAI, private keys, JWTs), embedded source with network/exec/shell idioms, base64/hex/**base32**/**base85**-encoded payloads (decoded and re-analyzed, incl. one **gzip/zlib** layer), **single-byte XOR-obfuscated** endpoints/commands (recovered by a key-invariant delta-signature search, no brute force), and **UTF-16 (wide) strings** that hide indicators from ASCII scans. Scans in bounded windows with a per-file finding cap; benign-host allowlist is configurable/strict-able (see env table). |

## How Purser compares

Where Purser sits *relative to* the ML model scanners: these tools are point
analyzers, Purser is the control plane above them — several are things Purser
can **ingest** rather than compete with (the Hub runs picklescan and Guardian;
their verdicts arrive as signals on `hf://` scans). The comparison below is on
the scanning axis only. Legend: ✅ yes · ◐ partial/limited ·
❌ no · ❔ not public. Best-effort assessment of publicly documented features as of
**July 2026** — projects evolve; verify before relying on a cell.

| Capability | **Purser** | picklescan | Fickling | ModelScan | ModelAudit | Commercial¹ |
|---|:---:|:---:|:---:|:---:|:---:|:---:|
| License | Apache-2.0 | OSS | OSS | OSS | OSS | Commercial |
| Pickle opcode malware scan | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Format breadth² | ✅ 35+ | ◐ 4 | ❌ pickle only | ◐ 3 | ✅ 30+ | ✅ |
| Safetensors / GGUF / ONNX / TFLite | ✅ | ❌ | ❌ | ❌ | ✅ | ✅ |
| Data-exfil & secret detection³ | ✅ | ❌ | ❌ | ❌ | ◐ | ◐ |
| `trust_remote_code` Python (AST) + `auto_map` | ✅ | ❌ | ❌ | ❌ | ◐ | ◐ |
| Policy engine (severity / format / publisher / name) | ✅ | ❌ | ❌ | ❌ | ◐ | ✅ |
| Country-of-origin restriction | ✅ | ❌ | ❌ | ❌ | ❌ | ◐ |
| Cryptographic signing / verified provenance⁴ | ✅ | ❌ | ❌ | ❌ | ❌ | ◐ |
| CLI | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| REST API server | ✅ | ❌ | ❌ | ❌ | ◐ | ✅ |
| SARIF output | ✅ | ❌ | ❌ | ❌ | ❌ | ◐ |
| Docker + Kubernetes deploy | ✅ | ❌ | ❌ | ❌ | ◐ | ◐ |
| Deploy-time enforcement (CI action + K8s admission webhook) | ✅ | ❌ | ❌ | ❌ | ❌ | ◐ |
| Ingests upstream/third-party scanner verdicts (plugin signals) | ✅ | ❌ | ❌ | ❌ | ❌ | ◐ |
| CVE feeds / behavioral backdoor / dashboards | ❌⁵ | ❌ | ❌ | ❌ | ❌ | ✅ |

¹ Protect AI **Guardian** (built on ModelScan) and **HiddenLayer Model Scanner** —
enterprise platforms; capabilities vary and are gated behind licensing.
² ~35 distinct formats identified and policy-gated — a dedicated scanner where the
format carries code/graph (pickle, Keras, ONNX, TF, GGUF, CoreML, OpenVINO, Caffe,
TorchServe `.mar`, MLflow, …), and format-ID + exfil for data-only blobs (GGML,
MXNet, GBM, TensorRT, Darknet, LightGBM, Torch7, …). For a few opaque ones
(TensorRT, MXNet) it stays format-ID + exfil rather than deep graph parsing —
where **ModelAudit** still has more per-format scanner depth (e.g. TensorRT).
Pick it if that depth matters more than policy/provenance.
³ Embedded endpoints, credentials, webhooks, and encoded/compressed payloads across
*all* file types — Purser's most distinctive engine; peers focus on code, not
exfiltration strings.
⁴ Purser verifies **user-signed** Ed25519 signatures against a trust store that
binds keys to publisher + country (with revocation/validity), **and Sigstore
(Fulcio/Rekor) bundles** for verified external-root identity (offline). Commercial
tools track provenance/lineage (AIBOM) but not user-controlled signature verification.
⁵ No *built-in* feeds or dashboards — but external feeds can plug in as
[signal sources](#signal-sources-upstream-intelligence); the honest ❌ is for
what ships in the box.

**Honest take:** Purser's edge is the combination of broad format coverage, the
exfiltration engine, `trust_remote_code` AST analysis, and a **policy +
verified-provenance + enforcement** layer (country-of-origin, model signing,
CI/admission gating) that also *aggregates* other analyzers' verdicts as
signals — in one OSS tool. It is *not* a substitute for commercial platforms
where you need built-in CVE/threat-intel feeds, ML-behavioral backdoor
detection, dashboards, or vendor support;
and **ModelAudit** is an excellent, more mature pure-scanner alternative if you don't
need policy/provenance. All static scanners — this one included — can be evaded by
novel pickle gadgets; treat a clean scan as
necessary, not sufficient.

> **Reproducible numbers.** These rows aren't just asserted — a head-to-head
> harness runs Purser and the OSS peers over a shared known-answer corpus and
> publishes detection / miss / false-positive figures: **100% detection on the
> known-answer set and 0% false positives across 79 benign artifacts (75 real
> HuggingFace models)** as last measured; see
> [`benchmarks/`](benchmarks/README.md#latest-measured). A weekly CI job
> re-measures and fails on any regression.

## Policy engine

Policies are YAML. Everything is user-defined:

```yaml
version: 1
name: strict
fail_on:
  severity: MEDIUM          # findings at/above this severity fail the scan
formats:
  mode: blocklist           # off | allowlist | blocklist  ("model types")
  list: [pickle, joblib, pytorch_legacy]
origin:
  mode: blocklist           # off | allowlist | blocklist
  countries: [CN, RU, KP, IR]   # ISO 3166-1 alpha-2
  unknown_origin: deny      # allow | warn | deny
publishers:
  blocked: [some-org]
  allowed: []               # non-empty => allowlist
models:                     # block/allow by model NAME (glob, case-insensitive)
  mode: blocklist           # off | allowlist | blocklist
  patterns:                 # matched against repo id (full + last component)
    - "evilcorp/*"          #   and the scan target's basename
    - "*-backdoor"
    - "known-cve-model"
denylist:                   # known-bad IOCs — any match is BLOCKED
  hashes: ["sha256:<hex>"]  # exact file-content SHA-256s
  publishers: ["evil-*"]    # publisher globs
  models: ["*/nullif-ai*"]  # repo/name globs
  files: [/feeds/bad.txt]   # external hash feeds (one digest per line),
                            #   re-read every scan — refresh like AV signatures
max_file_size_mb: 51200
rules:                      # per-rule overrides
  - id: PICKLE_UNKNOWN_IMPORT
    action: deny            # deny | warn | ignore
```

**Country of origin** is resolved in order: **a verified signature** (see
below) → explicit `--origin` flag / API field → sidecar `provenance.yaml` next
to the model → publisher lookup in the bundled database of ~70 known model
publishers (`purser origins`), extendable via
`PURSER_ORIGINS=/path/origins.yaml`. Unknown origins are allowed, warned, or
denied per policy.

**Model name** matching (the `models` block) compares glob patterns against the
model's repo id (full and last component) and the scan target's basename. For a
local file/dir, tag it with `--repo-id org/name` so name policies apply:
`purser scan ./model --repo-id evilcorp/badmodel`.

**Known-bad denylist** (the `denylist` block) is the AV-signature analogue for
model artifacts: exact content hashes, publisher globs, and repo globs that
always `BLOCK`. `denylist.files` points at external feed files (bare hex or
`sha256:` lines, `#` comments) that are **re-read on every scan**, so an
updated feed — a remounted ConfigMap, a synced IOC list — takes effect without
a policy reload. Populate it from upstream `unsafe` verdicts, incident
response, or your own curation.

Example policies live in [`policies/`](policies/): `default.yaml`,
`strict.yaml`, `allowlist-us-eu.yaml`, `signed-only.yaml`.

## Verified provenance (model signing)

Without a signature, an origin/publisher claim is *self-asserted* and
spoofable. Purser adds Ed25519 signing so origin can be a **cryptographic
fact**: the signer signs a manifest of every file's SHA-256; verification
recomputes it, requires an exact match (tamper/added-file detection), and
checks the signature against a **trust store** that binds each signing key to a
verified publisher + country.

```bash
pip install "purser[sign]"                  # or use the Docker image
purser keygen --out mykey               # Ed25519 keypair
purser sign model.safetensors --key mykey.key --key-id acme-2026
# add mykey.pub to trust_store.yaml (see policies/trust_store.example.yaml)
export PURSER_TRUST_STORE=/etc/purser/trust_store.yaml
purser verify model.safetensors         # VERIFIED / INVALID / UNTRUSTED / UNSIGNED
```

A **verified** signature outranks any claimed origin (a caller passing
`--origin US` cannot override a signature that binds the model to `CN`). An
**invalid, untrusted, revoked, or expired** signature is itself a finding. Trust
-store entries support key lifecycle — `revoked: true` and `not_before` /
`not_after` validity windows (checked against the signature's `created`
timestamp). Set `origin: { require_signed: true }` in a policy (see
`signed-only.yaml`) to **reject anything not validly signed by a trusted key** —
this is what turns country-of-origin from a label into an enforced control.

### Verified identity via Sigstore (external trust root)

The Ed25519 trust store binds `key → publisher` by *operator assertion*. For a
**verified external root**, Purser also verifies **Sigstore** (Fulcio/Rekor)
bundles: identity comes from a Fulcio-attested OIDC subject logged in Rekor's
transparency log — the same keyless model the project uses to sign its *own*
artifacts, and the format HuggingFace model-signing emits. Verification is
**offline**, against a vendored trust root (no network at scan time).

```bash
pip install "purser[sigstore]"
# sign externally with cosign/sigstore (keyless OIDC), producing a bundle:
cosign sign-blob model.safetensors --bundle model.safetensors.sigstore.json
purser verify model.safetensors     # reports the verified issuer + identity (SAN)
```

Place the bundle beside the model (`<file>.sigstore.json`, or
`model.sigstore.json` in a directory — signed over the canonical manifest). A
verified identity satisfies `require_signed`, and an `identity` policy pins *who*
may sign (issuer + SAN globs):

```yaml
identity:
  mode: allowlist                 # off | allowlist | blocklist
  issuers: ["https://token.actions.githubusercontent.com"]
  identities: ["https://github.com/purser-io/*"]   # SAN globs
```

Refresh the vendored trust root if Sigstore rotates its roots:
`make sigstore-trust-root` (needs `purser[sigstore]` + network). Signing stays
external — keyless signing needs a browser/OIDC flow. Legacy HuggingFace **GPG
commit** signatures are online-only and out of scope for offline verification.

## Install and CLI usage

Purser ships on two channels — the **PyPI package** (with optional extras) and
**prebuilt container images** on GHCR. Pick by how you run it:

**From PyPI** — one package, optional extras (`pip install "purser[<extra>]"`):

| Extra | Adds | Enables |
|---|---|---|
| *(none)* | core scanner, CLI, REST API | scanning + policy + signal sources + admission webhook |
| `sign` | `cryptography` | Ed25519 signing / verification |
| `sigstore` | `sigstore` | verified-identity (Fulcio/Rekor) provenance |
| `hf` | `huggingface_hub` | `purser scan hf://org/model` (+ upstream-verdict signals) |
| `h5` | `h5py` | deeper Keras `.h5` parsing |
| `deep` | *(no extra deps)* | gadget-chain / weight-tampering analyzers in-process |

Extras combine, e.g. `pip install "purser[sign,hf]"`.

**From GHCR** — prebuilt, signed, multi-arch images (`docker pull ghcr.io/purser-io/<image>`):

| Image | Contents | For |
|---|---|---|
| `purser` | core | scan service / CLI |
| `purser-hf` | core + `[hf]` extra | HuggingFace worker (Helm `hf.enabled`) |
| `purser-deep` | deep analyzers | gadget-chain / tampering companion (Helm `deep.enabled`) |

The `-hf` / `-deep` images simply pre-bundle what you'd otherwise add as a PyPI
extra — same capability, different distribution channel.

```bash
pip install "purser[sign]"    # or "purser[sign,hf]"; see the extras table above
purser scan model.pt
purser scan ./model-dir --policy policies/strict.yaml
purser scan hf://deepseek-ai/DeepSeek-R1 --policy policies/strict.yaml   # needs [hf]
purser scan model.pkl --origin CN --format json -o report.json
purser scan model.pkl --format sarif > report.sarif                     # CI integration
purser policy-check policies/strict.yaml
purser origins deepseek-ai
```

Exit codes: `0` pass/warn · `1` findings ≥ fail threshold · `2` blocked by
policy (origin/format/publisher/name/signing) · `3` error.

## REST API

```bash
uvicorn purser.api:app --host 0.0.0.0 --port 8080
```

| Endpoint | Purpose |
|---|---|
| `GET /healthz` | liveness (never authenticated) |
| `GET /metrics` | Prometheus metrics (unauthenticated; see Observability) |
| `GET /v1/policy` | effective policy (from `PURSER_POLICY`) |
| `GET /v1/origins` | publisher → country database |
| `POST /v1/scan/upload` | multipart upload scan |
| `POST /v1/scan/path` | scan a mounted path (restricted to `PURSER_SCAN_ROOT`) |
| `POST /v1/scan/huggingface` | download + scan an HF repo (off unless enabled) |

```bash
export PURSER_API_KEY=$(openssl rand -hex 32)
curl -H "X-API-Key: $PURSER_API_KEY" \
  -F "file=@model.pt" http://localhost:8080/v1/scan/upload | jq .verdict
```

### Security-relevant environment variables

| Variable | Default | Effect |
|---|---|---|
| `PURSER_API_KEY` | *(unset)* | If set, all `/v1` endpoints require it via `Authorization: Bearer <key>` or `X-API-Key`. Comma-separated list accepted. Unset = open (trusted-network only). |
| `PURSER_MAX_CONCURRENT_SCANS` | `4` | In-flight scan cap; excess requests get HTTP 429. |
| `PURSER_RATE_LIMIT_RPM` | `0` | Per-client (API key, else IP) requests/minute; `0` disables. Over-limit → HTTP 429 with `Retry-After`. |
| `PURSER_MAX_UPLOAD_MB` | `10240` | Upload size ceiling (HTTP 413 beyond). |
| `PURSER_MAX_SCAN_MB` | `4096` | Bytes scanned per file for exfil; a `SCAN_TRUNCATED` finding is emitted if a file exceeds it. |
| `PURSER_MAX_FINDINGS_PER_FILE` | `500` | Cap on findings per file (bounds memory/output on adversarial input). |
| `PURSER_EXFIL_STRICT` | `0` | `1` disables the benign-URL allowlist entirely — every embedded URL is flagged. |
| `PURSER_EXFIL_ALLOWLIST` | *(unset)* | Comma-separated hosts that **replace** the built-in benign-URL allowlist. |
| `PURSER_EXFIL_ALLOWLIST_ADD` | *(unset)* | Comma-separated hosts **added** to the built-in allowlist. |
| `PURSER_EXFIL_XOR` | `1` | `0`/`false` disables single-byte-XOR de-obfuscation of embedded payloads. |
| `PURSER_ENABLE_HF` | `0` | Must be `1`/`true` to enable `POST /v1/scan/huggingface`. |
| `PURSER_HF_ALLOWLIST` | *(empty)* | Comma-separated `org/` or `org/repo` prefixes permitted for the HF endpoint once enabled. |
| `PURSER_ENABLE_DEEP` | `0` | Must be `1`/`true` to run the deep-analysis companion (see below). |
| `PURSER_DEEP_URL` | *(empty)* | Base URL of the `purser-deep` service. If enabled but empty, the core runs the analyzers in-process when the package is importable. |
| `PURSER_SIGNALS` | `1` | Disables all [signal sources](#signal-sources-upstream-intelligence) when falsy (`0`/`false`/`no`/`off`). Network-using built-ins run only on hub-fetched scans; the offline `loader-cves` source runs on every scan; third-party plugins decide their own applicability. |
| `PURSER_SIGNAL_<NAME>` | `1` | Per-source gate, name upper-cased with `-`/`.` → `_` (e.g. `PURSER_SIGNAL_HF_VERDICTS=0`). |
| `PURSER_SIGNAL_TIMEOUT_SECONDS` | `10` | HTTP timeout per signal-source request. |
| `PURSER_CARD_ATTESTATIONS` | `0` | `1`/`true`/`yes`/`on` enables the opt-in model-card / eval-attestation gate on hub scans. Distinct from the generic per-source gate `PURSER_SIGNAL_CARD_ATTESTATIONS` — both must be enabled for the gate to run. |
| `PURSER_AUTO_APPROVE` | `0` | `1` auto-populates the admission webhook's approved-digest list from verdicts: verdicts in `PURSER_AUTO_APPROVE_VERDICTS` (default `PASS`) approve each scanned file's sha256; FAIL/BLOCKED revokes. |
| `PURSER_APPROVALS_PATH` | *(unset)* | File backend for auto-approval (the exact format the webhook reads — commit/sync it into the ConfigMap via GitOps). |
| `PURSER_APPROVALS_CONFIGMAP` | *(unset)* | In-cluster backend: name of the ConfigMap to patch via the K8s API (ServiceAccount token; the Helm chart's `admission.autoApprove.enabled` wires this + RBAC). Also: `_KEY` (default `approved.txt`), `_NAMESPACE`. |
| `PURSER_SCAN_ROOT` | `/models` | Path-scan confinement root. |
| `PURSER_METRICS_ENABLED` | `1` | `0`/`false` disables the `/metrics` endpoint. |
| `PURSER_AUDIT` | `off` | `stdout` or `syslog` to emit a JSON audit record per scan. |
| `PURSER_SYSLOG_ADDRESS` | `/dev/log` | Syslog target when `PURSER_AUDIT=syslog`: a socket path or `host:port` (UDP). |
| `PURSER_SYSLOG_FACILITY` | `user` | Syslog facility name. |
| `PURSER_SIGSTORE_TRUST_ROOT` | *(vendored)* | Path to a Sigstore `trusted_root.json` for offline verification; defaults to the bundled root (`make sigstore-trust-root` to refresh). |

## Observability

**Metrics (Prometheus).** The API exposes `GET /metrics` in the Prometheus text
format (no extra dependency — a tiny built-in registry). Series are chosen for a
security dashboard:

| Metric | Type | Labels | Answers |
|---|---|---|---|
| `purser_scans_total` | counter | `verdict` | pass/fail/blocked rate |
| `purser_findings_total` | counter | `severity` | how severe |
| `purser_findings_by_category_total` | counter | `category` | **what kind of threat** (code-execution, exfiltration, secret, steganography, gadget, …) |
| `purser_policy_blocks_total` | counter | `reason` | **why blocked** (origin, format, publisher, name, signature) |
| `purser_provenance_total` | counter | `status` | signing outcomes (verified/unsigned/invalid/revoked/…) |
| `purser_scans_by_origin_total` | counter | `origin` | **country of origin** mix |
| `purser_scan_files_total` | counter | `format` | which model formats |
| `purser_requests_rejected_total` | counter | `reason` | auth / rate-limit / capacity / oversize |
| `purser_bytes_scanned_total` | counter | — | throughput |
| `purser_scan_errors_total` | counter | — | scanner/analyzer errors |
| `purser_scans_in_progress` | gauge | — | live concurrency |
| `purser_scan_duration_seconds` | histogram | — | latency (p50/p95) |
| `purser_build_info` | gauge | `version` | running version |

```yaml
# prometheus scrape_config
- job_name: purser
  static_configs: [{ targets: ["purser:8080"] }]
```

Label cardinality is bounded (verdicts, severities, ~35 formats, ~20 categories,
ISO country codes). `/metrics` is unauthenticated by design (scrapers usually
are) — **network-restrict it** or disable with `PURSER_METRICS_ENABLED=0`.

**Grafana.** Import [`deploy/grafana/purser-overview.json`](deploy/grafana/purser-overview.json)
— panels for verdict rate, threat categories, policy blocks by reason,
provenance status, origin-country mix, format mix, request rejections, p95
latency, and in-flight scans.

<p align="center">
  <img src="https://raw.githubusercontent.com/purser-io/purser/main/assets/grafana-dashboard.png" alt="Purser Grafana dashboard: verdict rates, findings by threat category, policy blocks by reason, provenance status, country-of-origin and format mix, API rejections, throughput, and in-flight scans" width="100%" />
</p>

Example PromQL:

```promql
sum by (verdict)  (rate(purser_scans_total[$__rate_interval]))          # verdict rate
sum by (category) (rate(purser_findings_by_category_total[5m]))         # threats seen
sum by (reason)   (rate(purser_policy_blocks_total[5m]))                # why blocked
histogram_quantile(0.95, sum by (le) (rate(purser_scan_duration_seconds_bucket[5m])))
```

**Audit log (syslog / SIEM).** Set `PURSER_AUDIT=syslog` (or `stdout`) to emit one
JSON record per scan — verdict, severity counts, origin/publisher, provenance,
duration, and finding rule-ids — ready for a SIEM:

```bash
PURSER_AUDIT=syslog PURSER_SYSLOG_ADDRESS=logs.internal:514 uvicorn purser.api:app ...
# {"ts":"...","event":"model_scan","target":"model.pkl","verdict":"FAIL",
#  "severity_counts":{...},"finding_rule_ids":["PICKLE_DANGEROUS_IMPORT"], ...}
```

Both are driven from the central scan path, so the CLI and the API report
identically.

## Authentication and API keys

> [!WARNING]
> The API is **open by default** (no key required) — intended for a trusted
> network only. Set `PURSER_API_KEY` before exposing it.

Set `PURSER_API_KEY` to require a key on every `/v1` endpoint (`/healthz` and
`/metrics` stay open for probes/scrapers). Keys are compared in constant time.
The same key also guards the HF worker and the deep companion.

**1. Generate a key**
```bash
openssl rand -hex 32
```

**2. Set it on the server** — via env directly, a `.env` file for
`docker-compose`, or a Kubernetes Secret (`deploy/k8s/secret.yaml`):
```bash
export PURSER_API_KEY=<key>
# k8s: kubectl -n purser create secret generic purser-auth \
#        --from-literal=api-key="$(openssl rand -hex 32)"
```

**3. Send it from clients** — either header works:
```bash
curl -H "X-API-Key: <key>"            ...        # or
curl -H "Authorization: Bearer <key>" ...
```

**4. Rotate with zero downtime** — `PURSER_API_KEY` accepts a
**comma-separated list, and every listed key is valid at once**. To rotate:

1. Add the new key alongside the old: `PURSER_API_KEY=<old>,<new>` and
   restart/redeploy.
2. Move clients over to `<new>`.
3. Drop `<old>`: `PURSER_API_KEY=<new>` and restart/redeploy.

No request is rejected during the overlap. Use a distinct key per consumer if
you want to revoke one without affecting the others (remove just that entry).
Rotate keys the same way you would any secret, and store them in a secret
manager — never in the repo.

## Docker

Two images, so the service that handles hostile uploads carries the smallest
possible dependency surface:

- **`Dockerfile`** — slim **core** scanner (29 pinned deps, no `huggingface_hub`,
  no outbound HTTP-client stack). This is the default.
- **`Dockerfile.hf`** — **HF worker** (core + `huggingface_hub`, 38 deps) for
  the optional `POST /v1/scan/huggingface` download path. Run it only where you
  need it, ideally on a separate egress-restricted node.

Both are **multi-stage builds on a digest-pinned [Wolfi](https://github.com/wolfi-dev)
base** (Chainguard's minimal, glibc, low-CVE distro): a build stage installs
dependencies from **hash-pinned lockfiles** with `pip install --require-hashes`
into a virtualenv, and the final stage copies only that venv onto a
python-runtime-only Wolfi image — no pip, compilers, or build tooling ship in
the running container, which runs as non-root `10001:10001`. Update the base pin
with `make base-digest`.

```bash
# Pull the published, signed, multi-arch image (also -hf and -deep variants):
docker run --rm -v $PWD/models:/models:ro -v $PWD/policies:/policies:ro \
  -e PURSER_POLICY=/policies/strict.yaml -p 8080:8080 \
  ghcr.io/purser-io/purser:0.2.1
# one-shot CLI scan:
docker run --rm -v $PWD/models:/models:ro \
  ghcr.io/purser-io/purser:0.2.1 purser scan /models

# …or build locally: make build (core) · make build-hf · make build-deep → purser:dev
```

Or `docker compose up` (see `docker-compose.yml`).

## Deep analysis (optional companion)

`purser-deep` is a **separate, opt-in service/container** for the heavier
checks the core deliberately leaves out (so they stay off the core's
hostile-input path). Enable it from the core with
`PURSER_ENABLE_DEEP=1` + `PURSER_DEEP_URL=http://purser-deep:8090`
(or run in-process if the `purser_deep` package is importable). Its findings
merge into the normal report and count toward the policy verdict.

| Analyzer | Finds |
|---|---|
| Gadget-chain (`deep.gadget`) | Pickle **gadget composition** — indirection pivots (`getattr`/`operator`/`functools`), complex object graphs, deep attribute imports — that use individually-innocent pieces to evade import allowlists. |
| Weight tampering (`deep.weights`) | **Steganography** — data hidden in the low-bit plane of float tensors (invisible to a normal scan; found by running the exfil engine over the extracted low bytes) — plus non-finite/garbage weights and shape/size mismatches. Static, from safetensors/NumPy; the model is never loaded. |

```bash
make build-deep
PURSER_ENABLE_DEEP=1 PURSER_DEEP_URL=http://purser-deep:8090 \
  docker compose --profile deep up
```

**Honest scope:** these are higher-recall, higher-false-positive *heuristics* —
a strong second opinion, not a gate on their own. They do **not** detect
*trained* backdoors / data poisoning (learned behavior), which needs
model-evaluation tooling and stays out of scope. CVE feeds and volumetric-DoS
protection are also out of scope (use an edge WAF / scanner platform).

## Signal sources (upstream intelligence)

As a control plane, Purser's verdict aggregates **signals** — and external
intelligence about an artifact plugs into the same policy engine as the
built-in scanners. Signal findings appear as `signal_findings` in the report,
count toward the verdict, and can be tuned per rule with the normal policy
`rules:` overrides.

**Built-in: HuggingFace Hub scan verdicts** (`hf-verdicts`). When scanning an
`hf://` target (CLI) or via `POST /v1/scan/huggingface`, Purser also reads the
Hub's own per-file scan verdicts (the Hub runs picklescan, ClamAV, Protect AI
Guardian, JFrog, and VirusTotal over uploads) and surfaces any upstream
`unsafe` / `caution` verdict as a corroborating finding
(`HF_UPSTREAM_UNSAFE` HIGH / `HF_UPSTREAM_SUSPICIOUS` MEDIUM), recording
which upstream scanners flagged the file as evidence:

```bash
purser scan hf://org/model        # Purser's own analysis + the Hub's verdicts
```

Two rules keep this honest:

- **Upstream `unsafe` is a signal; upstream `safe` is not.** Hub scanners have
  documented false negatives, so a clean upstream verdict never downgrades or
  masks what Purser's own analysis found.
- **No new network paths from the built-ins.** The built-in sources only run
  when the artifact was fetched from a hub in the first place (the `-hf` path,
  where network is already gated); plain local scans stay fully offline. If
  verdicts can't be fetched, the gap is visible as a `SIGNAL_UNAVAILABLE`
  finding rather than silently missing coverage. Third-party plugins you
  install can add their own network paths — audit a plugin before enabling it,
  and pin `PURSER_SIGNAL_<NAME>=0` for any you don't want.

**Built-in: model-card / eval-attestation gate** (`card-attestations`,
**opt-in**: `PURSER_CARD_ATTESTATIONS=1`). For organizations that want models
to *document themselves*: on hub scans it checks the declared model card and
`model-index` eval results and surfaces their **absence** as LOW findings
(`CARD_MISSING`, `CARD_NO_EVAL_RESULTS`) — a WARN-level nudge by default that
policy `rules:` can `ignore` or escalate to `deny` (undocumented model →
`BLOCKED`). It gates the *attestation*, not the behavior: declared metrics are
claims, not proof of safety, and presence of a card never improves a verdict.

**Built-in: loader-CVE mapping** (`loader-cves`, **offline** — the first
signal that runs on *local* scans too). No feed of malicious models exists,
but framework loader CVEs are public: when an artifact **declares** a
framework version (e.g. `keras_version` in a `.keras`/`.h5` file) that falls
in the affected range of a known load-time RCE (Keras `safe_mode` bypasses
CVE-2025-9906/-9905, Lambda-layer CVE-2024-3660), a LOW `LOADER_CVE` advisory
is emitted from the vendored, curated dataset
(`purser/data/loader_cves.yaml`). It fires only on a declared in-range
version — never as blanket per-format noise — and says plainly that the
*loader* is what's exposed, not that the artifact is malicious.

**Writing your own.** Third-party sources register via the `purser.signals`
entry-point group — expose a zero-arg factory returning an object with
`name`, `available(ctx)`, and `collect(ctx) -> list[Finding]`:

```toml
# your plugin's pyproject.toml
[project.entry-points."purser.signals"]
my-feed = "my_pkg.purser_plugin:MyFeedSource"
```

Sources must never raise (report trouble as a finding), and may only *add*
findings — a source cannot suppress another signal or downgrade the verdict.
Disable all sources with `PURSER_SIGNALS=0`, or one with
`PURSER_SIGNAL_<NAME>=0` (e.g. `PURSER_SIGNAL_HF_VERDICTS=0`).

## Supply chain (of Purser itself)

A security tool should be verifiable. `make` targets and `.gitlab-ci.yml` cover:

| Concern | How |
|---|---|
| Reproducible deps | `make lock` writes hash-pinned `requirements*.lock`; images use `--require-hashes`; `make lock-verify` is a CI gate that fails on drift |
| SBOM | `make sbom` emits deterministic CycloneDX 1.5 (`sbom/*.cdx.json`) from the lockfiles — no build timestamp, so it's reproducible and diffable |
| Dependency isolation | HF tree split into a separate image (above) |
| Signed images | CI signs with **cosign keyless** (Fulcio/Rekor) and attaches the SBOM as a CycloneDX attestation on release tags; verify with `cosign verify` / `make verify-sig` |
| Vuln scanning | `make scan` runs `trivy` against the image (HIGH/CRITICAL gate) |

## Kubernetes

**Recommended: the Helm chart** ([`deploy/helm/purser/`](deploy/helm/purser/)) —
production-ready, with hardened securityContext, HPA/PDB, ServiceMonitor,
NetworkPolicy, a values-driven policy ConfigMap, generated/retained API-key
Secret, and optional HF-worker + deep-companion subcharts (auto-wired):

```bash
# published OCI chart (defaults to the ghcr.io/purser-io/purser images)…
helm install purser oci://ghcr.io/purser-io/charts/purser --version 0.2.1 \
  -n purser --create-namespace
# …or from a source checkout: helm install purser deploy/helm/purser ...
helm test purser -n purser
```

See the [chart README](deploy/helm/purser/README.md) and
[`values.yaml`](deploy/helm/purser/values.yaml).

**Or plain kustomize manifests** under [`deploy/k8s/`](deploy/k8s/) for a
kubectl-only setup:

```bash
kubectl apply -k deploy/k8s
```

Both run non-root with a read-only root filesystem, no privilege escalation, and
`/healthz` probes; policy is a mounted ConfigMap (change it without rebuilding);
mount a model-store PVC at `/models` for `POST /v1/scan/path`.

**Deploy-time enforcement (`admission.enabled=true`).** An optional
`ValidatingAdmissionWebhook` closes the scan→deploy TOCTOU gap: scanning proves a
model was safe *when scanned*; the webhook enforces at *admission* that every
container image is pinned by `@sha256:` digest and that any model a workload
declares (annotation `purser.io/models`) is on the **approved-digest** list — the
SHA-256s of models that passed a scan. Opt-in per namespace/pod and fail-closed
by default; see the [chart README](deploy/helm/purser/README.md#admission-webhook-deploy-time-enforcement).

**Closing the loop (`admission.autoApprove.enabled=true`).** The approved list
can populate itself from verdicts instead of being operator-managed: a `PASS`
at any scan endpoint approves each scanned file's digest into the webhook's
ConfigMap (narrow RBAC — get/patch on that one ConfigMap), and a later
`FAIL`/`BLOCKED` on the same artifact **revokes** it. Scan → approve → admit,
with no manual hop; every action is recorded in the report's
`metadata.approvals` and the audit log. Outside Kubernetes the same mechanism
writes a file (`PURSER_APPROVALS_PATH`) you can GitOps into the ConfigMap.

## Security model

- Models are **never loaded**: pickle streams are analyzed with
  `pickletools.genops`, archives are size/ratio-checked before reading,
  H5/protobuf/GGUF are inspected at byte level.
- The scanning service is designed to handle **hostile files**: zip-bomb and
  path-traversal guards, upload size caps, bounded windowed scanning with a
  per-file finding cap, scan-root confinement for path scans, non-root
  read-only container.
- It is also designed against **hostile clients**: optional API-key auth on all
  `/v1` endpoints, a concurrency cap (HTTP 429 when full), and an
  off-by-default, allowlist-scoped HuggingFace download endpoint.
- **Provenance** can be cryptographically verified (Ed25519 signing + trust
  store); a `require_signed` policy makes country-of-origin an enforced control.
- **Signals are add-only and untrusted.** A signal source can only *add*
  findings — the plugin context deliberately excludes the in-progress report,
  so no signal can suppress or downgrade another finding. Signal responses are
  parsed as JSON, never executed; the built-ins make network calls only on
  hub-fetched scans; third-party plugins are operator-installed code
  (audit before enabling).
- **Deploy-time enforcement fails closed.** The admission webhook defaults to
  `failurePolicy: Fail` and is opt-in per namespace — an outage blocks
  opted-in deploys rather than waving them through.
- A finding severity model (`INFO → CRITICAL`) feeds the policy verdict:
  `PASS / WARN / FAIL / BLOCKED / ERROR`.
- Honest limits: static
  scanning cannot *prove* safety (novel pickle gadgets, weight/backdoor
  poisoning are out of scope), so use it as one layer of defense-in-depth.

## Development

```bash
uv venv && uv pip install -e ".[dev]"
pytest
```

## Roadmap and security posture

- [`CHANGELOG.md`](CHANGELOG.md) — released versions and what each one shipped.
- [`ROADMAP.md`](ROADMAP.md) — what's next and why (foundation readiness: CNCF
  Landscape entry — the OpenSSF Best Practices badge is already **earned**;
  the `purser-eval` companion; Wolfi base auto-refresh). The external-PKI/
  Sigstore trust root, per-format scanner depth, the adversarial evasion
  benchmark, the pluggable signal sources (`purser.signals`), and the
  Kubernetes admission webhook have shipped.
- [`SECURITY.md`](SECURITY.md) — disclosure policy + SME security evaluation of
  the code and container images (threat model, hardening, residual risk).
- [`docs/openssf-best-practices.md`](docs/openssf-best-practices.md) — OpenSSF
  Best Practices **passing**-criteria self-assessment (each mapped to evidence).

## Contributing

Issues and merge/pull requests are welcome. Please run `ruff check` and `pytest`
before submitting, keep changes covered by tests, and report security issues
privately per [`SECURITY.md`](SECURITY.md) (not via a public issue).

## License

Licensed under the [Apache License 2.0](LICENSE) — Copyright © 2026 The Purser
Authors. Bundled third-party dependencies and their licenses are listed in
[`THIRD_PARTY_LICENSES.md`](THIRD_PARTY_LICENSES.md) (auto-generated from the
SBOM via `make licenses`; all permissive, no copyleft beyond MPL-2.0/certifi).

Product names, logos, and brands referenced here (e.g. ModelScan, picklescan,
Fickling, ModelAudit, Protect AI Guardian, HiddenLayer, Kubernetes, GitLab,
Hugging Face) are trademarks of their respective owners; see
[`TRADEMARKS.md`](TRADEMARKS.md) for use of the Purser name and logo.
