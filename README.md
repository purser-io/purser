<div align="center">

<img src="assets/brand/purser-mark.png" alt="" width="88" />

# Purser

**ML model security scanner with policy-based supply-chain controls.**

[![CI](https://github.com/purser-io/purser/actions/workflows/ci.yml/badge.svg)](https://github.com/purser-io/purser/actions/workflows/ci.yml)
&nbsp;[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
&nbsp;![Version](https://img.shields.io/badge/version-0.1.1-informational.svg)
&nbsp;![Python](https://img.shields.io/badge/python-3.11%2B-3776AB.svg?logo=python&logoColor=white)
&nbsp;![Tests](https://img.shields.io/badge/tests-172%20passing-brightgreen.svg)
&nbsp;![Lint](https://img.shields.io/badge/lint-ruff-000000.svg)
&nbsp;![Status](https://img.shields.io/badge/status-pre--1.0-orange.svg)

</div>

Purser statically scans machine-learning model artifacts for malicious
code and data-exfiltration indicators — taking the best-of-breed techniques
from open-source scanners (modelscan, picklescan) and extending them — and
enforces **user-defined policies**: restrict models by **country of origin**,
**publisher**, **name**, or **model format/type**. Ships as a CLI, a REST API,
container images, and Kubernetes manifests.

Nothing is ever deserialized or executed: all analysis is byte- and
opcode-level.

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
- [Docker](#docker) · [Kubernetes](#kubernetes) · [Deep analysis](#deep-analysis-optional-companion) · [Supply chain](#supply-chain-of-purser-itself)
- [Security model](#security-model) · [Development](#development) · [Docs & security](#roadmap-and-security-posture) · [License](#license)

## Using Purser

**In Kubernetes** — deploy once with the [Helm chart](deploy/helm/purser/), then
scan models against the in-cluster service (rules change via `helm upgrade`, no
rebuild). Two patterns:

```bash
helm install purser oci://ghcr.io/purser-io/charts/purser --version 0.1.1 \
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

A common placement is a **pre-load gate**: a serving controller or model-registry
webhook calls `/v1/scan/upload` and only mounts/serves a model whose verdict is
`PASS`/`WARN`.

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

Use the `-hf` image and `purser scan hf://org/model` to pull + scan a
HuggingFace model (add `HF_TOKEN` as a masked variable for private repos); add
`allow_failure: true` while tuning the policy. Full walkthrough:
[`docs/devsecops-gitlab.md`](docs/devsecops-gitlab.md).

## What it detects

| Engine | Formats | Detections |
|---|---|---|
| Pickle opcode analysis | `.pkl` `.pt` `.pth` `.bin` `.ckpt` `.joblib` `.dill` `.pdparams` | Dangerous imports (`os`, `subprocess`, `eval`, `socket`, `requests`, …) via GLOBAL **and** STACK_GLOBAL resolution, multi-pickle streams, REDUCE invoked-on-load tracking, unknown-import safelist tier, unparseable/evasive pickles |
| PyTorch | zip + legacy checkpoints, `.pt2` (torch.export) | All embedded pickles scanned; `torch.package` embedded Python source flagged |
| ExecuTorch | `.pte` | Flatbuffer identifier validation (extension spoofing) |
| Keras | `.h5`, `.keras` v3 | `Lambda` / `TFOpLambda` layers (marshaled-bytecode execution); works without h5py via byte heuristic |
| TensorFlow | SavedModel `.pb` | `PyFunc`/`EagerPyFunc` (code execution), `ReadFile`/`WriteFile` (file access) graph ops |
| TFLite | `.tflite` | Flex-delegate ops: `FlexPyFunc` (code execution), file-access kernels, full-TF attack surface; magic validation |
| TF.js | `model.json` | Weight-shard path traversal / remote shard references |
| ONNX | `.onnx` | Custom Python operator domains, external-data path traversal |
| safetensors | `.safetensors` | Header validation (spoofed/malformed headers used against parser bugs) |
| GGUF | `.gguf` | **Chat-template (Jinja SSTI) injection** — `__subclasses__`, `os.` access, dynamic code in templates |
| CoreML | `.mlmodel` `.mlpackage` | Custom-layer markers (developer-supplied native code) |
| skops | `.skops` | Schema types run through the pickle dangerous/safe classifier; pickle-fallback loader nodes |
| PaddlePaddle | `.pdmodel` `.pdparams` | `py_func`/`py_layer` ops (code execution); param files scanned as pickles |
| PMML | `.pmml` | XXE entity declarations, Extension elements with script content |
| Bundled Python | `*.py` (`modeling_*.py`, …) | **AST analysis of `trust_remote_code` source** — exec/eval, os/subprocess, sockets & HTTP clients, dynamic import, native code, marshal/pickle, base64/hex deobfuscation, `os.environ` harvesting; module-scope calls escalated (run on import) |
| HF config | `config.json`, `*_config.json` | `auto_map` / `custom_pipelines` / `trust_remote_code` keys that arm remote-code execution, linked to the referenced source files |
| NumPy | `.npy` `.npz` | Object-dtype arrays (embedded pickles) — payload scanned recursively |
| Archives | `.zip` `.tar` `.gz` | Zip-slip path traversal, zip bombs, recursive member scanning (depth-capped) |
| Identified for policy + exfil scan | legacy GGML, Flax/msgpack, MXNet `.params`, OpenVINO IR, XGBoost `.ubj`, CatBoost `.cbm` | Data-only/opaque formats: named for format allowlists; full exfiltration scan applies |
| **Exfiltration engine** | *all files* | Webhook endpoints (Slack/Discord/Telegram), hard-coded IP:port, non-allowlisted URLs, cloud/API credentials (AWS, GitHub, HF, OpenAI, private keys, JWTs), embedded source with network/exec/shell idioms, base64/hex/**base32**-encoded payloads (decoded and re-analyzed, incl. one **gzip/zlib** layer), and **UTF-16 (wide) strings** that hide indicators from ASCII scans. Scans in bounded windows with a per-file finding cap; benign-host allowlist is configurable/strict-able (see env table). |

## How Purser compares

Where Purser sits among ML model scanners. Legend: ✅ yes · ◐ partial/limited ·
❌ no · ❔ not public. Best-effort assessment of publicly documented features as of
**July 2026** — projects evolve; verify before relying on a cell.

| Capability | **Purser** | picklescan | Fickling | ModelScan | ModelAudit | Commercial¹ |
|---|:---:|:---:|:---:|:---:|:---:|:---:|
| License | Apache-2.0 | OSS | OSS | OSS | OSS | Commercial |
| Pickle opcode malware scan | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Format breadth² | ✅ 18+ | ◐ 4 | ❌ pickle only | ◐ 3 | ✅ 30+ | ✅ |
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
| CVE feeds / behavioral backdoor / dashboards | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |

¹ Protect AI **Guardian** (built on ModelScan) and **HiddenLayer Model Scanner** —
enterprise platforms; capabilities vary and are gated behind licensing.
² Distinct formats with a dedicated detector. Purser identifies the most formats,
but for some newer/opaque ones (TensorRT, OpenVINO, MXNet) it does format-ID +
exfil-scan rather than deep graph parsing — where **ModelAudit** has more per-format
scanner depth (e.g. TensorRT, OpenVINO). Pick it if that depth matters more than
policy/provenance.
³ Embedded endpoints, credentials, webhooks, and encoded/compressed payloads across
*all* file types — Purser's most distinctive engine; peers focus on code, not
exfiltration strings.
⁴ Purser verifies **user-signed** Ed25519 signatures against a trust store that
binds keys to publisher + country (with revocation/validity). Commercial tools track
provenance/lineage (AIBOM) but not user-controlled signature verification.

**Honest take:** Purser's edge is the combination of broad format coverage, the
exfiltration engine, `trust_remote_code` AST analysis, and a **policy + verified-
provenance** layer (country-of-origin, model signing) in one OSS tool with API/K8s
deployment. It is *not* a substitute for commercial platforms where you need CVE/
threat-intel feeds, ML-behavioral backdoor detection, dashboards, or vendor support;
and **ModelAudit** is an excellent, more mature pure-scanner alternative if you don't
need policy/provenance. All static scanners — this one included — can be evaded by
novel pickle gadgets; treat a clean scan as
necessary, not sufficient.

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
max_file_size_mb: 51200
rules:                      # per-rule overrides
  - id: PICKLE_UNKNOWN_IMPORT
    action: deny            # deny | warn | ignore
```

**Country of origin** is resolved in order: **a verified signature** (see
below) → explicit `--origin` flag / API field → sidecar `provenance.yaml` next
to the model → publisher lookup in the bundled database of ~90 known model
publishers (`purser origins`), extendable via
`PURSER_ORIGINS=/path/origins.yaml`. Unknown origins are allowed, warned, or
denied per policy.

**Model name** matching (the `models` block) compares glob patterns against the
model's repo id (full and last component) and the scan target's basename. For a
local file/dir, tag it with `--repo-id org/name` so name policies apply:
`purser scan ./model --repo-id evilcorp/badmodel`.

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

## Install and CLI usage

```bash
pip install "purser[sign]"    # +[hf] HuggingFace download, +[h5] h5py; or install from source
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
| `PURSER_ENABLE_HF` | `0` | Must be `1`/`true` to enable `POST /v1/scan/huggingface`. |
| `PURSER_HF_ALLOWLIST` | *(empty)* | Comma-separated `org/` or `org/repo` prefixes permitted for the HF endpoint once enabled. |
| `PURSER_ENABLE_DEEP` | `0` | Must be `1`/`true` to run the deep-analysis companion (see below). |
| `PURSER_DEEP_URL` | *(empty)* | Base URL of the `purser-deep` service. If enabled but empty, the core runs the analyzers in-process when the package is importable. |
| `PURSER_SCAN_ROOT` | `/models` | Path-scan confinement root. |
| `PURSER_METRICS_ENABLED` | `1` | `0`/`false` disables the `/metrics` endpoint. |
| `PURSER_AUDIT` | `off` | `stdout` or `syslog` to emit a JSON audit record per scan. |
| `PURSER_SYSLOG_ADDRESS` | `/dev/log` | Syslog target when `PURSER_AUDIT=syslog`: a socket path or `host:port` (UDP). |
| `PURSER_SYSLOG_FACILITY` | `user` | Syslog facility name. |

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

Label cardinality is bounded (verdicts, severities, ~28 formats, ~20 categories,
ISO country codes). `/metrics` is unauthenticated by design (scrapers usually
are) — **network-restrict it** or disable with `PURSER_METRICS_ENABLED=0`.

**Grafana.** Import [`deploy/grafana/purser-overview.json`](deploy/grafana/purser-overview.json)
— panels for verdict rate, threat categories, policy blocks by reason,
provenance status, origin-country mix, format mix, request rejections, p95
latency, and in-flight scans. Example PromQL:

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
make build           # core image, hash-verified deps
make build-hf        # HF worker image
docker run --rm -v $PWD/models:/models:ro -v $PWD/policies:/policies:ro \
  -e PURSER_POLICY=/policies/strict.yaml -p 8080:8080 purser:dev
# one-shot CLI scan:
docker run --rm -v $PWD/models:/models:ro purser:dev purser scan /models
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
helm install purser oci://ghcr.io/purser-io/charts/purser --version 0.1.1 \
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

- [`SECURITY.md`](SECURITY.md) — disclosure policy + SME security evaluation of
  the code and container images (threat model, hardening, residual risk).
- [`ROADMAP.md`](ROADMAP.md) — deferred/future work (including periodic Wolfi
  base-digest refresh, an external PKI trust root, and deeper detection).

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
