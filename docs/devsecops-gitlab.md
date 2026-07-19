# Purser in GitLab — Setup Guide

**Audience:** a DevSecOps engineer (any experience level) who wants model files
scanned automatically in GitLab, and bad ones to fail the pipeline. Follow the
steps top to bottom; copy-paste is fine.

**What you'll build:** a GitLab CI job that runs Purser on your model files
every push. If a model contains hidden code, leaked secrets, or breaks a rule
you set, the pipeline **fails** and the model doesn't ship.

**Mini-glossary** (used below): *pipeline* = the automated steps GitLab runs on
each push · *job* = one step in a pipeline · *runner* = the machine/agent that
executes jobs · *artifact* = a file a job saves for later · *exit code* = a
number a program returns; `0` means success, anything else means failure ·
*image* = a prebuilt container Purser ships in.

---

## Before you start

You need:

- A GitLab project (self-managed or gitlab.com).
- A runner that can run container images (the default on gitlab.com works).
- The Purser **image**. Two ways to get it:
  - **Build it once** from this repo and push to your GitLab Container Registry
    (Step 1), **or**
  - use an image your platform team already publishes — skip to Step 2 and set
    `PURSER_IMAGE` to it.

Throughout, `PURSER_IMAGE` means the full image name, e.g.
`registry.gitlab.com/your-group/purser:latest`.

---

## Step 1 — Get the Purser image (once)

If nobody has published it yet, build and push it from this repo. Add this job
to the **Purser repo's** `.gitlab-ci.yml` (it already has one you can copy
from), or run locally:

```bash
docker build -t "$CI_REGISTRY_IMAGE/purser:latest" -f Dockerfile .
docker push "$CI_REGISTRY_IMAGE/purser:latest"
```

The image is small, runs as a non-root user, and includes the `purser`
command. That's all your scanning jobs need.

> Tip: pin a specific tag (e.g. a version or commit) instead of `latest` so your
> pipeline results are reproducible.

---

## Step 2 — Add a policy (your team's rules)

A **policy** is a short YAML file describing what's allowed. Commit it to the
repo you want to protect, e.g. at `.purser/policy.yaml`:

```yaml
version: 1
name: team-policy

# Fail the scan if a finding is this severe or worse.
fail_on:
  severity: HIGH

# Only allow safe-by-design file types (no code-carrying formats).
formats:
  mode: allowlist
  list: [safetensors, gguf, onnx]

# Block models by name/source (glob patterns; optional).
models:
  mode: blocklist
  patterns: ["evilcorp/*", "*-backdoor"]
```

Start simple. `fail_on: HIGH` alone is a reasonable first policy. Tighten later.
Ready-made examples live in [`policies/`](../policies/): `default.yaml`
(lenient), `strict.yaml`, `allowlist-us-eu.yaml`, `signed-only.yaml`.

Validate a policy before committing:

```bash
purser policy-check .purser/policy.yaml
```

---

## Step 3 — Add the scan job

In the repo that holds your models, add this to `.gitlab-ci.yml`. It scans a
`models/` folder (change the path to wherever your models live):

```yaml
stages: [security]

scan-models:
  stage: security
  image: registry.gitlab.com/your-group/purser:latest   # your PURSER_IMAGE
  script:
    - purser scan ./models --policy .purser/policy.yaml --format sarif --output purser.sarif
  artifacts:
    when: always
    paths: [purser.sarif]     # keep the report even when the job fails
    expire_in: 30 days
```

**How the gate works:** Purser sets the job's exit code from the verdict, so
GitLab passes or fails the job automatically:

| Exit code | Verdict | Pipeline |
|---|---|---|
| `0` | PASS or WARN | ✅ passes |
| `1` | FAIL (dangerous finding) | ❌ fails |
| `2` | BLOCKED (policy rule) | ❌ fails |
| `3` | ERROR (couldn't scan) | ❌ fails |

No extra scripting needed — a dangerous model turns the pipeline red on its own.

---

## Step 4 — Choose: block vs. warn

- **Block (recommended for production):** leave the job as above. Bad models
  stop the pipeline.
- **Warn only (while you tune the policy):** add `allow_failure: true` to the
  job. It still runs and saves the report, but won't fail the pipeline:

  ```yaml
  scan-models:
    # ...as above...
    allow_failure: true
  ```

A good rollout: start with `allow_failure: true` for a week, review the reports,
then remove it to enforce.

---

## Step 5 — Private or gated model sources (optional)

If your jobs pull models from Hugging Face (including private repos), give the
job a token as a **masked CI/CD variable**:

1. GitLab → your project → **Settings → CI/CD → Variables**.
2. Add `HF_TOKEN`, paste the token, tick **Masked** and **Protected**.

Then a job can scan a remote model directly (use the HF-worker image tag, which
includes download support):

```yaml
scan-remote-model:
  image: registry.gitlab.com/your-group/purser-hf:latest
  script:
    - purser scan hf://your-org/your-model --policy .purser/policy.yaml
```

Keep the download-capable image on trusted runners only — it reaches out to the
internet, which the core scanning image does not.

---

## Step 6 — Run it as a shared service (optional)

Instead of scanning inside every pipeline, some teams run Purser as a small
web service that any pipeline (or person) can send files to. It ships as a
container and Kubernetes manifests. See the top-level README:
[Docker](../README.md#docker) and [Kubernetes](../README.md#kubernetes).

If you expose the service, set an API key so only your pipelines can use it:

- Generate one: `openssl rand -hex 32`.
- Add `PURSER_API_KEY` as a masked CI/CD variable and in the service's
  environment (a Kubernetes Secret is provided in `deploy/k8s/secret.yaml`).
- Callers send it as an `X-API-Key` header (or `Authorization: Bearer <key>`).
- Also set `PURSER_RATE_LIMIT_RPM` to cap requests per client.
- **Rotating a key without downtime:** `PURSER_API_KEY` takes a
  comma-separated list and *all* listed keys work at once. Set it to
  `<old>,<new>`, move clients to `<new>`, then drop `<old>`. Give each consumer
  its own key so you can revoke one without touching the rest. Full details:
  [Authentication & API keys](../README.md#authentication-and-api-keys).

**Want deeper checks?** There's an optional companion service,
`purser-deep`, that adds heavier heuristics (hidden-data/steganography in
weights, advanced pickle tricks). Turn it on with `PURSER_ENABLE_DEEP=1` and
`PURSER_DEEP_URL=http://purser-deep:8090`. It's off by default; see the
README's [Deep analysis](../README.md#deep-analysis-optional-companion) section.

---

## Step 7 — Enforce trusted models (optional, advanced)

If you want "only run models our team signed," your platform team can enable
**signing**:

1. Generate a signing key: `purser keygen --out purser`.
2. Sign approved models: `purser sign model.safetensors --key purser.key --key-id team-2026`.
3. Put the public key in a **trust store** file (see
   [`policies/trust_store.example.yaml`](../policies/trust_store.example.yaml))
   and point jobs at it with the `PURSER_TRUST_STORE` variable.
4. Use `policies/signed-only.yaml` (it sets `require_signed: true`) so unsigned
   or tampered models are rejected.

This turns "who made this model and from where" into something the pipeline can
actually verify, not just trust.

---

## Troubleshooting

- **Job fails with exit code 3 (ERROR):** the target path is wrong or empty.
  Check the `purser scan ./models` path matches where your files are.
- **Everything is BLOCKED:** your policy is stricter than your models. Run
  `purser policy-check` and review `formats`/`models`/`origin` rules. Loosen,
  or switch to `allow_failure: true` while tuning.
- **`huggingface_hub is not installed`:** you used the core image for an
  `hf://` scan. Use the `-hf` image (Step 5) for remote downloads.
- **A large file reports "truncated":** raise `PURSER_MAX_SCAN_MB` (e.g.
  `variables: PURSER_MAX_SCAN_MB: "8192"`).
- **Want machine-readable results elsewhere:** the job saves a SARIF file; you
  can also use `--format json` for a plain report.

---

## Where to go next

- Full options and env vars: [main README](../README.md).
- What Purser does/doesn't protect against: [SECURITY.md](../SECURITY.md).
- Explain the results to your ML teammates:
  [Data scientist guide](data-scientists.md).
