# Purser — Adoption Gap Analysis

Where the code actually is, what the 2026 market looks like, and what is missing
to make Purser **enterprise-adoptable** or **trivially easy for a homelab**.

Distinct from the two existing documents:
[`gap_analysis.md`](gap_analysis.md) assesses *security* of the implementation;
[`MarketResearch.md`](MarketResearch.md) covers *name/logo/licensing*. Neither
answers "why would someone deploy this, and what stops them."

_First reviewed: 2026-09-07 against `main` @ `0d7ef74`_
_Last reconciled: 2026-09-07 against `main` @ `7af2a2b` (after waves 1–3)_

> [!NOTE]
> **This document is maintained, not archived.** Waves 1–3 shipped from it, so
> several findings below are now resolved and are marked as such — the original
> evidence is kept, because it is what motivated the work and what a reader
> needs to judge whether the fix was right.

## Status at a glance

| Gap | Section | Status |
|---|---|---|
| Identity — no SSO/RBAC | [§3.1](#31-identity--the-hard-blocker) | ❌ open — the hard blocker |
| No AIBOM / ML-BOM output | [§3.2](#32-no-aibom--ml-bom-output---shipped-wave-2) | ✅ shipped (#32) |
| No compliance mapping | [§3.3](#33-no-compliance-mapping-at-all---addressed-wave-3) | ✅ shipped (#33) |
| No incremental scanning | [§3.4](#34-no-incremental-scanning) | ❌ open — pilot-killer |
| No registry integrations | [§3.5](#35-no-registry--storage-integrations) | ❌ open |
| Homelab: undiscoverable | [§4.1](#41-the-word-ollama-appeared-nowhere-in-this-repository---shipped-wave-1)–[§4.5](#45-no-zero-config-on-ramp---shipped-wave-1) | ✅ shipped (#31) |
| GGUF has no loader-CVE channel | [§4.4](#44-the-homelab-dominant-format-has-the-weakest-intel-coverage) | ❌ open — documented, not fixed |

---

## 1. Where the code actually is

Measured, not claimed:

| | |
|---|---|
| Source | **7,839 LOC** Python (`src/purser` + `src/purser_deep`) |
| Tests | **382 passing** / 3 skipped, `ruff` clean |
| Detections | **~70 rule IDs** across ~20 formats |
| Published | PyPI `purser` **0.3.0** (6 releases) |
| Traction | **2 stars, 0 forks**, repo created 2026-07-19 (~7 weeks old) |

> ⚠️ `gap_analysis.md` says "~4.6k LOC, 181 automated tests" and is dated
> 2026-07-19. The codebase has since roughly **doubled**. That document is
> stale and understates the project.

**What genuinely exists** — this is not a prototype:

- **Detection breadth**: pickle (static `pickletools.genops`, never `Unpickler`),
  PyTorch, Keras (H5 + v3, incl. non-`Lambda` custom layers), ONNX, TF
  SavedModel, TFLite, GGUF, Paddle, CoreML, OpenVINO IR, skops, PMML, MAR,
  ExecuTorch, NumPy, safetensors, archives (zip-slip/bomb), plus an
  **exfiltration engine** and a **`trust_remote_code` AST analyzer**.
- **Control-plane surface**: FastAPI REST (`api.py`), a Kubernetes
  `ValidatingAdmissionWebhook` (`admission.py`), and a scan→approve→admit loop
  (`core/approvals.py`).
- **Provenance**: Ed25519 detached signing over a SHA-256 manifest with a trust
  store (publisher + country, revocation, validity windows) **and** Sigstore
  (Fulcio/Rekor) verification against a vendored trust root.
- **Ops**: Prometheus `/metrics`, structured audit log, MITRE ATLAS tagging, a
  20-template Helm chart (HPA, PDB, NetworkPolicy, ServiceMonitor,
  PrometheusRule, `values.schema.json`), 3 digest-pinned Wolfi images
  (non-root, read-only rootfs), a GitHub Action, and GitLab CI.
- **Assurance**: OpenSSF Best Practices badge **passing** (project 13900);
  a benchmark harness measuring detection, FPR, and evasion resistance.

**Measured quality** (`benchmarks/results/`):

| Metric | Value |
|---|---|
| Detection on known-answer set | 100% (12/12) |
| False-positive rate | **0%** (0/79 benign, incl. 75 real HF models) |
| Scan latency p50 / p95 | 267 ms / **21,978 ms** |

Peer comparison on the same corpus: Purser 12/12, Fickling 7/7 (5 formats not
attempted), ModelAudit 7/12, ModelScan 2/3 (9 not attempted), picklescan 5/12.

**Honest read:** the engineering is well ahead of the adoption surface. Nothing
below is a criticism of code quality — the gaps are packaging, evidence, and
identity.

---

## 2. The 2026 market

### Consolidation is essentially complete at the runtime layer

| Acquirer | Target | Value | Date |
|---|---|---|---|
| Palo Alto Networks | Protect AI (ModelScan, Guardian) | ~$600M+ | Jul 2025 |
| Cisco | Robust Intelligence | ~$400M | Sep 2024 |
| Check Point | Lakera | ~$300M | Oct 2025 |
| SentinelOne | Prompt Security | ~$180M | Sep 2025 |

Every acquirer was an established security vendor **buying** the AI layer rather
than building it. Protect AI is now folded into **Prisma AIRS 2.0**.

### Category status

- **AI-SPM** — fast-growing but at risk of becoming *"just a feature"* inside
  CNAPP (Wiz/Google, Prisma Cloud, CrowdStrike, Tenable).
- **AI red teaming / evals** — commoditizing (garak, promptfoo, Inspect).
- **LLM firewalls** — consolidating, bundled into platforms.
- **Model supply chain** — **"Emerging"**, described as *"underowned, asymmetric
  upside"*. Players: HiddenLayer (AIBOM), Palo Alto, JFrog, Bosch AIShield.

### Five gaps the market map calls explicitly unserved

1. Indirect prompt-injection specialists
2. Agent permissions at scale
3. **Model supply chain beyond the Hub** — *"private models, internal
   registries, and policy enforcement inside their own pipelines"*
4. **Sovereign / air-gapped deployments** — *"tooling that operates fully
   disconnected (no cloud inspection, local evidence retention, offline policy
   updates) remains scarce"*
5. Budget-conscious evals at enterprise scale

**#3 and #4 are precisely what Purser is.** Offline-by-default, vendored intel
with `PURSER_LOADER_CVES` / `PURSER_INTEL_URL` for air-gap, policy enforced in
*your* CI and *your* admission controller, self-hosted with no callback. That is
the single most important strategic fact in this document, and the positioning
does not currently say it in these words.

### The demand driver has shifted

Buying is moving *"from demos to auditable evidence"*, pushed by the OWASP LLM
Top 10 and regulatory deadlines. Concretely:

- **EU AI Act** — 2 Aug 2026 is the binding date for high-risk obligations
  (Arts. 9–17, 26) under current law. The Digital AI Omnibus **provisionally**
  defers to 2 Dec 2027 / 2 Aug 2028, but it is **not formally adopted**;
  practitioner guidance is to plan for August 2026.
- **AIBOM** is moving from optional artifact to **procurement requirement**.
  Two formats matured: **CycloneDX ML-BOM v1.7** (OWASP; the practical CI/CD
  format) and **SPDX 3.0 AI + Dataset profiles** (ISO/IEC; the regulatory one).
  G7 + EU published joint AI-SBOM guidance in May 2026. Adoption is still
  *"early, often incomplete or inaccurate"* — i.e. the window is open.

### Open source is compressing the baseline

ModelScan, LLM Guard (~1M monthly HF downloads), garak, promptfoo, NeMo
Guardrails all make baseline features free. **Consequence for Purser:** raw
scanner recall is not a defensible wedge. The ROADMAP already concluded this
("Purser orchestrates detection rather than competing on it") — the market data
supports that call.

### One competitive fact worth acting on

The academic benchmark **arXiv 2608.27424** ("Beyond F1") evaluated ModelScan,
ModelAudit, and Fickling over 170 artifacts / 145 families, and separates
*judgment accuracy* from *judgment availability*. **Purser is absent.** Its own
benchmark (12 malicious families) is an order of magnitude smaller. Meanwhile
picklescan has 60+ GHSAs and Fickling 12 — the scanners themselves are a
vulnerability class, which is an argument for Purser's never-execute design that
nobody has made on its behalf.

---

## 3. Enterprise adoption gaps

Ranked by how often each one *kills a deal*, not by effort.

### 3.1 Identity — the hard blocker

`api.py` authenticates with **comma-separated shared API keys**. That is it.

- No OIDC/SSO, no SAML, no SCIM
- No RBAC — every key is equal; no separation between "may scan", "may read
  policy", and "may approve a digest"
- No per-key identity, so the audit log cannot attribute an action to a person
- No multi-tenancy

Procurement research is blunt that *"SSO and SCIM are the two that block deals
most often, because without them the customer cannot onboard or offboard users
at their own scale."* A shared bearer token also means the `approvals` path —
which decides what admission lets into the cluster — has **no attributable
authorization**. For a security product that is the most serious gap here.

### 3.2 No AIBOM / ML-BOM output — ✅ SHIPPED (Wave 2)

> **Resolved in #32.** `core/mlbom.py` emits CycloneDX 1.7 via
> `--format cyclonedx`, validated against the official `bom-1.7.schema.json`.
> The premise below held exactly: `FileResult` already carried `sha256`,
> `format` and `size`, so no detection or plumbing was needed. SPDX 3.0 AI
> profile remains unimplemented and is still worth its own issue.

The original finding:


`scripts/gen_sbom.py` produces a CycloneDX SBOM of **Purser's own
dependencies**. Nothing emits a bill of materials for the **models it scans**.

Purser already extracts almost everything an ML-BOM needs — format, hashes,
declared framework versions, provenance/signature identity, publisher, country
of origin, CVE mapping, ATLAS tags — and throws it away into a JSON report.
Emitting **CycloneDX ML-BOM v1.7** (and ideally SPDX 3.0 AI profile) would turn
Purser from "a scanner" into "the thing that produces your EU AI Act Annex IV
evidence," exactly as AIBOM becomes a procurement gate. This is the highest
leverage-to-effort item in this document.

### 3.3 No compliance mapping at all — ✅ ADDRESSED (Wave 3)

> **Resolved.** `data/compliance_map.yaml` + `core/compliance.py` now tag every
> finding with OWASP ML / OWASP LLM / NIST AI RMF / EU AI Act Annex IV
> controls, and generate [`docs/compliance-mapping.md`](docs/compliance-mapping.md)
> from the same file. The counts below are what prompted the work.

Reference counts across every `.md` in the repo, **as of 2026-09-07 before
Wave 3**:

| Framework | Files mentioning it |
|---|---|
| NIST AI RMF | **0** |
| ISO/IEC 42001 | **0** |
| EU AI Act | **0** |
| OWASP (LLM/ML Top 10) | **0** |
| SOC 2 | **0** |
| FedRAMP | **0** |
| SLSA | 3 |

MITRE ATLAS tagging exists in code and is genuinely good. But an enterprise
buyer arrives with a control matrix, and there is no document that says "Purser
rule X satisfies control Y." Since buying has shifted to *auditable evidence*,
this is a paperwork gap with outsized commercial impact — and most of it is
writing, not code.

### 3.4 No incremental scanning

There is no digest-keyed scan-result cache in `core/scanner.py` or
`core/dispatch.py`. Every scan re-reads every byte. Combined with a **p95 of
22 seconds** on real models, a CI gate over a large model registry re-scans
unchanged multi-gigabyte artifacts on every run. This is the gap most likely to
get Purser *removed* after a pilot.

### 3.5 No registry / storage integrations

Hits across `src/`: `s3` 0, `minio` 0, `boto` 0, `artifactory` 0, `nexus` 0,
`harbor` 0, `azure` 0, `sagemaker` 0, `vertex` 0. `mlflow` appears 4 times but
only as a *detection* rule (`MLFLOW_PYFUNC_LOADER`), not as an integration.

The only fetch path is the HF Hub. Yet market gap #3 is *specifically* "private
models, internal registries." Enterprise models live in S3/MinIO, Artifactory,
MLflow Model Registry, SageMaker, and Vertex — none reachable today without the
user staging files onto a volume first.

### 3.6 Smaller but real

- **Audit records** are JSON to stdout/syslog — no CEF/LEEF for SIEM ingestion,
  and the records are unsigned, so the audit trail is not tamper-evident.
- **Rate limiting is per-replica**, not cluster-global (already noted in
  `gap_analysis.md` §4).
- **Single maintainer, 2 stars.** The project's own CNCF assessment is correct:
  Sandbox is plausible, Incubating (≥3 production adopters, multi-org
  committers) is out of reach. No enterprise will adopt a solo-maintained
  security control without either a support channel or a foundation behind it.

---

## 4. Homelab adoption gaps

The 2026 homelab AI stack is **Ollama** (won on simplicity), vLLM+Ray,
llama.cpp, **Docker Compose**, K3s, and Unraid 8 (now with native Compose).
The dominant artifact format is **GGUF**.

### 4.1 The word "Ollama" appeared nowhere in this repository — ✅ SHIPPED (Wave 1)

> **Resolved in #31.** Now referenced in `README.md`, `docs/homelab.md`,
> `docker-compose.yml`, `deploy/unraid/purser.xml` and `docs/README.md`.

The original finding: zero matches across all `.py`, `.md`, `.yaml`, `.yml`.
That was the entire homelab gap in one line — because:

### 4.2 …the engine already works. It's a discoverability gap, not a capability gap

I tested this directly. Ollama stores models as **extensionless
`sha256-<hex>` blobs**. Purser's magic-byte sniffing handles them correctly:

```
files Purser would scan: ['sha256-aabbccddeeff001']
verdict: PASS | files: 1
  file: sha256-aabbccddeeff001 | format: gguf | findings: 0
```

`iter_scannable` + `detect_format` identify the blob as GGUF with no extension
to go on. **`purser scan ~/.ollama/models` works today and nobody knows.** A
README section, a compose recipe, and a blog post are worth more here than any
code.

### 4.3 Compose requires cloning and building — ✅ SHIPPED (Wave 1)

> **Resolved in #31.** All three services now reference published multi-arch
> images with `build:` kept as the dev path. Two further bugs surfaced while
> making "no clone" actually true: the compose file mounted `./policies` and
> `./models`, neither of which exists without a clone. The policy now defaults
> to the image-baked `/policies/default.yaml` and the model mount is
> `PURSER_MODELS`.

The original finding:

`docker-compose.yml` used `build:` + `image: purser:dev` for all three services.
A homelabber must clone the repo and build three images. Every comparable
self-hosted tool ships a copy-pasteable compose file with a **published
`image:`** tag. Since images are already on GHCR, this is close to a one-line
fix — `image: ghcr.io/purser-io/purser:0.3.0` with `build:` as fallback.

### 4.4 The homelab-dominant format has the weakest intel coverage

`loader_cves.yaml` version channels are **`keras_version` and
`transformers_version` only**. GGUF/llama.cpp carries no version the artifact
declares, which the ROADMAP already acknowledges. So the loader-CVE signal —
one of the flagship "aggregation" features — is structurally blind to the format
homelabs actually run. GGUF detection itself is fine
(`GGUF_TEMPLATE_INJECTION`, `GGUF_BAD_MAGIC`).

### 4.5 No zero-config on-ramp — ✅ SHIPPED (Wave 1)

> **Resolved in #31.** A 60-second quickstart is now on the README's first
> screen, `docs/homelab.md` covers Ollama / Docker / Compose / Unraid / K3s /
> air-gap, and `deploy/unraid/purser.xml` is a Community Applications template.
> The CA *listing* still needs a separate submission to the CA repo.

The original finding: getting value meant understanding policies, `PURSER_SCAN_ROOT`,
`PURSER_API_KEY`, and which of three images to run. There is no
`purser scan --quick ~/.ollama` story, no Unraid template, no `docker run
--rm -v ~/.ollama:/models:ro ghcr.io/...` one-liner in the README's first
screen. Homelab adoption is won on the first 60 seconds.

> Also: `pyproject.toml` sets `Homepage = "https://purser-io.io"`. It resolves,
> but the doubled `-io.io` looks like a typo worth confirming.

---

## 5. Execution plan

Sequenced by leverage-per-effort, not by interest. Waves 1–3 are cheap and
produce the adoption and evidence that make waves 5–7 worth building — they are
also exactly the traction gates [`ROADMAP.md`](ROADMAP.md) identifies for CNCF
Sandbox.

### Wave 1 — Homelab on-ramp ✅ SHIPPED

The optimal first move: near-zero code, unblocks everything downstream.

Verified prerequisites before any docs were written:

- `ghcr.io/purser-io/purser{,-hf,-deep}` are **anonymously pullable**, tagged
  `0.3.0` / `0.3` / `latest`, with cosign `.sig` + `.att` present.
- All three are **multi-arch** `linux/amd64` + `linux/arm64` — Raspberry Pi and
  ARM NAS work unmodified.
- The Dockerfile already sets `ENV PATH="/venv/bin:$PATH"`, `ENTRYPOINT []`,
  pre-creates `/models`, and bakes in `/policies/default.yaml`, so
  `docker run … purser scan /models` needed **no image change at all**.
- `purser scan` on an Ollama-style store returns `PASS` with **exit code 0**.

| Change | File |
|---|---|
| 60-second quickstart on the first screen | `README.md` |
| Compose uses published images; `build:` kept as the dev path | `docker-compose.yml` |
| Compose works with **no clone** — image-baked policy default, `PURSER_MODELS` for the model mount, repo-only mounts commented | `docker-compose.yml` |
| Homelab guide — Ollama, Docker, Compose, Unraid, K3s, air-gap | `docs/homelab.md` |
| Unraid Community Applications template | `deploy/unraid/purser.xml` |
| Guide linked from both indexes | `README.md`, `docs/README.md` |

Two accuracy fixes made while writing, both worth noting because the original
plan was wrong:

1. Compose mounted `./policies` and `./models`, which **do not exist without a
   clone** — that silently broke the "no clone" claim. Now defaults to the
   image's own policy.
2. `admission`, `autoscaling`, and `ingress` already default to **false**, so
   the K3s snippet no longer pretends they need disabling. A homelab install is
   `--set replicaCount=1`.

The Ollama gap is documented honestly rather than papered over: GGUF gets
format scanning (`GGUF_BAD_MAGIC`, `GGUF_TEMPLATE_INJECTION`) but **no
loader-CVE advisory**, because the signal keys off declared framework versions
and GGUF carries none (§4.4).

### Wave 2 — ML-BOM ✅ SHIPPED

`src/purser/core/mlbom.py` renders a `ScanReport` as **CycloneDX 1.7**, wired as
`--format cyclonedx` into the existing `cli.py:_emit` branch.

The open question resolved immediately: **`FileResult` already carries
`sha256`, `format`, and `size`** (`core/findings.py`), so no plumbing was
needed — §3.2's claim that the data was already collected and discarded held
up exactly.

**Acceptance met:** output validated against the *official*
`bom-1.7.schema.json` from the CycloneDX specification repo (with the `jsf` and
`spdx` sub-schemas resolved) — **valid, zero errors**. 15 new tests, offline.

Mapping decisions, each chosen to avoid overclaiming:

| Decision | Why |
|---|---|
| Models are `machine-learning-model` components keyed by **SHA-256** | Same digest the admission approvals path uses, so a BOM entry and an admitted digest are directly comparable |
| Loader CVEs under their **real CVE id**, `source: osv`; Purser rules as `purser:<RULE_ID>`, `source: purser` | A rule must never masquerade as a CVE. A test asserts this |
| Ratings use `method: "other"` | Purser severities are policy-relative, not CVSS. Claiming CVSS would be false |
| Declared framework attributed **per file**, not scan-wide | A directory can mix frameworks; smearing one version across components is wrong. Caught during implementation |
| `serialNumber` = UUIDv5 over target + sorted digests | Content-addressed, so an unchanged scan yields the same serial |
| Architecture / task / datasets / performance **absent, not guessed** | Purser never loads the model, so it cannot know them. An ML-BOM from a never-execute scanner is an accurate artifact inventory, not a substitute for a publisher's model card |

One claim corrected mid-implementation: the first docstring said an unchanged
scan yields a *byte-identical* BOM. It does not — `metadata.timestamp` moves by
design. Everything else is byte-identical, and that is what the docs now say.

### Wave 3 — Compliance mapping ✅ SHIPPED

Built as planned, by mirroring `core/atlas.py`: `data/compliance_map.yaml` is
the single source of truth for both the finding tags and the generated
[`docs/compliance-mapping.md`](docs/compliance-mapping.md)
(`make compliance-doc`). A test fails CI if the committed doc goes stale, so
the tags a reviewer greps and the table they read cannot drift apart. Tags also
ride into the ML-BOM from Wave 2, so the document handed to an auditor carries
the control references with it. `PURSER_COMPLIANCE=0` disables.

**The control ids were verified against published sources, not written from
memory** — a compliance mapping with invented identifiers is worse than none:

| Framework | Granularity | Basis |
|---|---|---|
| OWASP ML Top 10 (2023) | exact ids | published Top 10 |
| OWASP LLM Top 10 (2025) | exact ids | published Top 10 |
| NIST AI RMF 1.0 | **category level only** (`GOVERN-6`, `MAP-4`, `MANAGE-3`, `MEASURE-2`) | the three categories scoped to third-party/supply-chain risk are GOVERN 6, MAP 4, MANAGE 3 |
| EU AI Act | Annex IV **section** numbers (1–9) | the granularity Annex IV itself uses |

The plan sketched ids like `nist:MEASURE-2.7` and `euaiact:AnnexIV-2b`. Those
subcategory decimals and sub-letters could **not** be verified against NIST AI
100-1 or the Annex IV text, so the mapping deliberately stops at the
granularity it can defend and says so in both the YAML header and the doc.
Refining to subcategories is left to the operator's own control matrix.

Two modelling calls worth noting:

* `CARD_*` findings are **excluded from the supply-chain umbrella** — a missing
  model card is a documentation gap, not a supply-chain attack. They map to
  Annex IV(1) and (4) instead.
* `GGUF_TEMPLATE_INJECTION` gets `owasp-llm:LLM01` *and* `LLM03` — it fires
  when the model is prompted, but arrived through the supply chain.

The doc also carries a **"coverage this mapping does not claim"** section:
Purser produces no evidence for training-data governance, behavioural
evaluation, human oversight, or incident reporting, and an auditor should not
read a Purser report as covering them.

### Wave 4 — Third-party benchmark (corpus + outreach)

Grow `benchmarks/kat.py` past 12 families toward the arXiv harness's 145, then
approach the authors for inclusion. Their metric — *judgment availability* vs
*accuracy* — favours Purser: broad format coverage plus 0% FPR, against tools
carrying 60+ GHSAs.

### Waves 5–7 — The real blockers (months)

| Item | Where | Note |
|---|---|---|
| **OIDC + RBAC** | `api.py:require_auth` → pluggable backend; JWKS validation; scopes for scan / read-policy / approve; per-identity attribution in `core/audit.py:build_record` | Biggest lift. Regulated buyers cannot start without it |
| **Incremental cache** | `core/scanner.py`, keyed on `(sha256, scanner-version, policy-hash)` | Fixes the p95-22s pilot-killer. Highest ops payoff per line |
| **S3/MinIO** | New `[s3]` extra; `s3://` targets mirroring the existing `hf://` path | MinIO also covers homelab NAS setups |

### The trap

Doing waves 5–7 first. OIDC and a scan cache are the most
*engineering-satisfying* items and the least likely to win a user. Purser beats
every OSS peer on its own corpus and has 2 stars — that is a distribution
problem, and no amount of RBAC fixes it.

### Caveat on this document

The "two of five unserved gaps" framing that motivates waves 2–3 rests on a
**single** market map. Worth corroborating against a second source before
committing two weeks to ML-BOM.

### The one-line strategic read

Purser is a technically strong product aimed — apparently by accident — at
**two of the five gaps the 2026 market map calls explicitly unserved**
(air-gapped/sovereign, and supply chain beyond the Hub). It is losing on
distribution and evidence, not on engineering. Fix the compose file and ship an
ML-BOM before writing another detector.
