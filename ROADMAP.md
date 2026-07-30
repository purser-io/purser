# Purser Roadmap

Forward-looking work. Competitive positioning is in the
[comparison chart](README.md#how-purser-compares); shipped history is in
[`CHANGELOG.md`](CHANGELOG.md). This file tracks what is **not done yet** and why.

Purser is released and installable (**v0.2.1** — on PyPI, with signed multi-arch
container images and a signed Helm chart on GHCR, built and published by CI). The
security-hardening arc, supply-chain foundations (hash-pinned Wolfi builds, SBOM,
cosign/SLSA, multi-arch), model signing with revocation, the exfil /
`trust_remote_code` engines, observability, disguise-resistant format detection,
deploy-time admission enforcement, Sigstore verified-identity provenance, and a
gated validation benchmark (incl. an adversarial evasion suite) are all shipped
(250 tests). What remains is **not** bug-fixing — it is maturity, reach,
and depth. See *Recently shipped* at the bottom.

Status legend: **planned** (agreed, not started) · **candidate** (worth doing,
undecided) · **deferred** (chosen not to do yet) · **out-of-scope**.

---

## Recommended next (priority order)

1. **Foundation readiness.** Community scaffolding ships (CONTRIBUTING, Code of
   Conduct, issue/PR templates, enforced DCO, `CITATION.cff`, `py.typed`).
   - **OpenSSF Best Practices badge** — a full **passing**-criteria self-assessment
     is prepared ([`docs/openssf-best-practices.md`](docs/openssf-best-practices.md));
     every MUST is met (two justified N/A). Remaining: the owner self-certifies at
     bestpractices.dev and drops the badge into the README (no code gap).
   - **CNCF Landscape entry** — prepared ([`docs/cncf-landscape-entry.md`](docs/cncf-landscape-entry.md))
     but **deferred**: the landscape's inclusion bar (traction ≈ ≥300 stars, plus a
     backing org/Crunchbase) isn't met yet. Submit once adoption grows.

*(Real-world validation + published benchmark — formerly #1 — is now complete:
the Phase-1 known-answer harness, Phase-2 peer comparison (`compare.py`), Phase-3
adversarial evasion suite (`evasion.py`), and a scheduled CI job that gates on
detection / FPR / evasion regression all ship in `benchmarks/`. The real-model
negative set is now **75 pinned HuggingFace models** — a broad architecture sweep
(encoders, causal/seq2seq LMs, vision, audio, multimodal; pickle / safetensors /
ONNX / Keras incl. int8-quantized) at **0% FPR** — published in
`benchmarks/README.md` and re-measured weekly. Further corpus growth + long-term
trend tracking is ongoing maintenance.)*

*(Per-format scanner depth — formerly #2 — is now complete for what a static,
no-load scanner can do: dedicated op / custom-code detection for pickle, Keras
(incl. non-`Lambda` custom layers), ONNX, TF SavedModel, TFLite, GGUF, Paddle,
CoreML (incl. `CustomModel`), and OpenVINO IR. True `declared`-vs-`reachable`
dataflow reachability needs the framework's own graph semantics at model-load
time, so — like TensorRT deep-parse and full pickle gadget-chain reachability —
it is **out of scope** for a scanner that never loads the model.)*

---

## Planned

| Item | Notes |
|---|---|
| **External PKI — remaining** | **Sigstore (Fulcio/Rekor) verification shipped** (`core/sigstore_verify.py`, offline against a vendored trust root; `identity` policy). Remaining: HuggingFace **GPG commit-signature** verification (online-only — a downloaded snapshot has no `.git` — so a lower-priority companion to the Sigstore path, which already covers HF's *Sigstore-based* model signing); and optionally an in-tool keyless signer (today signing is external via cosign/sigstore, which need a browser OIDC flow). |

## Candidates — detection depth

| Item | Notes |
|---|---|
| Per-format op/custom-code depth | **Shipped** for every format where static analysis is feasible: pickle opcodes, Keras (incl. non-`Lambda` custom layers), ONNX, TF SavedModel (exec + host-I/O ops), TFLite, GGUF, Paddle (`py_func`), CoreML (`CustomModel` + custom layers), and OpenVINO IR. TensorRT/MXNet stay format-ID + exfil. The one thing left — `declared`-vs-`reachable` dataflow — is **out of scope** (see below). |
| Python source dataflow/taint | The AST scanner matches dangerous call names and flags `getattr`/decode→exec; source assembled fully at runtime can still evade. A taint pass raises attacker cost further. |
| More exfil encodings | UTF-16, base64/hex/base32/base85, one gzip/zlib layer, and **single-byte XOR** are covered — decoded blobs are only flagged when they resolve to a real endpoint/command indicator, so no rise in the false-positive rate (verified 0% over the real-model set). Remaining: **multi-byte / rolling-key XOR** (infeasible to key-recover generally). Note: the XOR path deliberately confirms only *structural* indicators (webhook/URL/code/private-key), not narrow-charset credential regexes, which alias with quantized weight bytes. |
| Packed-binary C2 endpoints | Endpoints stored as packed bytes (no ASCII/UTF-16 form) aren't extracted; needs structured per-format parsing. |

## Candidates — provenance & trust

| Item | Notes |
|---|---|
| Origin database provenance | `org_countries.yaml` is a hand-maintained heuristic; document sourcing + a review cadence, or derive origin only from verified signers once the PKI trust root lands. |

## Candidates — ecosystem intelligence & provenance interop

Prompted by a review of dynamic-eval / governance vendors (SurePath → F5, Weights
& Biases, Seekr) and the model-threat-feed landscape. **The framing that survives
that review:** *bias, reliability, adversarial-robustness, and behavioral
poisoning are all **dynamic*** — they require **running** the model against inputs
— so they are not the static core's job (see *Out of scope → Dynamic evaluation*).
What a never-execute scanner *can* add is (a) **ingesting** existing threat/verdict
intelligence and (b) **provenance/attestation** depth and interop.

| Item | Notes |
|---|---|
| **Upstream scan-verdict enrichment (HuggingFace)** | The HF Hub already exposes per-file verdicts from Protect AI, JFrog, ClamAV (Cisco), and picklescan via `GET /api/models/{repo}/tree/{rev}?expand=true` → `securityFileStatus` (coarse `?securityStatus=true`). Free, per-commit, **no bulk endpoint** (one call/repo, cache by commit sha). Candidate for the **`-hf` path** (network already gated there): surface an `unsafe`/`suspicious` upstream verdict as a corroborating finding. **Rule: treat `unsafe` as signal; never let upstream `safe` downgrade Purser's own verdict** (FN history: nullifAI 7z, picklescan zero-days). Closest thing to a real "model threat feed" that exists — free, secondhand commercial intel. |
| **Loader-CVE mapping (OSV/GHSA, offline)** | No feed of malicious *models* exists, but framework/parser CVEs do: map a detected format + declared version to known load-time RCEs (`.keras`/`.h5` CVE-2025-9906/-9905 `safe_mode` bypass, Keras Lambda CVE-2024-3660, llama.cpp GGUF parser CVEs; CWE-502 class). Ingest bulk **OSV-JSON** (`ossf/osv-schema`, CC-BY-4.0) or the GHSA mirror **offline**; emit "load-unsafe under `<framework> <version>`". Also flags OSV `MAL-` malicious-*package* records against bundled deps. |
| **MITRE ATLAS technique tagging** | Tag findings with `AML.T####` IDs from `mitre-atlas/atlas-data` (YAML / STIX 2.1, free, monthly). Enrichment/credibility only — not a signature source. Cheap to ingest; aligns reports with the framework reviewers expect. |
| **Known-bad denylist + refresh** | A first-class `denylist` policy dimension (SHA-256 hashes + publisher/repo globs), refreshable offline like AV signatures, **populated from** the sources above (HF `unsafe`, huntr → CVE, operator curation). The policy engine already has publisher/name blocklists (a `models` example even names `known-cve-model`); this generalizes it and adds content hashes. A genuine **open** malicious-model hash/IOC feed is a market gap Purser could help seed. |
| **Signed AIBOM (model bill-of-materials)** | Extend the CycloneDX SBOM (today: the *package*) to a signed **model AIBOM** — files, hashes, formats, detected code surfaces, provenance/identity, verdict — as a cosign attestation. The static-provenance answer to W&B lineage (checksum/tamper-only, no signing) and to HiddenLayer's "AIBOM" marketing — but open and signed. |
| **Provenance interop (W&B / registry)** | Read a W&B **Artifact manifest + digest + lineage DAG** (open-source SDK, no execution) as a provenance signal, and ship a **W&B Automations → webhook** gate recipe: scan on new version/alias, block promotion to a **protected alias** (`Production`) on FAIL. Generalizes to any registry with a promotion webhook. |
| **Model-card / eval-attestation gate** | Static "visibility into bias/reliability" *without computing it*: a policy dimension that reads a declared eval/safety card (HF model card, an eval-results file, or a Seekr-style "Model Test Card" if present) and gates on **attested** claims (require a card; require declared eval coverage; block if a declared score is below a floor), cross-checking any hashes the card references against the actual files. Governs the *attestation*, not the model — keeps the never-execute guarantee. |

## Candidates — operability

| Item | Notes |
|---|---|
| Global memory accountant | Per-scan windowing + finding cap + concurrency cap bound memory in practice; a cross-request budget would be stricter. |
| Exfil scan latency on huge models | A multi-hundred-MB weight file still takes ~20 s. Cost (profiled) is per-string iteration over the ~millions of printable runs weight data yields, not the regexes. **Done:** length-gate the secret (>=14) / encoded (>=64) heuristics in `scanners/exfil.py` (~30% win, no detection change). **Avoid:** a buffer-wide regex rewrite — non-anchored patterns (IP:port, code/secret alternations, `{64,}` encoded) backtrack over the full binary and made it ~2x slower. **Next:** scan only structural/metadata regions of known formats, or lower the default per-file byte cap (`PURSER_MAX_SCAN_MB`). |

## Candidates — distribution / UX

| Item | Notes |
|---|---|
| Admission-webhook depth | The `ValidatingAdmissionWebhook` (shipped) enforces image-digest pinning + approved-model digests at deploy time. Next: a controller that *populates* the approved-digest set automatically from scan results (today it is operator-managed via the ConfigMap / GitOps), and optional cosign attestation verification instead of a digest allowlist. |

## Out of scope

Mirrors the *does-not-defend-against* list in [`SECURITY.md`](SECURITY.md)
(§ Threat model / Residual risk). The actively-worked residuals it also
mentions — multi-byte / rolling-key XOR, packed-binary endpoints, and fully
runtime-assembled `trust_remote_code` source — are **not** out of scope; they
live under *Candidates — detection depth* above.

| Item | Why |
|---|---|
| Pickle gadget-chain reachability | *Heuristic* gadget-composition detection ships in the **`purser-deep`** companion (pivot primitives, complex graphs, deep imports). Full reachability/soundness is still infeasible statically; the robust guarantee remains the ban-pickle allowlist policy (`signed-only.yaml`). |
| Graph `declared`-vs-`reachable` dataflow (TF / Paddle / CoreML / ONNX) | Purser flags **declared** dangerous ops / custom code (the conservative, safe choice for a gate). Pruning to only *reachable* ops needs the framework's own graph semantics at model-load — which a no-load scanner won't do. Flagging a declared dangerous op even if a particular graph prunes it is the intended, fail-safe behavior; deep runtime reachability is enterprise/dynamic-analysis territory. |
| Weight *steganography / tampering* | Covered by **`purser-deep`** (`deep.weights`): hidden data in tensor low-bit planes, non-finite weights, size mismatches — static, no model load. |
| Dynamic evaluation — bias, reliability, adversarial-robustness, behavioral backdoors / poisoning | Out of scope for the never-execute **core**: all require **running** the model against inputs. The vendors in this space are dynamic (Seekr *SeekrGuard*, W&B *Weave* scorers, F5/SurePath red-team, `garak`, `promptfoo`). If pursued, this is a **separate opt-in companion** (as `purser-deep` is a separate image) that wraps existing eval / red-team tooling — never folded into the static core. Static weight *steganography / tampering* is already covered by `purser-deep`. |
| Determined / volumetric DoS | The concurrency cap, per-client rate limit, and per-file windowing bound resource use, but absorbing a determined flood is the job of an edge proxy / WAF / autoscaler, not the scanner. |
| Spoofed provenance when signing is not required | By design, origin/publisher is *advisory* unless a policy sets `require_signed`. Enforce trust with `policies/signed-only.yaml` + a trust store; Purser will not treat unsigned claims as authoritative on its own. |
| Threat-intel **dashboards / hosted feed service** | Running a hosted threat-intel service or SOC dashboards is enterprise-platform territory (Guardian, HiddenLayer). **Correction (2026-07):** *ingesting* existing free feeds (HF scan verdicts, OSV/GHSA loader-CVEs, MITRE ATLAS) and maintaining an offline known-bad denylist are **no longer out of scope** — they moved to *Candidates — ecosystem intelligence & provenance interop*. There is still **no** open feed of malicious *model artifacts* to consume; that gap is real. |

---

## Recently shipped

Moved out of the roadmap now that they're done (see [`CHANGELOG.md`](CHANGELOG.md)
for per-release detail):

- **Public release & distribution (v0.1.0 → v0.2.1):** public git repo with
  protected `main`; GitHub Actions CI (lint + test matrix 3.11–3.14, lockfile /
  license gates, Helm lint, image builds + Trivy) and a tag-driven release
  pipeline; **PyPI** publishing via OIDC Trusted Publishing; public multi-arch
  **signed** container images (core / HF / deep) and a **signed** Helm chart on
  GHCR (OCI); CodeQL + **dependency-review** (now active — the repo's Dependency
  Graph + Dependabot alerts are enabled, so PRs are gated on new-dependency CVEs
  and copyleft licenses); `CHANGELOG.md`; a `demo/` sandbox.
- **Community & governance:** `CONTRIBUTING.md`, a Contributor Covenant Code of
  Conduct, bug/feature issue forms + a PR template, an **enforced DCO** sign-off
  check, `CITATION.cff`, a `py.typed` marker, and package `[project.urls]`.
- **Deploy-time enforcement:** a composite GitHub Action (`action.yml`) gates a
  CI job on the policy verdict, **and** a Kubernetes `ValidatingAdmissionWebhook`
  (`purser.admission`, Helm `admission.enabled`) enforces image-digest pinning +
  approved-model digests at admission — closing the scan→deploy TOCTOU gap.
- **Validation benchmark:** a known-answer + real-model harness (**75 pinned
  HuggingFace models**, 0% FPR), a peer-scanner head-to-head comparison, a Phase-3
  adversarial evasion suite (gated on evasion recall), and a scheduled CI job that
  gates on detection/FPR/evasion regression (`benchmarks/`).
- **Disguise-resistant detection:** magic bytes beat a spoofed extension, and
  directory walks sniff files hidden under doc/config names.
- **Wolfi base auto-refresh:** a weekly CI job (`wolfi-base-check.yml`) detects a
  stale base digest and **auto-refreshes** — bumps the pin in all three
  Dockerfiles, rebuilds each image, runs Trivy (HIGH/CRITICAL, fixed-only — the CI
  gate) on the new base, and opens a **PR** with the per-image result (falling back
  to an issue only if the run itself errors). The PR is opened with a scoped
  `GH_PR_TOKEN` secret and DCO-signed (`signoff`), so it passes checks and triggers
  CI; the drift issue is auto-closed on resolution. Supersedes the earlier detect-
  and-open-an-issue job; manual `make base-digest` still prints the live digest.
  **Setup dependency:** requires a repo secret `GH_PR_TOKEN` (fine-grained PAT /
  App, Contents + Pull requests: write) — the default `GITHUB_TOKEN` cannot create
  PRs on this repo.
- **Provenance:** Ed25519 model signing + trust store, `require_signed` policy,
  and key **revocation / validity windows**; **Sigstore (Fulcio/Rekor) verified
  identity** — offline bundle verification against a vendored trust root, with an
  `identity` (issuer/SAN) policy — moving the key→identity binding from an
  operator assertion to a verified external root.
- **Detection:** `trust_remote_code` AST scanner + `auto_map` config scanner;
  exfil UTF-16 / hex / base32 / base85 / gzip / single-byte-XOR decoding; configurable benign-host allowlist.
- **Protocol-0/1 (ASCII) pickle spoof:** an ASCII pickle disguised under a
  structured-binary extension (`.onnx`/`.pb`/`.tflite`/`.pte`/`.pdmodel`) is now
  confirmed via a `pickletools.genops` trial-parse and routed to the pickle
  scanner (previously only flagged as a format *mismatch*). Real protobuf/
  flatbuffer models are never misrouted — 0 misroutes over the real-model corpus
  (incl. a 418 MB ONNX). Closes that gated evasion residual (recall 16/16);
  packed-binary endpoints remain the one open residual.
- **Per-format depth:** Keras **non-`Lambda` custom-layer** detection (config walked
  for layer classes outside the Keras/TF namespaces — external code on load);
  **OpenVINO IR** graph parsing (XXE / DOCTYPE-entity + external library/path refs);
  broadened **TF SavedModel** host-I/O ops and **CoreML** `CustomModel`-backend
  detection.
- **Format breadth (~35 identified formats).** Added detection for TorchServe
  `.mar`, MLflow (`MLmodel`), Caffe (`.prototxt`/`.caffemodel`), NeMo `.nemo`,
  H2O MOJO, Darknet `.weights`, LightGBM native, and Torch7 `.t7`. **Security
  value split (why these, not just count):** MAR / MLflow / Caffe carry a **real
  code-execution surface** we were previously blind to — a TorchServe `handler.py`,
  an MLflow `python_function` loader module, or a Caffe `PythonLayer` all run
  arbitrary code on load, so these get **dedicated scanners** (`MAR_HANDLER_CODE`,
  `MLFLOW_PYFUNC_LOADER`, `CAFFE_PYTHON_LAYER`). The rest are **data-only** blobs
  with no code surface — identified for policy allowlists + exfil scan only, which
  also stops them being misclassified. (NeMo / MOJO archives are recursed.)
- **Supply chain:** hash-pinned lockfiles + `--require-hashes`, split core/HF/deep
  Wolfi images, deterministic CycloneDX SBOM, `trivy` + `osv-scanner` CI gates,
  multi-arch `buildx` with SLSA provenance + SBOM attestations, cosign signing.
- **Observability:** Prometheus `/metrics` (built-in registry) with
  security-domain series + an importable Grafana dashboard, and a structured JSON
  **audit log** to syslog/stdout (`PURSER_AUDIT`)
- **Alerting:** an optional Helm `PrometheusRule` starter set (target-down, scan errors incl. deep-unavailable, FAIL/BLOCKED spike, load-shedding, auth-failure spikes).
