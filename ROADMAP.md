# Purser Roadmap

**North star: the open-source model supply-chain control plane.** One policy +
provenance + enforcement plane that ingests signals from many analyzers —
Purser's own static scanner, the `purser-deep` companion, verified
signatures/identity, and upstream/third-party intelligence — and renders a
single verdict it enforces in CI, over the REST API, and at Kubernetes
admission. The scanner is
one input; the control plane (policy, provenance, enforcement, signal
aggregation) is the product. Detection depth still matters, but Purser
*orchestrates* detection rather than competing on it alone.

Forward-looking work. Competitive positioning is in the
[comparison chart](README.md#how-purser-compares); shipped history is in
[`CHANGELOG.md`](CHANGELOG.md). This file tracks what is **not done yet** and why.

Purser is released and installable (**v0.2.1** — on PyPI, with signed multi-arch
container images and a signed Helm chart on GHCR, built and published by CI). The
security-hardening arc, supply-chain foundations (hash-pinned Wolfi builds, SBOM,
cosign/SLSA, multi-arch), model signing with revocation, the exfil /
`trust_remote_code` engines, observability, disguise-resistant format detection,
deploy-time admission enforcement, Sigstore verified-identity provenance,
pluggable signal sources with upstream-verdict ingestion (`purser.signals`), and a
gated validation benchmark (incl. an adversarial evasion suite) are all shipped
(330 tests). What remains is **not** bug-fixing — it is maturity, reach,
and depth. See *Recently shipped* at the bottom.

Status legend: **planned** (agreed, not started) · **candidate** (worth doing,
undecided) · **deferred** (chosen not to do yet) · **out-of-scope**.

---

## Recommended next (priority order)

Re-sequenced for the control-plane pivot (2026-08-02). The ordering logic:
ship the pivot so anyone can see it (#1), make the control-plane claim
literally true in a cluster (#2), prove the aggregation thesis with a second
real intel signal (#3), then convert the resulting momentum into foundation
standing (#4 — its gates are *outputs* of #1). Detection-depth residuals are
deliberately held behind all four: the pivot's core argument is that Purser
orchestrates detection rather than competing on it.

1. **Ship & launch the pivot.** Merge the pivot branch, cut **v0.3.0** (the
   release that carries the repositioning + `purser.signals` to PyPI/GHCR),
   push the prepared HF **Space** (`demo/hf-space/`, needs the maintainer's HF
   account), and publish the launch post
   ([`docs/launch-control-plane.md`](docs/launch-control-plane.md)). The
   strategy is explicit that distribution matters as much as features — and
   every later item (adopters, second maintainer, CNCF) compounds on this one.

2. **Close the enforcement loop (admission-webhook depth).** **Auto-approval
   SHIPPED:** `core/approvals.py` populates the webhook's approved-digest set
   from verdicts — PASS approves each scanned file's sha256, FAIL/BLOCKED
   revokes — via a file backend (`PURSER_APPROVALS_PATH`, GitOps-able) or an
   in-cluster ConfigMap patch (stdlib K8s API + narrow Role; Helm
   `admission.autoApprove.enabled`). Opt-in (`PURSER_AUTO_APPROVE=1`),
   auditable (`metadata.approvals`). **Remaining:** verify **cosign
   attestations** instead of a digest allowlist — connecting the provenance
   layer to the enforcement layer directly.

3. **Prove aggregation with a second real intel signal.**
   - **Loader-CVE mapping — SHIPPED** as the offline `loader-cves` source:
     declared framework version (e.g. `keras_version`) in a known load-time
     RCE range → LOW `LOADER_CVE` advisory from the vendored curated dataset
     (`data/loader_cves.yaml`). First signal that runs on local scans;
     remaining refinement: automate dataset refresh from bulk OSV-JSON and
     broaden beyond Keras (llama.cpp/GGUF needs a loader-version channel the
     artifact doesn't carry).
   - **Known-bad denylist — SHIPPED** (`denylist:` policy block; see
     candidates table). Seeding an open malicious-model IOC feed remains the
     open opportunity.
   - **MITRE ATLAS tagging — SHIPPED** (`atlas:AML.T####` tags from a
     vendored mapping; `PURSER_ATLAS=0` off) and **verdict-lookup caching —
     SHIPPED** (`PURSER_SIGNAL_CACHE_TTL`; commit-sha revisions cache for
     the process lifetime, failures never cached).
   - Remaining in this arc: the **exfil-latency** work (structural-region
     scanning — also the prerequisite for the packed-binary-C2 residual).

4. **Foundation readiness.** Community scaffolding ships (CONTRIBUTING, Code of
   Conduct, issue/PR templates, enforced DCO, `CITATION.cff`, `py.typed`).
   - **OpenSSF Best Practices badge — EARNED (passing).** Project
     [13900](https://www.bestpractices.dev/projects/13900) is at **100% / passing**;
     the badge is live in the README. Backed by the full self-assessment +
     submission sheet ([`docs/openssf-best-practices.md`](docs/openssf-best-practices.md)).
   - **CNCF project hosting (Sandbox → Incubating → Graduated)** — a far bigger and
     *different* track than the Landscape catalog below, and **not pursued yet**.
     Honest re-evaluation against the CNCF TOC criteria (`github.com/cncf/toc`):
     - **Already met:** Apache-2.0 license; a Contributor Covenant CoC; a public
       `SECURITY.md` disclosure process; and a genuine cloud-native surface (Helm
       chart, a `ValidatingAdmissionWebhook`, digest-pinned OCI images, Prometheus
       metrics) that plausibly fits the **Security** and emerging **AI** TAGs.
     - **Sandbox (entry level):** the most plausible near-term target. **IP
       neutrality is no longer a blocker** — acceptance requires donating the
       trademark/logo/domain to the Linux Foundation, and the brand is
       **unencumbered** (nothing filed; no org, product, or investment beyond these
       repos) and the maintainer is **willing to donate it**, so the transfer is
       clean. Sandbox has no hard traction bar. Remaining work is modest: (1)
       **governance docs** — now **shipped** (`GOVERNANCE.md`, `MAINTAINERS.md`,
       `OWNERS`, `ADOPTERS.md`); (2) a crisp **cloud-native fit** framing
       for the Security / AI TAG; (3) the practical reality that the TOC favors some
       **momentum and ideally >1 maintainer** — a brand-new solo project may be told
       it is *early*, but it is no longer *strategically* blocked.
     - **Incubating:** out of reach — needs **≥3 independent end-user adopters in
       production** and a healthy **multi-org** committer base with sustained
       releases. Purser is single-digit-stars and single-maintainer.
     - **Graduated:** far off — committers from **≥2 orgs**, broad public production
       adoption, a **third-party security audit**, the **OpenSSF Best Practices
       passing badge** (already **earned** — project 13900), and a TOC
       supermajority vote.
     - **Recommendation:** with the brand-donation question resolved (open to
       donating — the reserved-brand note in `TRADEMARKS.md` / market research is a
       *default*, not a constraint), **Sandbox is a real near-term goal.** Concrete
       path: governance docs ship and the OpenSSF badge is earned — remaining is
       to land a second maintainer + a couple of named
       adopters to clear the TOC's single-vendor / early-stage bar, and apply.
       Those two gates are what item **#1** (the launch) is designed to
       produce — which is why this sequences after it.
   - **CNCF Landscape entry** (the *catalog* — not project hosting) — prepared
     ([`docs/cncf-landscape-entry.md`](docs/cncf-landscape-entry.md)) but deferred:
     its lighter bar (traction ≈ ≥300 stars + a backing org/Crunchbase) isn't met
     yet, and it's independent of the hosting track above.

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

**Deliberately deprioritized** behind the aggregation/enforcement work in
*Recommended next*: post-pivot, the scanner is one signal, and competing on
raw detection depth is the losing game the strategy explicitly avoids. These
stay tracked because the built-in signal still needs maintenance — not
because they lead.

| Item | Notes |
|---|---|
| Per-format op/custom-code depth | **Shipped** for every format where static analysis is feasible: pickle opcodes, Keras (incl. non-`Lambda` custom layers), ONNX, TF SavedModel (exec + host-I/O ops), TFLite, GGUF, Paddle (`py_func`), CoreML (`CustomModel` + custom layers), and OpenVINO IR. TensorRT/MXNet stay format-ID + exfil. The one thing left — `declared`-vs-`reachable` dataflow — is **out of scope** (see below). |
| More exfil encodings | UTF-16, base64/hex/base32/base85, one gzip/zlib layer, and **single-byte XOR** are covered — decoded blobs are only flagged when they resolve to a real endpoint/command indicator, so no rise in the false-positive rate (verified 0% over the real-model set). Remaining: **multi-byte / rolling-key XOR** (infeasible to key-recover generally). Note: the XOR path deliberately confirms only *structural* indicators (webhook/URL/code/private-key), not narrow-charset credential regexes, which alias with quantized weight bytes. |
| Packed-binary C2 endpoints | Endpoints stored as packed bytes (no ASCII/UTF-16 form) aren't extracted; needs structured per-format parsing. |

## Candidates — provenance & trust

| Item | Notes |
|---|---|
| Origin database provenance — **documented** | Sourcing + review cadence now documented in the file header (`data/org_countries.yaml`: HQ-country heuristic, advisory-only, outranked by verified signatures, re-verified each minor release). The stronger alternative — deriving origin *only* from verified signers — remains available to strict deployments today via `require_signed` + a curated trust store. |

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
| **Upstream scan-verdict enrichment** — **SHIPPED (incl. caching)** | Ingestion shipped (see *Recently shipped*: `purser.signals`, source `hf-verdicts`), and verdict lookups now cache per process (`PURSER_SIGNAL_CACHE_TTL`; commit-sha revisions for the process lifetime; failures never cached). |
| **Loader-CVE mapping (OSV/GHSA, offline)** — **promoted to Recommended next #3** | No feed of malicious *models* exists, but framework/parser CVEs do: map a detected format + declared version to known load-time RCEs (`.keras`/`.h5` CVE-2025-9906/-9905 `safe_mode` bypass, Keras Lambda CVE-2024-3660, llama.cpp GGUF parser CVEs; CWE-502 class). Ingest bulk **OSV-JSON** (`ossf/osv-schema`, CC-BY-4.0) or the GHSA mirror **offline**; emit "load-unsafe under `<framework> <version>`". Also flags OSV `MAL-` malicious-*package* records against bundled deps. Build as a `purser.signals` source — offline, so it also breaks the signals-are-hub-only limitation. |
| **MITRE ATLAS technique tagging** — **SHIPPED** | Done: `atlas:AML.T####` tags appended to findings from a vendored rule-id → technique mapping (`data/atlas_map.yaml`; T0011 / T0025 / T0018 / T0010.003). Enrichment only, `PURSER_ATLAS=0` disables. Remaining refinement: refresh the mapping from `mitre-atlas/atlas-data` releases. |
| **Known-bad denylist + refresh** — **SHIPPED** | Done: a first-class `denylist:` policy block — SHA-256 content hashes, publisher globs, repo globs (always `BLOCK`), and `denylist.files` external hash feeds re-read per evaluation (refresh like AV signatures, no policy reload). Remaining opportunity: **seeding an open malicious-model hash/IOC feed** to populate it from — that market gap is still real. |
| **Signed AIBOM (model bill-of-materials)** | Extend the CycloneDX SBOM (today: the *package*) to a signed **model AIBOM** — files, hashes, formats, detected code surfaces, provenance/identity, verdict — as a cosign attestation. The static-provenance answer to W&B lineage (checksum/tamper-only, no signing) and to HiddenLayer's "AIBOM" marketing — but open and signed. |
| **Provenance interop (W&B / registry)** | Read a W&B **Artifact manifest + digest + lineage DAG** (open-source SDK, no execution) as a provenance signal, and ship a **W&B Automations → webhook** gate recipe: scan on new version/alias, block promotion to a **protected alias** (`Production`) on FAIL. Generalizes to any registry with a promotion webhook. |
| **Model-card / eval-attestation gate — remaining refinements** | The v1 gate **shipped** (see *Recently shipped* and *Planned — `purser-eval` companion*: opt-in `card-attestations` source). Left here: **score floors / coverage expressions** (needs a policy dimension), **hash cross-checks** of card-referenced files, non-HF card formats (eval-results files, Seekr-style test cards). |

## Planned — `purser-eval` companion (slice 1 shipped; behavioral slices scoped)

The control plane gains a **behavioral** signal source: a separate, opt-in
companion (a sibling of `purser-deep`) that produces eval-derived findings
feeding the same policy engine, report, and admission gate. Scoping first,
code second — this section is the scope.

**Interface (fixed before any analyzer exists).** `purser-eval` is just
another signal source: it emits `Finding`s onto the report's
`signal_findings` channel (or serves them over HTTP like `purser-deep`'s
`/v1/deep-scan`), so nothing in the core changes when it lands. Findings are
policy-tunable per rule like everything else.

**Tractable first slices, in order:**

1. **Model-card / eval-attestation gate (static — first). SHIPPED** as the
   opt-in `card-attestations` signal source (`PURSER_CARD_ATTESTATIONS=1`):
   absence of a model card or of declared `model-index` eval results
   surfaces as LOW findings that policy rules can `ignore` or escalate to
   `deny`. Governs the claim, not the behavior. Remaining refinements:
   score floors / required-coverage expressions (needs a policy dimension),
   and cross-checking hashes a card references against the actual files.
2. **Wrap existing OSS eval/red-team tooling.** Adapters that run e.g.
   `garak` LLM probes *in the eval companion's own sandbox* and translate
   results into findings behind the same interface. Purser orchestrates and
   gates; it does not reinvent probes.
3. **Extend `purser-deep` weight analysis** where a static signal genuinely
   helps (stego/tampering already ship there).

**Explicit non-goals.** No trained-backdoor / data-poisoning *detection*
claims — that is an open research problem and out of scope (see the
out-of-scope table). The **core never executes a model**; anything dynamic
lives only in the separate, opt-in eval image, clearly labeled as a
heuristic second opinion, never a soundness gate.

## Candidates — operability

| Item | Notes |
|---|---|
| Global memory accountant | Per-scan windowing + finding cap + concurrency cap bound memory in practice; a cross-request budget would be stricter. |
| Exfil scan latency on huge models *(pulled into Recommended next #3 — post-pivot this is adoption friction on the gate's main path, not polish)* | A multi-hundred-MB weight file still takes ~20 s. Cost (profiled) is per-string iteration over the ~millions of printable runs weight data yields, not the regexes. **Done:** length-gate the secret (>=14) / encoded (>=64) heuristics in `scanners/exfil.py` (~30% win, no detection change). **Avoid:** a buffer-wide regex rewrite — non-anchored patterns (IP:port, code/secret alternations, `{64,}` encoded) backtrack over the full binary and made it ~2x slower. **Next:** scan only structural/metadata regions of known formats (also the prerequisite for the packed-binary-C2 residual), or lower the default per-file byte cap (`PURSER_MAX_SCAN_MB`). |

## Candidates — distribution / UX

| Item | Notes |
|---|---|
| Admission-webhook depth — **promoted to Recommended next #2** | The `ValidatingAdmissionWebhook` (shipped) enforces image-digest pinning + approved-model digests at deploy time. Next: a controller that *populates* the approved-digest set automatically from scan results (today it is operator-managed via the ConfigMap / GitOps), and optional cosign attestation verification instead of a digest allowlist — the piece that closes the scan→approve→admit loop. |

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
| Dynamic evaluation — bias, reliability, adversarial-robustness, behavioral backdoors / poisoning | Out of scope for the never-execute **core**: all require **running** the model against inputs. The vendors in this space are dynamic (Seekr *SeekrGuard*, W&B *Weave* scorers, F5/SurePath red-team, `garak`, `promptfoo`). The **separate opt-in companion** path is now scoped as *Planned — `purser-eval` companion* above (attestation gate first; wraps existing eval / red-team tooling; never folded into the static core). Static weight *steganography / tampering* is already covered by `purser-deep`. |
| Determined / volumetric DoS | The concurrency cap, per-client rate limit, and per-file windowing bound resource use, but absorbing a determined flood is the job of an edge proxy / WAF / autoscaler, not the scanner. |
| Spoofed provenance when signing is not required | By design, origin/publisher is *advisory* unless a policy sets `require_signed`. Enforce trust with `policies/signed-only.yaml` + a trust store; Purser will not treat unsigned claims as authoritative on its own. |
| Threat-intel **dashboards / hosted feed service** | Running a hosted threat-intel service or SOC dashboards is enterprise-platform territory (Guardian, HiddenLayer). **Correction (2026-07):** *ingesting* existing free feeds (HF scan verdicts, OSV/GHSA loader-CVEs, MITRE ATLAS) and maintaining an offline known-bad denylist are **no longer out of scope** — they moved to *Candidates — ecosystem intelligence & provenance interop*. There is still **no** open feed of malicious *model artifacts* to consume; that gap is real. |

---

## Recently shipped

Moved out of the roadmap now that they're done (see [`CHANGELOG.md`](CHANGELOG.md)
for per-release detail):

- **Pluggable signal sources + HF upstream verdicts:** a `purser.signals`
  subsystem where external intelligence plugs into the policy engine as a
  first-class signal (`signal_findings` on the report, policy rule overrides
  apply, entry-point group `purser.signals` for third-party sources). First
  two sources: `hf-verdicts` — the Hub's own per-file scan verdicts
  (picklescan / ClamAV / Protect AI / JFrog / VirusTotal) corroborate
  `-hf`-path scans — and the opt-in `card-attestations` gate
  (`PURSER_CARD_ATTESTATIONS=1`; `CARD_MISSING` / `CARD_NO_EVAL_RESULTS`).
  Upstream `safe` never downgrades Purser's own verdict, local scans stay
  fully offline, and gates are env-controlled (`PURSER_SIGNALS`,
  `PURSER_SIGNAL_<NAME>`, `PURSER_SIGNAL_TIMEOUT_SECONDS`).

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
  check, `CITATION.cff`, a `py.typed` marker, package `[project.urls]`, and full
  governance docs (`GOVERNANCE.md`, `MAINTAINERS.md`, `OWNERS`, `ADOPTERS.md`).
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
- **Python source dataflow/taint:** an intraprocedural, per-scope taint pass over
  bundled `.py` that catches payloads the literal name-match misses — a dangerous
  callable **aliased** to a variable then invoked (`sink = os.system; sink(cmd)` —
  previously *nothing*), a callable **dynamically resolved** from a decoded/
  char-assembled name (`getattr(os, decoded)(...)`), and **deobfuscated data**
  passed to a code-exec/os/native sink (`exec(b64decode(...))`). Analysis is
  per-scope so a variable name in one function can't taint a sibling's (kills the
  cross-context FP), and sinks are narrowed to the code-execution surface — over a
  4,854-file real-Python corpus it fires **twice** (both genuine `ctypes.WinDLL`
  aliases). Deliberate non-goals: cross-scope (closure) taint and pure
  string-literal split names (`"sy"+"stem"`) stay at the existing MEDIUM
  getattr-indirection signal. New rules `PY_DYNAMIC_CALL` / `PY_TAINTED_FLOW`;
  adds the `alias-callable` evasion sample (recall 17/17).
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
