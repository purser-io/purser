# Changelog

All notable changes to Purser are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html). Per-release
GitHub notes are generated automatically; this file is the curated summary.

## [Unreleased]
### Changed
- **Repositioned as a model supply-chain control plane.** README, roadmap,
  package/CLI/API descriptions now lead with what differentiates Purser —
  policy + provenance + enforcement across CI and Kubernetes admission, with
  scanning as one signal input. No functional change; the never-execute
  guarantee and "clean scan ≠ safe" scope statements are unchanged.

### Added
- **Pluggable signal sources (`purser.signals`).** External intelligence about
  a scanned artifact now plugs into the policy engine as a first-class signal:
  findings land on a new `signal_findings` report channel, count toward the
  verdict, honor policy `rules:` overrides, and third-party sources register
  via the `purser.signals` entry-point group (a plugin that fails to load
  surfaces as a `SIGNAL_UNAVAILABLE` coverage-gap finding, never an error).
  Gates: `PURSER_SIGNALS=0` (all), `PURSER_SIGNAL_<NAME>=0` (per source),
  `PURSER_SIGNAL_TIMEOUT_SECONDS` (default 10).
- **HuggingFace upstream scan-verdict ingestion** (signal source
  `hf-verdicts`). Scans on the `-hf` path (`hf://` targets,
  `POST /v1/scan/huggingface`) also read the Hub's own scan results
  (`securityRepoStatus` via `?securityStatus=true`, per-scanner detail via
  `paths-info` — verified against the live API) — inheriting its picklescan /
  ClamAV / Protect AI / JFrog / VirusTotal scans — and surface upstream
  `unsafe` / `caution` as corroborating `HF_UPSTREAM_UNSAFE` (HIGH) /
  `HF_UPSTREAM_SUSPICIOUS` (MEDIUM) findings, with the flagging scanners
  recorded as evidence. An upstream `safe` verdict never downgrades Purser's
  own analysis, and plain local scans remain fully offline
  (regression-tested). Honors `HF_ENDPOINT` and `HF_TOKEN`.
- **Model-card / eval-attestation gate** (signal source `card-attestations`,
  opt-in via `PURSER_CARD_ATTESTATIONS=1`) — the first `purser-eval` slice,
  static by design. On hub scans it reads the declared model card and
  `model-index` eval results and reports their *absence* (`CARD_MISSING`,
  `CARD_NO_EVAL_RESULTS`, both LOW) so policy can require documented models
  (`rules: {id: CARD_MISSING, action: deny}` blocks them). Attestation
  presence is deliberately not a finding and never improves a verdict.
- **Known-bad denylist policy dimension** (`denylist:` block). Exact
  file-content SHA-256s, publisher globs, and repo/name globs that always
  `BLOCK` (`POLICY_DENYLIST_HASH` / `_PUBLISHER` / `_MODEL`), plus
  `denylist.files` — external hash-feed files re-read on every evaluation so
  a refreshed feed (remounted ConfigMap, synced IOC list) takes effect
  without a policy reload. The offline AV-signature analogue for model
  artifacts; generalizes the existing publisher/name blocklists with content
  hashes.
- **Scan→approve→admit loop** (`core/approvals.py`, opt-in
  `PURSER_AUTO_APPROVE=1`). Verdicts now populate the admission webhook's
  approved-digest list automatically: verdicts in
  `PURSER_AUTO_APPROVE_VERDICTS` (default `PASS`) approve each scanned file's
  SHA-256, and `FAIL`/`BLOCKED` revokes previously-approved digests. Two
  backends: a plain file (`PURSER_APPROVALS_PATH`, the exact format the
  webhook reads — GitOps it into the ConfigMap) or an in-cluster ConfigMap
  patched through the Kubernetes API with the pod's ServiceAccount (stdlib
  HTTP, no client dependency; Helm `admission.autoApprove.enabled` wires the
  env + a Role scoped to that one ConfigMap). Every action is surfaced in the
  report's `metadata.approvals` and audit log; store failures degrade to a
  recorded error, never a broken scan.
- **HuggingFace Space live demo** (`demo/hf-space/`, push-ready): Gradio app
  running the real scanner + policy engine on uploads or Hub repos, with
  upstream-verdict ingestion; deploy instructions in `DEPLOY.md`.
- **Launch + foundation docs:** a control-plane launch-post draft
  (`docs/launch-control-plane.md`) and a CNCF Sandbox application draft with
  explicit readiness gates (`docs/cncf-sandbox-application.md`).
- **Dataflow/taint analysis of bundled Python source.** A per-scope,
  intraprocedural taint pass catches trust-remote-code payloads assembled or
  resolved at runtime that a literal call-name match misses: a dangerous callable
  **aliased** to a variable then invoked (`sink = os.system; sink(cmd)` — formerly
  undetected), a callable **dynamically resolved** from a decoded / char-assembled
  name (`getattr(os, decoded)(...)`), and **deobfuscated data** flowing into a
  code-execution / os-command / native sink (`exec(b64decode(...))`). New findings
  `PY_DYNAMIC_CALL` and `PY_TAINTED_FLOW`. Analysis is per-scope (a name in one
  function can't taint a sibling's) and narrowed to the code-execution surface —
  verified to fire only twice over a 4,854-file real-Python corpus (both genuine
  `ctypes.WinDLL` aliases), and the benign model corpus is unaffected.
- **Detect protocol-0/1 (ASCII) pickles disguised under a structured-binary
  extension.** An ASCII pickle renamed `.onnx`/`.pb`/`.tflite`/`.pte`/`.pdmodel`
  is now confirmed with a `pickletools.genops` trial-parse and scanned as the
  pickle it is (previously only flagged as a format mismatch, not classified by
  payload). Real protobuf/flatbuffer models are never misrouted — they begin with
  field tags (`0x08`/`0x0a`) or a flatbuffer offset and must parse cleanly to a
  pickle `STOP` — verified 0 misroutes over the real-model corpus (incl. a 418 MB
  ONNX). Closes the corresponding adversarial-evasion residual (recall 16/16).

## [0.2.1] - 2026-07-28
### Fixed
- **Upload scans no longer block the event loop.** `POST /v1/scan/upload` is an
  async handler but ran the synchronous, CPU-bound `scan_target` inline, which
  stalled the single uvicorn worker for the whole scan — so `/metrics`,
  `/healthz`, and the liveness probe hung while a scan ran (a large scan could
  time out Prometheus scrapes and trip a pod restart), and the
  `purser_scans_in_progress` gauge could never be scraped as non-zero. The scan
  now runs via `run_in_threadpool`, keeping the loop responsive, making the
  in-flight gauge observable, and letting `PURSER_MAX_CONCURRENT_SCANS`
  genuinely gate concurrency. (`scan_path`, a sync `def`, was already offloaded
  by Starlette.) Guarded by a regression test that asserts `/metrics` responds
  mid-scan.

## [0.2.0] - 2026-07-27
### Added
- **Foundation readiness (roadmap #1).** Added a full **OpenSSF Best Practices** *passing*-criteria self-assessment (`docs/openssf-best-practices.md`) — every MUST mapped to in-repo evidence, two justified N/A; the badge is earned by the owner self-certifying at bestpractices.dev. Also a prepared **CNCF Landscape** entry (`docs/cncf-landscape-entry.md`), submission deferred until the landscape's traction/organization inclusion bar is met.
- **Validation benchmark corpus expanded to 75 real models** (roadmap #1). The benign negative set grew from 14 to **75 pinned HuggingFace models** — a broad architecture sweep (encoders, causal/seq2seq LMs, vision, audio, multimodal) across pickle / safetensors / ONNX / Keras incl. int8-quantized ONNX — re-measured at **0% FPR** (0/79), TPR 100%. `fetch_benign.py` now pins one representative ONNX per repo (primary + quantized) rather than every quantization variant, keeping the corpus CI-friendly.
- **Format breadth → ~35 identified formats.** New detection for **TorchServe `.mar`** (`MAR_HANDLER_CODE` — bundled `handler.py` runs on serve), **MLflow** `MLmodel` (`MLFLOW_PYFUNC_LOADER` — `python_function` loader/code runs on load), and **Caffe** `.prototxt`/`.caffemodel` (`CAFFE_PYTHON_LAYER` — `PythonLayer` runs at inference) — all real code-execution surfaces, so they get dedicated scanners. Plus data-only identification (policy-allowlist + exfil) for **NeMo `.nemo`**, **H2O MOJO**, **Darknet `.weights`**, **LightGBM** native, and **Torch7 `.t7`** (NeMo/MOJO archives recursed).
- **Per-format scanner depth** (roadmap #2): Keras scanning now flags **non-`Lambda` custom layers** — the model config is walked for layer classes whose `module` is outside the Keras/TF namespaces (v3) or that aren't builtin (legacy H5), i.e. layers that run external code on load (`KERAS_CUSTOM_LAYER`); works with or without h5py. A new **OpenVINO IR** scanner safely parses the `.xml` graph and flags DOCTYPE/entity declarations (XXE / entity-expansion) and references to host shared libraries or absolute paths (`OPENVINO_XXE`, `OPENVINO_EXTERNAL_REF`). **TF SavedModel** op coverage broadened to queue-based host file readers, and **CoreML** now flags the `CustomModel` backend (`COREML_CUSTOM_MODEL`, whole-model native code) in addition to custom layers. Verified 0% FPR over the real HuggingFace models. This completes roadmap #2 for what a static, no-load scanner can do — `declared`-vs-`reachable` dataflow (framework-load-dependent) is out of scope.
- **Sigstore verified-identity provenance** (`purser[sigstore]`): verify a model's Sigstore (Fulcio/Rekor) bundle — a `.sigstore.json` sidecar — **offline** against a vendored trust root, deriving a *verified external-root identity* (OIDC issuer + SAN) instead of the operator-asserted Ed25519 trust store. A verified identity satisfies `require_signed`; a new `identity` policy block pins allowed/blocked issuers + SAN globs. Covers cosign keyless and HuggingFace Sigstore-based model signing; signing stays external. `purser verify` reports the identity. Refresh the vendored root with `make sigstore-trust-root`. (Roadmap #2.)
- **base85 exfiltration decoding:** the exfil engine now decodes base85 (RFC 1924) blobs and re-analyzes them, alongside the existing base64/hex/base32 + one gzip/zlib layer. Flagged only when the decoded bytes resolve to a real URL/secret/code indicator, so base85's permissive alphabet doesn't raise the false-positive rate. Surfaced and then closed as a measured gap by the Phase-3 evasion suite.
- **Single-byte XOR de-obfuscation:** the exfil engine recovers single-byte-XOR-obfuscated endpoints/commands via a key-invariant delta-signature search (no brute force), confirming a contiguous printable run that contains a *structural* indicator (webhook/URL/code/private-key). Narrow-charset credential regexes are excluded from this path because they alias with quantized weight bytes; verified 0% false-positive rate over the real-model benchmark. Disable with `PURSER_EXFIL_XOR=0`.
- Helm chart: an optional **PrometheusRule** alert set (`metrics.prometheusRule.enabled`) — target-down, scan errors (incl. deep-companion unavailable), FAIL/BLOCKED spike, policy blocks, load-shedding, and auth-failure spikes, wired to the existing `/metrics` series.
- **TensorRT** engine recognition: `.engine`/`.plan`/`.trt` are now identified as a `tensorrt` format (data-only/opaque, like MXNet/GGML) so policy can allow/deny them and reports name them; the format-agnostic exfiltration scan runs over their bytes. Deep graph parsing remains a roadmap candidate.
- **Kubernetes admission webhook** (`purser.admission`, Helm `admission.enabled`): a `ValidatingAdmissionWebhook` that enforces image-digest pinning and approved-model digests at deploy time, closing the scan→deploy TOCTOU gap. Opt-in per namespace/pod, fail-closed by default, with a chart-generated + retained serving cert wired into the webhook `caBundle`.
- **Validation benchmark, Phases 2–4:** a peer-scanner head-to-head comparison (`benchmarks/compare.py` vs picklescan/ModelScan/Fickling/ModelAudit); a Phase-3 adversarial **evasion suite** (`benchmarks/evasion.py`) measuring evasion recall over techniques Purser claims to resist (spoofed extensions, nested archives, `STACK_GLOBAL`/`posix` pickles, encoded/obfuscated exfil) while reporting known-open residuals (packed-binary endpoints, protocol-0 ASCII pickle under a structured extension); regression-gate flags on `run.py` (`--min-tpr`/`--max-fpr`) and `evasion.py` (`--min-recall`); an expanded benign corpus; and a scheduled CI workflow (`benchmark.yml`) that fails on a detection drop, FPR rise, or evasion-recall regression. Published numbers in `benchmarks/README.md`.

## [0.1.3] - 2026-07-24
### Fixed
- Exfiltration false positives on binary/quantized weights: the secret and
  encoded-payload heuristics are now **entropy-gated** (a chance `hf_...` or hex
  run inside weight bytes no longer flags), the HuggingFace-token pattern is
  length-bounded, and `.cache/` directories are skipped. Surfaced by the new
  validation benchmark, where a benign quantized ONNX model was hard-failing.

### Performance
- Faster exfil scanning of large binaries: the secret and encoded-payload
  heuristics skip the short printable runs that cannot contain them (~30% faster
  on a 268 MB quantized ONNX; no detection change).

### Added
- A composite **GitHub Action** (`action.yml`) — `uses: purser-io/purser@<ref>` runs a scan and gates CI on the policy verdict.
- Ship a `py.typed` marker (PEP 561) so type checkers pick up Purser's type
  hints; add project URLs to the package metadata; `CITATION.cff`.

## [0.1.2] - 2026-07-23
### Fixed
- **Resist extension/name disguise.** Magic bytes now beat a spoofed extension:
  a protocol-2+ pickle renamed `model.onnx` / `weights.pb` is detected and
  scanned as the pickle it is (previously a silent PASS), and directory walks
  magic-sniff files hidden under doc/config extensions (e.g. a pickle named
  `README.md`) instead of skipping by name. Real safetensors are disambiguated
  so they are not misrouted.

### Added
- `demo/` directory — a block-China origin policy, a stdlib sample-model
  generator, and a walkthrough README for trying the CLI.

## [0.1.1] - 2026-07-19
### Added
- **PyPI publishing.** The release pipeline builds the sdist + wheel and
  publishes via OIDC Trusted Publishing; the distributions are attached to the
  GitHub Release.

### Changed
- Container images and the Helm chart are public on GHCR; README and site
  install instructions use `pip install purser` and the published images.

## [0.1.0] - 2026-07-19
### Added
- Initial release: static malicious-code and data-exfiltration scanning across
  the major model formats; policy engine (severity / format / publisher / name /
  country-of-origin); Ed25519 signed provenance with a trust store; REST API and
  CLI; Prometheus metrics and an audit log; optional deep-analysis companion;
  digest-pinned Wolfi container images, kustomize manifests, and a Helm chart.

[0.2.1]: https://github.com/purser-io/purser/releases/tag/v0.2.1
[0.2.0]: https://github.com/purser-io/purser/releases/tag/v0.2.0
[0.1.3]: https://github.com/purser-io/purser/releases/tag/v0.1.3
[0.1.2]: https://github.com/purser-io/purser/releases/tag/v0.1.2
[0.1.1]: https://github.com/purser-io/purser/releases/tag/v0.1.1
[0.1.0]: https://github.com/purser-io/purser/releases/tag/v0.1.0
