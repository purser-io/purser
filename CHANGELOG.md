# Changelog

All notable changes to Purser are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html). Per-release
GitHub notes are generated automatically; this file is the curated summary.

## [Unreleased]
### Added
- **base85 exfiltration decoding:** the exfil engine now decodes base85 (RFC 1924) blobs and re-analyzes them, alongside the existing base64/hex/base32 + one gzip/zlib layer. Flagged only when the decoded bytes resolve to a real URL/secret/code indicator, so base85's permissive alphabet doesn't raise the false-positive rate. Surfaced and then closed as a measured gap by the Phase-3 evasion suite.
- Helm chart: an optional **PrometheusRule** alert set (`metrics.prometheusRule.enabled`) — target-down, scan errors (incl. deep-companion unavailable), FAIL/BLOCKED spike, policy blocks, load-shedding, and auth-failure spikes, wired to the existing `/metrics` series.
- **TensorRT** engine recognition: `.engine`/`.plan`/`.trt` are now identified as a `tensorrt` format (data-only/opaque, like OpenVINO/MXNet) so policy can allow/deny them and reports name them; the format-agnostic exfiltration scan runs over their bytes. Deep graph parsing remains a roadmap candidate.
- **Kubernetes admission webhook** (`purser.admission`, Helm `admission.enabled`): a `ValidatingAdmissionWebhook` that enforces image-digest pinning and approved-model digests at deploy time, closing the scan→deploy TOCTOU gap. Opt-in per namespace/pod, fail-closed by default, with a chart-generated + retained serving cert wired into the webhook `caBundle`.
- **Validation benchmark, Phases 2–4:** a peer-scanner head-to-head comparison (`benchmarks/compare.py` vs picklescan/ModelScan/Fickling/ModelAudit); a Phase-3 adversarial **evasion suite** (`benchmarks/evasion.py`) measuring evasion recall over techniques Purser claims to resist (spoofed extensions, nested archives, `STACK_GLOBAL`/`posix` pickles, encoded/obfuscated exfil) while reporting known-open residuals (base85/XOR/packed-binary/protocol-0-ASCII-under-structured-ext); regression-gate flags on `run.py` (`--min-tpr`/`--max-fpr`) and `evasion.py` (`--min-recall`); an expanded benign corpus; and a scheduled CI workflow (`benchmark.yml`) that fails on a detection drop, FPR rise, or evasion-recall regression. Published numbers in `benchmarks/README.md`.

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

[0.1.3]: https://github.com/purser-io/purser/releases/tag/v0.1.3
[0.1.2]: https://github.com/purser-io/purser/releases/tag/v0.1.2
[0.1.1]: https://github.com/purser-io/purser/releases/tag/v0.1.1
[0.1.0]: https://github.com/purser-io/purser/releases/tag/v0.1.0
