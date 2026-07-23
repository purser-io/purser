# Changelog

All notable changes to Purser are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html). Per-release
GitHub notes are generated automatically; this file is the curated summary.

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

[0.1.2]: https://github.com/purser-io/purser/releases/tag/v0.1.2
[0.1.1]: https://github.com/purser-io/purser/releases/tag/v0.1.1
[0.1.0]: https://github.com/purser-io/purser/releases/tag/v0.1.0
