# OpenSSF Best Practices — self-assessment

This maps Purser to the [OpenSSF Best Practices badge](https://www.bestpractices.dev/)
**passing** criteria, with the evidence for each. It is the working copy of the
answers to submit at bestpractices.dev; the badge itself is earned by the project
owner self-certifying there (see *Submitting* at the bottom).

Legend: **Met** · **N/A** (with justification) · **Partial** (met beyond the
passing requirement's floor, noted for transparency).

## Basics

| Criterion | Status | Evidence |
|---|---|---|
| Project description (what it does, why) | Met | `README.md`, https://purser-io.io |
| How to contribute | Met | `CONTRIBUTING.md` |
| Contribution requirements (style, tests, DCO) | Met | `CONTRIBUTING.md` (ruff + pytest; `Signed-off-by` DCO) |
| FLOSS OSI license | Met | Apache-2.0 — `LICENSE`, `pyproject.toml` |
| License in a standard location | Met | top-level `LICENSE` |
| Basic documentation | Met | `README.md`, `docs/` (data-scientist, DevSecOps, policy guides) |
| Interface/API documentation | Met | `README.md` (CLI, REST API, env vars), `docs/` |
| Project sites use HTTPS | Met | github.com/purser-io/purser, https://purser-io.io |
| Discussion mechanism | Met | GitHub Issues + issue forms (`.github/ISSUE_TEMPLATE/`) |
| Content in English | Met | all docs |
| Maintained (actively) | Met | active commit history; CHANGELOG |

## Change control

| Criterion | Status | Evidence |
|---|---|---|
| Public version-controlled source | Met | public git repo |
| Tracks changes + interim versions (distributed VCS) | Met | git |
| Unique version numbering | Met | SemVer in `pyproject.toml` / `Chart.yaml` |
| Semantic versioning | Met | `0.2.x`; tags `v0.1.0`…`v0.2.1` |
| Release notes for each release | Met | `CHANGELOG.md` (Keep-a-Changelog) + GitHub Releases |

## Reporting

| Criterion | Status | Evidence |
|---|---|---|
| Bug-reporting process | Met | GitHub Issues + `.github/ISSUE_TEMPLATE/bug_report.yml` |
| Responds to bug reports | Met | maintained; issue triage |
| Enhancement-request process | Met | `feature_request.yml` |
| Publicly archived report history | Met | GitHub Issues (public) |
| **Private** vulnerability-report process | Met | `SECURITY.md` — GitHub private advisory + `security@purser-io.io` |
| Vulnerability-report response time stated | Met | `SECURITY.md` — acknowledge ≤ **3 business days**, coordinated disclosure ≤ **90 days** |

## Quality

| Criterion | Status | Evidence |
|---|---|---|
| Working build (from source) | Met | `pyproject.toml` (hatchling) + `uv`; `Makefile`; multi-stage Dockerfiles |
| Common, FLOSS build tools | Met | `uv` / `pip`, `hatchling`, `helm`, `docker` |
| Automated test suite | Met | 292 tests in `tests/` |
| Test-invocation documented | Met | `CONTRIBUTING.md` (`uv run pytest -q`); `make test` |
| Tests cover the majority of the code | Met | unit + API + adversarial/evasion fixtures across scanners/policy/signing |
| Continuous integration | Met | `.github/workflows/ci.yml` (3.11–3.14 matrix, lint, tests, helm, image build + Trivy) |
| New functionality → new tests (policy) | Met | `CONTRIBUTING.md` ("new detection logic needs both a malicious and a benign fixture") |
| Compiler/linter warnings enabled | Met | `ruff` in CI (`E`/`F` rule sets); Trivy HIGH/CRITICAL gate |
| Warnings addressed | Met | CI fails on ruff findings; 0 open CodeQL alerts |

## Security

| Criterion | Status | Evidence |
|---|---|---|
| Developers understand secure design | Met | `SECURITY.md` (threat model, hardening, residual risk) |
| Know common implementation errors | Met | scanner never deserializes; zip-bomb/slip guards, size caps, path confinement |
| Uses published crypto protocols | Met | Ed25519 signatures; Sigstore (Fulcio/Rekor); cosign for artifacts |
| Uses existing crypto libraries (no roll-your-own) | Met | `cryptography`, `sigstore` |
| Crypto is FLOSS | Met | both libraries are OSS |
| Adequate key lengths | Met | Ed25519; SHA-256 manifests |
| No known-broken crypto | Met | no MD5/SHA-1 for security decisions |
| Secure random where needed | Met | stdlib `secrets`/`os.urandom` via `cryptography` |
| Delivery protected against MITM | Met | HTTPS PyPI; **hash-pinned** lockfiles (`--require-hashes`); cosign-signed images + Helm chart; SLSA provenance |
| Signed releases available | Met | cosign keyless (Fulcio/Rekor) images + chart; PyPI Trusted Publishing |
| Publicly-known vulnerabilities fixed ≤ 60 days | Met | Wolfi base CVE fixed same-session; CodeQL alerts triaged to **0 open** |
| No leaked credentials/secrets | Met | secret-scanning discipline; findings avoid echoing secrets; `HF_TOKEN` from env only |
| Password storage (if any) | N/A | no user passwords; the optional API key is compared in constant time and only a truncated SHA-256 is used as a rate-limit bucket id, never stored as a credential |
| Perfect forward secrecy | N/A | Purser terminates no TLS itself (served behind an ingress/proxy); no in-app key exchange |

## Analysis

| Criterion | Status | Evidence |
|---|---|---|
| Static analysis before release | Met | CodeQL (`.github/workflows/codeql.yml`) + `ruff`, on every push |
| Static analysis covers common vulns | Met | CodeQL default security queries |
| Static-analysis findings addressed | Met | 0 open alerts (27 triaged/dismissed with documented rationale; 3 fixed) |
| Static analysis run often | Met | every push + PR |
| Dynamic analysis | Partial | an adversarial **evasion suite** + a real-model **benchmark** exercise the scanners on inert samples (`benchmarks/`); structure-aware fuzzing of the pickle parser is a roadmap item (not required for *passing*) |

## Summary

All **passing**-level MUST criteria are met; the two N/A items are justified,
and dynamic-analysis exceeds the passing floor (evasion + benchmark harness),
with fuzzing tracked for the *silver* level. Silver/gold would additionally want
a written assurance case, a coverage threshold, and two-person review — future
work.

## Submission sheet (bestpractices.dev, in criterion order)

Copy-paste answer key, in the site's order. **Level** is the criterion's weight
(MUST / SHOULD / SUGGESTED). **Answer** is what to select; the text is the
justification to paste into that criterion's field. Only MUSTs (and justified
SHOULDs) gate the passing badge; SUGGESTED are bonus. Base URL below = the repo
`https://github.com/purser-io/purser`.

### Basics
| Criterion | Level | Answer | Justification to paste |
|---|---|---|---|
| description_good | MUST | Met | README + https://purser-io.io describe the tool: a model supply-chain control plane (policy, provenance, enforcement; static malicious-code + exfiltration scanning as one signal input). |
| interact | MUST | Met | GitHub Issues + issue forms (`.github/ISSUE_TEMPLATE/`). |
| contribution | MUST | Met | `CONTRIBUTING.md`. |
| contribution_requirements | SHOULD | Met | `CONTRIBUTING.md` — ruff + pytest, and a DCO `Signed-off-by`. |
| floss_license | MUST | Met | Apache-2.0 (`LICENSE`). |
| floss_license_osi | SUGGESTED | Met | Apache-2.0 is OSI-approved. |
| license_location | MUST | Met | Top-level `LICENSE`. |
| documentation_basics | MUST | Met | `README.md` + `docs/` (data-scientist, DevSecOps, policy guides). |
| documentation_interface | MUST | Met | `README.md` (CLI, REST API, env vars) + `docs/`. |
| sites_https | MUST | Met | github.com/purser-io/purser and https://purser-io.io are HTTPS. |
| discussion | MUST | Met | GitHub Issues (public, threaded). |
| english | SHOULD | Met | All docs are in English. |
| maintained | MUST | Met | Active commit history; maintained `CHANGELOG.md`. |

### Change Control
| Criterion | Level | Answer | Justification to paste |
|---|---|---|---|
| repo_public | MUST | Met | Public git repo on GitHub. |
| repo_track | MUST | Met | git tracks all changes. |
| repo_interim | MUST | Met | Interim commits between releases are in git history. |
| repo_distributed | SUGGESTED | Met | git (distributed VCS). |
| version_unique | MUST | Met | Unique SemVer in `pyproject.toml` / `Chart.yaml`. |
| version_semver | SUGGESTED | Met | Semantic Versioning. |
| version_tags | SUGGESTED | Met | Release tags `v0.1.0`…`v0.2.1`. |
| release_notes | MUST | Met | `CHANGELOG.md` (Keep-a-Changelog) + GitHub Releases per tag. |
| release_notes_vulns | MUST | Met | Security-relevant fixes are called out in `CHANGELOG.md` (e.g. exfil FP hardening, Wolfi base CVE); no unfixed known vulns at any release. |

### Reporting
| Criterion | Level | Answer | Justification to paste |
|---|---|---|---|
| report_process | MUST | Met | GitHub Issues + `bug_report.yml`. |
| report_tracker | SHOULD | Met | GitHub Issues. |
| report_responses | MUST | Met | Maintained; issues are triaged. |
| enhancement_responses | SHOULD | Met | `feature_request.yml` + triage. |
| report_archive | MUST | Met | GitHub Issues is a public, searchable archive. |
| vulnerability_report_process | MUST | Met | `SECURITY.md` — private reporting process documented. |
| vulnerability_report_private | MUST | Met | GitHub private security advisory **and** `security@purser-io.io` (live, monitored). |
| vulnerability_report_response | MUST | Met | `SECURITY.md` — acknowledge ≤ 3 business days, coordinated disclosure ≤ 90 days. |

### Quality
| Criterion | Level | Answer | Justification to paste |
|---|---|---|---|
| build | MUST | Met | `pyproject.toml` (hatchling) + `uv`; `Makefile`; multi-stage Dockerfiles. |
| build_common_tools | SUGGESTED | Met | `uv`/`pip`, hatchling, helm, docker. |
| build_floss_tools | SHOULD | Met | All build tools are FLOSS. |
| test | MUST | Met | 292 automated tests in `tests/`. |
| test_invocation | SHOULD | Met | `CONTRIBUTING.md` (`uv run pytest -q`); `make test`. |
| test_most | SUGGESTED | Met | Unit + API + adversarial/evasion coverage across scanners/policy/signing. |
| test_continuous_integration | SUGGESTED | Met | `.github/workflows/ci.yml` (3.11–3.14 matrix). |
| test_policy | MUST | Met | `CONTRIBUTING.md` — new detection logic needs a malicious **and** a benign fixture. |
| tests_are_added | MUST | Met | New functionality ships with tests (e.g. the taint pass and ASCII-pickle detection each added tests). |
| tests_documented_added | SUGGESTED | Met | The test-addition policy is documented in `CONTRIBUTING.md`. |
| warnings | MUST | Met | `ruff` (E/F) in CI; Trivy HIGH/CRITICAL image gate. |
| warnings_fixed | MUST | Met | CI fails on ruff findings; **0 open CodeQL alerts**. |
| warnings_strict | SUGGESTED | Met | ruff enforced in CI (E/F rule sets). |

### Security
| Criterion | Level | Answer | Justification to paste |
|---|---|---|---|
| know_secure_design | MUST | Met | `SECURITY.md` (threat model, hardening, residual risk); the scanner never deserializes/executes a model, and signal-source responses are parsed as data, never executed. |
| know_common_errors | MUST | Met | No deserialization; zip-bomb/zip-slip guards, size caps, path confinement; signal-source HTTP is hub-only with request timeouts, add-only findings, and fail-visible (`SIGNAL_UNAVAILABLE`) degradation. |
| crypto_published | MUST | Met | Ed25519 signatures; Sigstore (Fulcio/Rekor); cosign for artifacts. |
| crypto_call | SHOULD | Met | Uses `cryptography` / `sigstore` — no roll-your-own crypto. |
| crypto_floss | MUST | Met | Both crypto libraries are FLOSS. |
| crypto_keylength | MUST | Met | Ed25519; SHA-256 manifests. |
| crypto_working | MUST | Met | No MD5/SHA-1 used for security decisions. |
| crypto_weaknesses | SHOULD | Met | No known-broken algorithms in use. |
| crypto_pfs | SHOULD | N/A | Purser terminates no TLS itself (runs behind an ingress/proxy); no in-app key exchange. |
| crypto_password_storage | MUST | N/A | No user passwords; the optional API key is compared in constant time and only a truncated SHA-256 is used as a rate-limit bucket id, never stored as a credential. |
| crypto_random | MUST | Met | stdlib `secrets` / `os.urandom` via `cryptography`. |
| delivery_mitm | MUST | Met | HTTPS PyPI; hash-pinned lockfiles (`--require-hashes`); cosign-signed images + Helm chart; SLSA provenance. |
| delivery_unsigned | MUST | Met | Released artifacts are signed (cosign keyless; PyPI Trusted Publishing); no unsigned delivery channel is relied upon. |
| vulnerabilities_fixed_60_days | MUST | Met | Wolfi base CVE fixed same session; CodeQL alerts triaged to 0 open. |
| vulnerabilities_critical_fixed | SHOULD | Met | No open critical vulnerabilities. |
| no_leaked_credentials | MUST | Met | Secret-scanning discipline; findings avoid echoing secrets; `HF_TOKEN` from env only. |

### Analysis
| Criterion | Level | Answer | Justification to paste |
|---|---|---|---|
| static_analysis | MUST | Met | CodeQL (`.github/workflows/codeql.yml`) + `ruff`, every push. |
| static_analysis_common_vulnerabilities | SUGGESTED | Met | CodeQL default security queries. |
| static_analysis_fixed | MUST | Met | 0 open alerts (findings fixed; by-design `py/path-injection` dismissed with documented rationale). |
| static_analysis_often | SUGGESTED | Met | Runs on every push + PR. |
| dynamic_analysis | SUGGESTED | Met | An adversarial evasion suite + a real-model benchmark exercise the scanners on inert samples (`benchmarks/`). |
| dynamic_analysis_unsafe | SUGGESTED | N/A | Pure Python — no memory-unsafe languages to run under a memory-safety harness. |
| dynamic_analysis_enable_assertions | SUGGESTED | N/A | Pure Python; the test suite exercises assertions. |
| dynamic_analysis_fixed | MUST | Met | Issues surfaced by the benchmark/evasion harness are gated in CI and fixed in a timely way (e.g. the quantized-weight exfil FP). |

## Submitting (project owner)

**Registered — project ID 13900: 100% / PASSING** —
https://www.bestpractices.dev/projects/13900. The README badge is live and
auto-updates:

```markdown
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/13900/badge)](https://www.bestpractices.dev/projects/13900)
```

Maintenance: when facts change (test counts, new subsystems like
`purser.signals`, the description), refresh the corresponding answers on
bestpractices.dev using the submission sheet above as the source of truth —
the site copy of `description_good`, `know_secure_design`, and
`know_common_errors` should match this file.
