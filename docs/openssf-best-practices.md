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
| Semantic versioning | Met | `0.1.x`; tags `v0.1.0`…`v0.1.3` |
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
| Automated test suite | Met | 250 tests in `tests/` |
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

## Submitting (project owner)

1. Sign in at https://www.bestpractices.dev/ with the `purser-io` GitHub account.
2. "Add project" → repo URL `https://github.com/purser-io/purser`.
3. Answer each criterion using the table above (URLs point at the evidence).
4. On completion you receive a project **ID**; add the badge to `README.md`:

   ```markdown
   [![OpenSSF Best Practices](https://www.bestpractices.dev/projects/<ID>/badge)](https://www.bestpractices.dev/projects/<ID>)
   ```
