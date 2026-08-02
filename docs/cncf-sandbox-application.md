# CNCF Sandbox application — draft

Working draft for the [Sandbox application form](https://github.com/cncf/sandbox)
(submitted as an issue there; reviewed by the TOC on a rolling basis).
**Do not submit yet** — see *Readiness gates* at the bottom.

---

## Application answers (draft)

**Project name:** Purser

**Description:** The open-source model supply-chain control plane: a policy,
provenance, and enforcement layer for ML model artifacts. Purser aggregates
signals about a model — its own never-execute static scanner (~35 formats),
upstream scanner verdicts (e.g. the HuggingFace Hub's scan pipeline), an
opt-in model-card/eval-attestation gate,
Ed25519/Sigstore verified provenance, and pluggable third-party sources (the
`purser.signals` entry-point interface) — and
renders a single policy verdict enforced in CI (exit codes / GitHub Action),
via a REST API, and at deploy time through a Kubernetes
`ValidatingAdmissionWebhook` that rejects pods referencing unapproved model
digests or unpinned images.

**Repository:** https://github.com/purser-io/purser · **License:** Apache-2.0

**Website:** https://purser-io.io

**Cloud-native fit / TAG alignment:** Security TAG (primary), AI TAG
(secondary). Purser is Kubernetes-native where it matters: distributed as
signed multi-arch OCI images + a signed Helm chart (OCI), configured via
ConfigMaps, observable via Prometheus metrics + a `PrometheusRule` starter
set + a Grafana dashboard, and its distinguishing enforcement primitive is a
fail-closed admission webhook — the model-artifact analogue of image
admission controllers (Kyverno/OPA for models). It closes the scan→deploy
TOCTOU gap that CLI scanners leave open.

**Comparable / adjacent projects:** in-toto, Sigstore (Purser consumes
Sigstore verification offline), Kyverno/OPA Gatekeeper (image policy; Purser
does model-artifact policy), OSS scanners (picklescan/ModelScan/ModelAudit —
scanning only, no policy/enforcement plane; Purser can ingest rather than
compete). No CNCF project owns "unified model gate: scan + intel +
provenance + policy + admission." (The gate is static/attestation-based by
design — it does not evaluate model behavior, and its docs say so plainly.)

**Vendor neutrality / IP:** No company behind the project; the trademark,
logo, and domain are unencumbered and the maintainer is willing to donate
them to the Linux Foundation (`GOVERNANCE.md` §10, `TRADEMARKS.md`).

**Maturity signals:** OpenSSF Best Practices **passing** badge (project
13900); released on PyPI + GHCR; CI with a 3.11–3.14 test matrix, CodeQL,
dependency-review, Trivy/osv-scanner gates; SLSA provenance + SBOM
attestations, cosign-signed artifacts; DCO enforced; a published validation
benchmark (known-answer TPR, 0% FPR over 75 real models, adversarial evasion
suite) re-measured weekly in CI; governance docs (`GOVERNANCE.md`,
`MAINTAINERS.md`, `OWNERS`, `ADOPTERS.md`).

## Readiness gates (why not submit today)

The TOC favors momentum and >1 maintainer; a solo, single-digit-stars
project risks a "come back later." Close these first:

1. **A second maintainer** (independent org if possible) — the single
   strongest signal. Recruit via the launch post + good-first-issues.
2. **2–3 named adopters** in `ADOPTERS.md` — even homelab/eval-stage users
   count at Sandbox level; production users are better.
3. **The control-plane launch** shipped (`docs/launch-control-plane.md`) so
   reviewers see the positioning, the live Space demo, and some traction.

When those exist, file the application issue using the answers above, and
notify the Security TAG (#tag-security) for a friendly pre-review.
