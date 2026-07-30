# Purser Governance

This document defines how the **Purser** project is governed: the roles, how
decisions get made, and how the project's stewardship evolves. It is intended to
scale from the current small team to a broader community, and to satisfy the
governance expectations of open-source foundations (e.g. the OpenSSF Best
Practices badge and CNCF project hosting).

Companion documents: [`MAINTAINERS.md`](MAINTAINERS.md) (who the maintainers
are), [`OWNERS`](OWNERS) (machine-readable approver/reviewer list),
[`CONTRIBUTING.md`](CONTRIBUTING.md) (how to contribute),
[`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md), [`SECURITY.md`](SECURITY.md), and
[`ADOPTERS.md`](ADOPTERS.md).

## 1. Mission and scope

Purser is a **static** security scanner for machine-learning model artifacts. It
detects malicious code and data-exfiltration indicators and enforces
policy-based supply-chain controls **without ever deserializing or executing a
model**. In scope: byte/opcode/AST/structural analysis of model files, a policy
engine, verified provenance, and the CLI / REST API / container / Kubernetes
delivery around them. Out of scope is captured in
[`SECURITY.md`](SECURITY.md) (threat model) and [`ROADMAP.md`](ROADMAP.md).

## 2. Principles

Decisions are weighed against these, in tension order:

1. **Never execute a model.** The no-load guarantee is inviolable; no feature
   may deserialize or run untrusted model content.
2. **Low false-positive rate.** A detection that floods users with noise is a
   regression; new detection logic must hold the benchmark's measured FPR.
3. **Defense-in-depth, honestly scoped.** A PASS means "clear of known malicious
   content," not "certified safe" — claims stay calibrated to what static
   analysis can prove.
4. **Transparency.** Design decisions, security posture, and residual risk are
   documented in the open.

## 3. Roles

### Contributors
Anyone who files an issue or opens a pull request. Contributors need no prior
standing; every contribution goes through the same review (see §5).

### Reviewers
Contributors with a track record in an area may be granted reviewer status for
that area by a maintainer. Reviewers may formally review and approve changes;
their approval counts toward merge requirements. Reviewers are listed as
`reviewers` in [`OWNERS`](OWNERS).

### Maintainers
Maintainers are responsible for the technical direction, code review, releases,
security response, and community health of the project. They have merge rights
and are the set of people who make binding project decisions. Maintainers are
listed in [`MAINTAINERS.md`](MAINTAINERS.md) and as `approvers` in
[`OWNERS`](OWNERS).

Maintainer responsibilities:
- Review and merge contributions, or explain why not.
- Uphold the principles (§2), the review bar (§5), and the Code of Conduct.
- Triage issues and security reports (see [`SECURITY.md`](SECURITY.md)).
- Cut releases (§6).
- Grow the maintainer/reviewer base and mentor contributors.

## 4. Decision-making

The project runs on **lazy consensus**: a proposal proceeds unless someone
raises a substantive, unresolved objection.

- **Routine changes** (bug fixes, tests, docs, incremental detection depth) are
  decided in the pull request. Merge requires the review bar in §5.
- **Substantial changes** (new detection engines, policy-model changes, public
  API or CLI changes, security-relevant behavior, dependencies, governance)
  should start as a GitHub issue describing the motivation and approach. Allow at
  least **7 days** for maintainer/community feedback before merging, unless it is
  an urgent security fix.
- **Objections** must be technical and actionable. The proposer works to resolve
  them; unresolved objections escalate to a maintainer decision (below).
- **Maintainer decisions.** When consensus is not reached, the maintainers
  decide by simple majority of active maintainers. No change merges over the
  sustained, unaddressed objection of a maintainer. Decisions and their
  rationale are recorded in the relevant issue/PR.

## 5. Contribution review bar

Every change to `main` must:
- carry a **DCO `Signed-off-by`** line matching the author (enforced in CI);
- pass **CI** — `ruff`, `pytest` on Python 3.11–3.14, Helm lint, the image build
  + Trivy scan, dependency-review, and CodeQL;
- include **tests** for new behavior — per [`CONTRIBUTING.md`](CONTRIBUTING.md),
  new detection logic needs both a malicious and a benign fixture, and must not
  regress the measured false-positive rate;
- receive approval from at least **one maintainer** (or an area reviewer plus a
  maintainer) who is **not** the author. Once there is more than one maintainer,
  authors do not merge their own changes without a second approval.

## 6. Releases

Purser follows [Semantic Versioning](https://semver.org). Releases are cut by a
maintainer by tagging `vX.Y.Z` on `main`, which drives the automated pipeline
(build + sign container images and the Helm chart, publish to PyPI via OIDC
Trusted Publishing, and create the GitHub Release). Every release has a curated
[`CHANGELOG.md`](CHANGELOG.md) entry. Any maintainer may propose a release; there
is no fixed cadence.

## 7. Becoming, and stepping down as, a maintainer

**Adding a maintainer.** A candidate has typically demonstrated sustained,
high-quality contributions and sound review judgment over a period of months,
and adheres to the Code of Conduct. Any maintainer may nominate a candidate in a
pull request that adds them to [`MAINTAINERS.md`](MAINTAINERS.md) and
[`OWNERS`](OWNERS). Approval requires a **supermajority (two-thirds)** of current
maintainers with no sustained objection. While the project has a single
maintainer, that maintainer may add a second directly; thereafter this process
applies.

**Stepping down / emeritus.** Maintainers may step down at any time and are
listed as *emeritus* in `MAINTAINERS.md`. A maintainer who is unresponsive for
an extended period (roughly **six months**) may be moved to emeritus by a
maintainer decision; they may return by the same process used to add a
maintainer. Removal for Code of Conduct violations follows the enforcement
process below.

## 8. Code of Conduct

The project adopts the [Contributor Covenant](CODE_OF_CONDUCT.md). Reports and
enforcement go to **security@purser-io.io**. Maintainers are responsible for
fair, confidential enforcement and may take action up to and including removal.

## 9. Security

Vulnerabilities are handled per [`SECURITY.md`](SECURITY.md) — a private GitHub
security advisory (or the `security@purser-io.io` alias), acknowledged within
**3 business days**, under coordinated disclosure. Security fixes may bypass the
normal feedback window at maintainer discretion.

## 10. Licensing, DCO, and project ownership

Purser is licensed under **Apache-2.0** ([`LICENSE`](LICENSE)). All
contributions are made under that license and certified via the **DCO**. Trademark
and brand usage are described in [`TRADEMARKS.md`](TRADEMARKS.md).

The project currently lives under the `purser-io` GitHub organization. The
maintainers are open to donating the project to a **neutral foundation** (e.g.
the Linux Foundation / CNCF) if that serves its long-term health; such a move —
including any trademark, domain, and repository transfer — is a maintainer
decision made in the open under §4.

## 11. Amending this document

Changes to this document are proposed via pull request and require maintainer
approval under §4 (substantial-change process). The current, single-maintainer
reality is stated honestly here; this governance is written to scale as the
project attracts additional maintainers, and we actively welcome contributors on
that path.
