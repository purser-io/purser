# Purser Roadmap

Forward-looking work. Competitive positioning is in the
[comparison chart](README.md#how-purser-compares); shipped history is in
[`CHANGELOG.md`](CHANGELOG.md). This file tracks what is **not done yet** and why.

Purser is released and installable (**v0.1.2** — on PyPI, with signed multi-arch
container images and a signed Helm chart on GHCR, built and published by CI). The
security-hardening arc, supply-chain foundations (hash-pinned Wolfi builds, SBOM,
cosign/SLSA, multi-arch), model signing with revocation, the exfil /
`trust_remote_code` engines, observability, and disguise-resistant format
detection are all shipped (176 tests). What remains is **not** bug-fixing — it is
maturity, reach, and depth. See *Recently shipped* at the bottom.

Status legend: **planned** (agreed, not started) · **candidate** (worth doing,
undecided) · **deferred** (chosen not to do yet) · **out-of-scope**.

---

## Recommended next (priority order)

1. **Real-world validation + published benchmark.** Purser has adversarial unit
   fixtures but no measured false-positive/false-negative rates against a corpus
   of real (and known-malicious) models. Building that harness and publishing the
   numbers is the highest-leverage credibility step versus peers.
2. **External PKI / transparency trust root.** The largest remaining *trust*
   improvement for **model** provenance — move it from operator-asserted keys to a
   verified root (Sigstore Fulcio/Rekor or HuggingFace commit signatures). Note:
   Purser's own *artifacts* are already cosign-keyless-signed via Fulcio/Rekor.
3. **Per-format scanner depth (TensorRT, OpenVINO, non-`Lambda` Keras).** Closes
   the one area where the OSS peer **ModelAudit** leads (per the comparison chart).
4. **Enforcement primitive.** A Kubernetes `ValidatingAdmissionWebhook` or CI
   action that *enforces* the verdict (+ hash pinning) at deploy time, closing the
   scan→deploy TOCTOU gap.
5. **Foundation readiness.** Community scaffolding now ships (CONTRIBUTING, Code
   of Conduct, issue/PR templates, enforced DCO, `CITATION.cff`, `py.typed`) — next
   is a CNCF Landscape entry and an OpenSSF Best Practices badge.

---

## Planned

| Item | Notes |
|---|---|
| **External PKI / transparency trust root** | Model signing today is Ed25519 + a local trust store binding key→publisher→country — integrity and key-attested identity, but the key→identity binding is an operator assertion. Integrate Sigstore (Fulcio/Rekor) or HuggingFace commit-signature verification so identity derives from a verified external root. |
| **Wolfi base auto-refresh** | Drift *detection* ships (`wolfi-base-check.yml` compares the pinned digest to live `:latest` weekly and opens an issue). Remaining: automatically rebuild + `trivy`-scan + open a PR on drift, rather than a manual `make base-digest` bump. |

## Candidates — detection depth

| Item | Notes |
|---|---|
| Per-format graph parsing (TensorRT, OpenVINO, CoreML, TF, Paddle) | Detection is currently marker/substring based (or format-ID + exfil only for TensorRT/OpenVINO/MXNet), so it can't distinguish *declared* vs *reachable* ops. **ModelAudit** has deeper scanners here — the main parity gap from the comparison chart. |
| Keras custom-layer (non-`Lambda`) | The h5py-less byte fallback only matches `Lambda`/`TFOpLambda`; a custom registered layer with a malicious `__call__` evades it. Needs deeper HDF5/config parsing. |
| Python source dataflow/taint | The AST scanner matches dangerous call names and flags `getattr`/decode→exec; source assembled fully at runtime can still evade. A taint pass raises attacker cost further. |
| More exfil encodings | base85 and XOR/rolling-key deobfuscation remain (higher false-positive risk). UTF-16, base64/hex/base32, and one gzip/zlib layer are already covered. |
| Packed-binary C2 endpoints | Endpoints stored as packed bytes (no ASCII/UTF-16 form) aren't extracted; needs structured per-format parsing. |
| Protocol-0/1 pickle under a spoofed structured extension | Magic beats extension for protocol-2+ pickles and for binaries hidden under doc/config names; a *protocol-0/1 (ASCII)* pickle renamed to a structured non-pickle extension (e.g. `.onnx`) is flagged as a format mismatch but not yet classified by payload. |

## Candidates — provenance & trust

| Item | Notes |
|---|---|
| Origin database provenance | `org_countries.yaml` is a hand-maintained heuristic; document sourcing + a review cadence, or derive origin only from verified signers once the PKI trust root lands. |

## Candidates — operability

| Item | Notes |
|---|---|
| Global memory accountant | Per-scan windowing + finding cap + concurrency cap bound memory in practice; a cross-request budget would be stricter. |
| `PrometheusRule` alerts | Ship alert rules to pair with the Grafana dashboard (spike in FAIL/BLOCKED, `DEEP_UNAVAILABLE`, error rate). |

## Candidates — distribution / UX

| Item | Notes |
|---|---|
| Kubernetes admission controller / CI plugin | See *Enforcement primitive* above — a webhook/action enforcing verdicts + hash pinning at deploy time. |

## Out of scope

Mirrors the *does-not-defend-against* list in [`SECURITY.md`](SECURITY.md)
(§ Threat model / Residual risk). The actively-worked residuals it also
mentions — obfuscated encodings (base85/XOR), packed-binary endpoints, and
fully runtime-assembled `trust_remote_code` source — are **not** out of scope;
they live under *Candidates — detection depth* above.

| Item | Why |
|---|---|
| Pickle gadget-chain reachability | *Heuristic* gadget-composition detection ships in the **`purser-deep`** companion (pivot primitives, complex graphs, deep imports). Full reachability/soundness is still infeasible statically; the robust guarantee remains the ban-pickle allowlist policy (`signed-only.yaml`). |
| Weight *steganography / tampering* | Covered by **`purser-deep`** (`deep.weights`): hidden data in tensor low-bit planes, non-finite weights, size mismatches — static, no model load. |
| Weight *behavioral* backdoors | Out of scope: detecting *trained* triggers / poisoning needs model-evaluation, not container/static analysis. Commercial platforms (see comparison chart) cover it. |
| Determined / volumetric DoS | The concurrency cap, per-client rate limit, and per-file windowing bound resource use, but absorbing a determined flood is the job of an edge proxy / WAF / autoscaler, not the scanner. |
| Spoofed provenance when signing is not required | By design, origin/publisher is *advisory* unless a policy sets `require_signed`. Enforce trust with `policies/signed-only.yaml` + a trust store; Purser will not treat unsigned claims as authoritative on its own. |
| CVE / threat-intel feeds, dashboards | Enterprise-platform territory (Guardian, HiddenLayer); out of scope for a self-hosted OSS scanner. |

---

## Recently shipped

Moved out of the roadmap now that they're done (see [`CHANGELOG.md`](CHANGELOG.md)
for per-release detail):

- **Public release & distribution (v0.1.0 → v0.1.2):** public git repo with
  protected `main`; GitHub Actions CI (lint + test matrix 3.11–3.14, lockfile /
  license gates, Helm lint, image builds + Trivy) and a tag-driven release
  pipeline; **PyPI** publishing via OIDC Trusted Publishing; public multi-arch
  **signed** container images (core / HF / deep) and a **signed** Helm chart on
  GHCR (OCI); CodeQL + dependency-review; `CHANGELOG.md`; a `demo/` sandbox.
- **Community & governance:** `CONTRIBUTING.md`, a Contributor Covenant Code of
  Conduct, bug/feature issue forms + a PR template, an **enforced DCO** sign-off
  check, `CITATION.cff`, a `py.typed` marker, and package `[project.urls]`.
- **Disguise-resistant detection:** magic bytes beat a spoofed extension, and
  directory walks sniff files hidden under doc/config names.
- **Wolfi base drift detection:** a scheduled CI job flags a stale base digest.
- **Provenance:** Ed25519 model signing + trust store, `require_signed` policy,
  and key **revocation / validity windows**.
- **Detection:** `trust_remote_code` AST scanner + `auto_map` config scanner;
  exfil UTF-16 / hex / base32 / gzip decoding; configurable benign-host allowlist.
- **Supply chain:** hash-pinned lockfiles + `--require-hashes`, split core/HF/deep
  Wolfi images, deterministic CycloneDX SBOM, `trivy` + `osv-scanner` CI gates,
  multi-arch `buildx` with SLSA provenance + SBOM attestations, cosign signing.
- **Observability:** Prometheus `/metrics` (built-in registry) with
  security-domain series + an importable Grafana dashboard, and a structured JSON
  **audit log** to syslog/stdout (`PURSER_AUDIT`).
