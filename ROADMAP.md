# Purser Roadmap

Forward-looking work. Competitive positioning is in the
[comparison chart](README.md#how-purser-compares). This file tracks what is
**not done yet** and why.

As of this reassessment the security-hardening arc (gap-analysis items 1–10),
the supply-chain foundations (hash-pinned Wolfi builds, SBOM, cosign/SLSA CI,
multi-arch), model signing with revocation, and the exfil/`trust_remote_code`
engines are all shipped (159 tests). What remains is **not** bug-fixing — it is
maturity, reach, and depth. See *Recently shipped* at the bottom.

Status legend: **planned** (agreed, not started) · **candidate** (worth doing,
undecided) · **deferred** (chosen not to do yet) · **out-of-scope**.

---

## Recommended next (priority order)

1. **Ship it: git repo + PyPI/OCI release.** The project is feature-complete for
   a 1.0 but is not yet versioned or installable. Highest leverage — nothing else
   matters if people can't get it. (Git init was **deferred at the user's
   request**; do this when ready.)
2. **External PKI / transparency trust root.** The largest remaining *trust*
   improvement — moves provenance from operator-asserted keys to a verified root
   (Sigstore/Fulcio+Rekor or HF commit signatures).
3. **Wolfi base digest-refresh automation.** Operational hygiene: the pinned base
   silently ages against CVEs without it.
4. **Per-format scanner depth (TensorRT, OpenVINO).** Closes the one area where
   the OSS peer **ModelAudit** leads (per the comparison chart).
5. **Observability (metrics + audit log).** Needed before anyone runs the service
   in production at scale.

---

## Planned

| Item | Notes |
|---|---|
| **External PKI / transparency trust root** | Signing today is Ed25519 + a local trust store binding key→publisher→country — integrity and key-attested identity, but the key→identity binding is an operator assertion. Integrate Sigstore (Fulcio/Rekor) or HuggingFace commit-signature verification so identity derives from a verified external root. |
| **Wolfi base digest refresh** | The base is digest-pinned (`ARG WOLFI`) for reproducibility, so it does **not** track upstream. Wolfi rebuilds often for CVEs; bump with `make base-digest`. Deferred automation: a scheduled CI job that refreshes the digest, rebuilds, runs `trivy`, and opens an MR on change. Manual for now. |

## Candidates — detection depth

| Item | Notes |
|---|---|
| Per-format graph parsing (TensorRT, OpenVINO, CoreML, TF, Paddle) | Detection is currently marker/substring based (or format-ID + exfil only for TensorRT/OpenVINO/MXNet), so it can't distinguish *declared* vs *reachable* ops. **ModelAudit** has deeper scanners here — this is the main parity gap from the comparison chart. |
| Keras custom-layer (non-`Lambda`) | The h5py-less byte fallback only matches `Lambda`/`TFOpLambda`; a custom registered layer with a malicious `__call__` evades it. Needs deeper HDF5/config parsing. |
| Python source dataflow/taint | The AST scanner matches dangerous call names and flags `getattr`/decode→exec; source assembled fully at runtime can still evade. A taint pass raises attacker cost further. |
| More exfil encodings | base85 and XOR/rolling-key deobfuscation remain (higher false-positive risk). UTF-16, base64/hex/base32, and one gzip/zlib layer are already covered. |
| Packed-binary C2 endpoints | Endpoints stored as packed bytes (no ASCII/UTF-16 form) aren't extracted; needs structured per-format parsing. |

## Candidates — provenance & trust

| Item | Notes |
|---|---|
| Origin database provenance | `org_countries.yaml` is a hand-maintained heuristic; document sourcing + a review cadence, or derive origin only from verified signers once the PKI trust root lands. |

## Candidates — operability

| Item | Notes |
|---|---|
| Global memory accountant | Per-scan windowing + finding cap + concurrency cap bound memory in practice; a cross-request budget would be stricter. |

*(Shipped: Prometheus `/metrics` + structured syslog/JSON audit log — see*
*Recently shipped.)*

## Candidates — distribution / UX

| Item | Notes |
|---|---|
| **PyPI / OCI release** | Publish `purser` to an index and signed images to a registry. Prereq for adoption. |
| Kubernetes admission controller / CI plugin | A ValidatingAdmissionWebhook or CI action enforcing scan verdicts + hash pinning at deploy time (closes the TOCTOU note, gap-analysis §5.4). |

## Deferred

| Item | Notes |
|---|---|
| Git history / initial commit | Repo is not a git repository; `git init` was started then **removed at the user's request** ("hold on git"). Do when the user says so. |

## Out of scope

Mirrors the *does-not-defend-against* list in [`SECURITY.md`](SECURITY.md)
(§ Threat model / Residual risk). The actively-worked residuals it also
mentions — obfuscated encodings (base85/XOR), packed-binary endpoints, and
fully runtime-assembled `trust_remote_code` source — are **not** out of scope;
they live under *Candidates — detection depth* above.

| Item | Why |
|---|---|
| Pickle gadget-chain reachability | *Heuristic* gadget-composition detection now ships in the **`purser-deep`** companion (pivot primitives, complex graphs, deep imports). Full reachability/soundness is still infeasible statically; the robust guarantee remains the ban-pickle allowlist policy (`signed-only.yaml`). |
| Weight *steganography / tampering* | Now covered by **`purser-deep`** (`deep.weights`): hidden data in tensor low-bit planes, non-finite weights, size mismatches — static, no model load. |
| Weight *behavioral* backdoors | Still out of scope: detecting *trained* triggers / poisoning needs model-evaluation, not container/static analysis. Commercial platforms (see comparison chart) cover it. |
| Determined / volumetric DoS | The concurrency cap, per-client rate limit, and per-file windowing bound resource use, but absorbing a determined flood is the job of an edge proxy / WAF / autoscaler, not the scanner. |
| Spoofed provenance when signing is not required | By design, origin/publisher is *advisory* unless a policy sets `require_signed`. Enforce trust with `policies/signed-only.yaml` + a trust store; Purser will not treat unsigned claims as authoritative on its own. |
| CVE / threat-intel feeds, dashboards | Enterprise-platform territory (Guardian, HiddenLayer); out of scope for a self-hosted OSS scanner. |

---

## Recently shipped

Moved out of the roadmap now that they're done:

- **Security hardening (gap-analysis items 1–10):** API-key auth, per-client rate
  limiting, concurrency cap, gated HF endpoint; full-file hashing; windowed scan +
  `SCAN_TRUNCATED`; ONNX abs-path + zip-bomb fixes.
- **Provenance:** Ed25519 model signing + trust store, `require_signed` policy,
  and key **revocation / validity windows** (`revoked` / `expired` verdicts).
- **Detection:** `trust_remote_code` AST scanner + `auto_map` config scanner;
  exfil UTF-16 / hex / base32 / gzip decoding; configurable benign-host allowlist.
- **Supply chain:** hash-pinned lockfiles + `--require-hashes`, split core/HF Wolfi
  images, deterministic CycloneDX SBOM, `trivy` + `osv-scanner` CI gates,
  multi-arch `buildx` with SLSA provenance + SBOM attestations, cosign signing.
- **Observability:** Prometheus `/metrics` endpoint (built-in registry, no dep)
  with security-domain series (findings by threat category, policy blocks by
  reason, provenance status, origin country, format mix, rejections, in-flight
  gauge, duration histogram) + an importable Grafana dashboard
  (`deploy/grafana/purser-overview.json`); and a structured JSON **audit log**
  to syslog/stdout (`PURSER_AUDIT`).
- **Docs:** competitive comparison chart in the README.
