# Security Policy & Assessment

This document is both Purser's **vulnerability-disclosure policy** and a
**security SME evaluation** of the code and container images. It is a
*maintainer/SME self-assessment* (evidence-backed, file-referenced) — not an
independent third-party audit. Forward work is tracked in
[`ROADMAP.md`](ROADMAP.md).

_Last reviewed: 2026-08-02 · applies to Purser 0.2.x (incl. the signals
subsystem and the admission webhook)._

---

## Reporting a vulnerability

**Do not open a public issue for security bugs.** Report privately:

- Preferred: a **GitHub private security advisory** (Security → *Report a
  vulnerability*).
- Otherwise: email **security@purser-io.io** (monitored security alias).

Please include: affected version/commit, a minimal reproducer (for a scanner
**bypass**, the crafted model file — inert payloads only), impact, and any fix
idea. We aim to acknowledge within **3 business days** and follow **coordinated
disclosure** (target ≤90 days). Scanner-evasion reports are in scope and
valued — see *Threat model* for what "evasion" means here.

Report test/reproducer models with **inert** payloads (e.g. `os.system("true")`),
never live malware.

## Supported versions

| Version | Supported |
|---|---|
| 0.2.x | ✅ (current) |
| < 0.2 | ❌ |

Pre-1.0: only the latest minor line receives security fixes.

---

## Threat model

Purser's job is to inspect **untrusted, potentially hostile model files** —
and, on hub scans, **untrusted external signals about them** — and render one
policy verdict it enforces. So the files it reads are the adversary, (for the
service) so are its network clients, and (for signal ingestion) so is anything
a remote endpoint returns.

**Assets:** the host/cluster running the scanner; secrets reachable from it
(`HF_TOKEN`, mounted model stores); the integrity of the **policy verdict**
used as a gate — in CI, over the API, and at Kubernetes admission.

**Trust boundaries:**
1. *Model file → scanner.* Files are **parsed, never executed** (see below).
2. *Client → API.* All `/v1` endpoints are authenticated + rate-limited when
   configured; `/healthz` and `/metrics` are open by design (network-restrict
   `/metrics`, or disable it with `PURSER_METRICS_ENABLED=0`; it exposes only
   aggregate counters, no model content or paths).
3. *Signer → trust root.* For the Ed25519 path, provenance is only as
   trustworthy as the keys an operator places in the trust store; for the
   Sigstore path, it derives from a verified external root (Fulcio/Rekor) via
   the transparency log.
4. *Signal source → verdict.* On the `-hf` path, `purser.signals` sources fetch
   JSON from the Hub (`HF_ENDPOINT`-overridable) and their findings count
   toward the verdict. Responses are **parsed as data, never executed**, and a
   source can only **add** findings — the plugin context deliberately excludes
   the in-progress report, so no signal can suppress or downgrade another
   finding (`signals/__init__.py`). A compromised or spoofed upstream can
   therefore cause false *positives* (over-blocking), not false negatives.
   Third-party plugins are **operator-installed code**: audit before
   installing; disable with `PURSER_SIGNALS=0` / `PURSER_SIGNAL_<NAME>=0`.
5. *Admission webhook → API server.* The `ValidatingAdmissionWebhook` is
   **fail-closed by default** (`admission.failurePolicy: Fail`) and opt-in per
   namespace; its TLS cert/CA bundle are chart-managed. Fail-closed trades
   availability for integrity: an outage blocks opted-in deploys rather than
   waving them through.
6. *Verdict → approval store (auto-approval, opt-in).* With
   `PURSER_AUTO_APPROVE=1`, a scan verdict **writes** the approved-digest list
   the webhook enforces — which makes the scanning service an *approval
   authority*: compromising it (or feeding it a payload its static analysis
   misses) yields a deployable digest. Mitigations: off by default; only
   verdicts in `PURSER_AUTO_APPROVE_VERDICTS` approve while FAIL/BLOCKED
   actively revokes; the in-cluster grant is a namespaced Role on the single
   approvals ConfigMap (never a ClusterRole); and every action is recorded in
   `metadata.approvals` + the audit log. Treat auto-approval as a policy
   decision: keep it off where a human review step is the point.

**Primary guarantee — models are never executed or extracted:**
- Pickle streams are parsed statically with `pickletools.genops`
  (`scanners/pickle_scanner.py:291`) — **no `Unpickler`, no `find_class`, no
  `pickle.load`**.
- Archives are inspected via `zipfile`/`tarfile` member reads — **no
  `extractall`/`extract`**; tar is opened read-only (`scanners/archive.py:93`).
- H5/protobuf/GGUF/flatbuffers are read at the byte/structure level.
- Verified across the source: **zero** `eval`/`exec`/`os.system`/`subprocess`/
  `pickle.load`/`yaml.load`/`shell=True` call sites in Purser's own code
  (the only occurrences of those tokens are *detection signatures* and tests).

**Out of scope:** learned/behavioral backdoors in weights (poisoning, triggers);
novel pickle gadget chains through allowlisted libraries; a determined DoS beyond
the built-in caps. See *Residual risk*.

---

## Code security evaluation (SME)

| Area | Assessment | Evidence |
|---|---|---|
| Deserialization safety | **Strong.** Static opcode analysis only; nothing is unpickled/loaded/executed. | `pickle_scanner.py`, no `Unpickler`/`find_class` |
| Config parsing | **Good.** `yaml.safe_load` throughout; no `yaml.load`. | `core/policy.py`, `core/provenance.py`, `core/signing.py` |
| Archive handling | **Good.** Zip-slip (path traversal) + zip-bomb guards; symlink/hardlink members skipped; depth-capped recursion; member reads only. | `scanners/archive.py` |
| Path traversal (API) | **Good.** `/v1/scan/path` resolves the target and requires it under `PURSER_SCAN_ROOT` (`root not in target.parents` after `resolve()`). | `api.py` `scan_path` |
| Upload handling | **Good.** Client filename is basename-only; streamed to a temp dir with a hard size cap (413); temp dir always cleaned. | `api.py` `scan_upload` |
| Temp files | **Good.** Attacker bytes staged to `mkdtemp`/`NamedTemporaryFile` and removed in `finally`; never executed. | `core/dispatch.py`, `api.py` |
| AuthN | **Good (opt-in).** API-key via `Authorization: Bearer`/`X-API-Key`, **constant-time** compare (`hmac.compare_digest`); open only when unset (documented). | `api.py` `require_auth` |
| Rate limiting / DoS | **Adequate.** Per-client token bucket (429 + `Retry-After`) + global concurrency cap + per-file windowing/finding cap. Per-replica, not cluster-global. | `api.py`, `scanners/exfil.py` |
| SSRF | **Contained.** Three outbound paths. Scan-time (hub-only, `-hf`-path-only): `snapshot_download(repo_id=…)` for artifacts (endpoint **off by default**, allowlist-scoped, auth-gated) and the signal sources' verdict/card lookups (`GET/POST` to the same hub, repo-id-scoped URLs, `PURSER_SIGNAL_TIMEOUT_SECONDS` timeout, responses parsed as JSON and never executed; kill switches `PURSER_SIGNALS=0`, `PURSER_SIGNAL_<NAME>=0`). User-invoked only: `purser update-intel` fetches the loader-CVE dataset over HTTPS from `PURSER_INTEL_URL` (default: the project repo) — never at scan time; the fetched file is schema-validated YAML parsed as data, and a failed validation leaves the previous dataset in place. None reach arbitrary hosts; local scans make no network calls (regression-tested). | `core/hf.py`, `api.py` `scan_hf`, `signals/hf_verdicts.py`, `signals/card_attestations.py`, `core/intel.py` |
| Secret handling | **Good.** `HF_TOKEN` from env only; upload/HF responses strip absolute paths before returning; findings avoid echoing full secret values. | `api.py`, `scanners/exfil.py` |
| Signature integrity | **Good.** Ed25519 over a full-file SHA-256 manifest; exact-match + added-file detection; **symlinks excluded** from the manifest; revocation + validity windows. | `core/signing.py:100` |
| Error handling | **Good.** Per-scanner exceptions are contained as `SCANNER_ERROR` findings — one malformed file can't crash a directory scan. | `core/dispatch.py` |

No high-severity code findings in this pass. Lower-assurance areas are inherent
to static analysis (see *Residual risk*), not defects.

---

## Container & deployment evaluation (SME)

**Images** (`Dockerfile` core, `Dockerfile.hf` HF worker, `Dockerfile.deep`
deep-analysis companion):

- **Multi-stage** — build tooling (`pip`, compilers, `-dev`) lives only in the
  build stage; the runtime stage is python-runtime-only.
- **Digest-pinned Wolfi** base (`ARG WOLFI=…@sha256:…`) — reproducible, low-CVE,
  glibc.
- **Non-root** `USER 10001:10001`; `ENTRYPOINT []` + explicit venv paths;
  HEALTHCHECK in exec form (no shell dependency).
- **Hash-pinned dependencies** installed with `pip --require-hashes`.
- **Attack-surface split:** the core image has **no `huggingface_hub` / HTTP
  client stack**; the network-fetching HF worker and the heavier
  **deep-analysis companion** (`purser-deep`) are separate, off-by-default
  images so their surface stays out of the core.

**Deep companion (`purser-deep`)** — a separate, opt-in service the core
calls only when `PURSER_ENABLE_DEEP=1`:
- Its `POST /v1/deep-scan` accepts **raw file bytes** and, like the core,
  enforces `PURSER_API_KEY` (constant-time) when set and caps body size.
- The analyzers are static (no model load); a per-analyzer `try/except` means a
  crafted file can't crash the service.
- The core→deep call is server-to-server egress to a **configured URL only**
  (`PURSER_DEEP_URL`), not an attacker-controlled host; failure is surfaced
  as a `DEEP_UNAVAILABLE` finding, never a silent pass.
- It ships the same trusted `requirements-deep.lock` and is actually *smaller*
  than core (no signing deps).

**Admission webhook** (`src/purser/admission.py`, Helm `admission.enabled`) —
the deploy-time enforcement point:
- **Fail-closed by default** (`admission.failurePolicy: Fail`): if the webhook
  is unreachable, opted-in namespaces cannot create pods — an availability
  trade made deliberately, since `Ignore` would let a webhook outage become a
  policy bypass. Opt-in is per namespace/pod via label selectors, so the blast
  radius is scoped.
- Enforces **image-digest pinning** and an **approved-model-digest** allowlist
  (operator-managed ConfigMap/GitOps); rejection reasons are returned in the
  admission response, sanitized against log injection.
- Serving cert + `caBundle` are chart-generated and kept stable across
  upgrades; rotate by deleting the cert Secret and upgrading.

**Kubernetes** (`deploy/k8s/deployment.yaml`) sets a hardened `securityContext`:
`runAsNonRoot`, `runAsUser: 10001`, `allowPrivilegeEscalation: false`,
`readOnlyRootFilesystem: true`, `capabilities.drop: ["ALL"]`,
`seccompProfile: RuntimeDefault`; policy via read-only ConfigMap, API key via
Secret.

**Operator hardening checklist:**
- [ ] Set `PURSER_API_KEY` (and front with an auth/rate-limiting proxy for
  internet exposure). Rotate periodically — a comma-separated list allows
  zero-downtime rotation and per-consumer revocation (see the README's
  *Authentication and API keys*).
- [ ] Set `PURSER_RATE_LIMIT_RPM` and lower the Ingress `proxy-body-size`
  from the 10 GB example to your real maximum.
- [ ] Keep the HF worker **off** (`PURSER_ENABLE_HF=0`) unless needed; when
  on, set `PURSER_HF_ALLOWLIST` and run it on an **egress-restricted** node.
- [ ] Keep the deep companion **off** (`PURSER_ENABLE_DEEP=0`) unless needed;
  when on, set the same `PURSER_API_KEY` on it and keep it on the internal
  network (the core reaches it via `PURSER_DEEP_URL`).
- [ ] On air-gapped or egress-filtered runners, set `PURSER_SIGNALS=0` (or
  `PURSER_SIGNAL_<NAME>=0` per source) to skip upstream-verdict lookups;
  treat upstream verdicts as advisory input, never authority. Audit any
  third-party `purser.signals` plugin before installing it — plugins are
  operator-installed code.
- [ ] If you enable the admission webhook, keep `failurePolicy: Fail` and
  scope the namespace selector deliberately — `Ignore` converts webhook
  downtime into a silent policy bypass.
- [ ] Leave auto-approval (`PURSER_AUTO_APPROVE`) **off** unless the
  scan-to-deploy flow is meant to be fully automatic; when on, keep the
  approve set to `PASS` only, monitor `metadata.approvals` in the audit log,
  and remember the scanner becomes an approval authority (see trust
  boundary 6).
- [ ] Use a `require_signed` policy (`policies/signed-only.yaml`) and a curated
  trust store for provenance enforcement.
- [ ] Refresh the pinned Wolfi digest on a cadence (`make base-digest`) and gate
  releases on `trivy` + `osv-scanner` (wired in `.gitlab-ci.yml`).
- [ ] Mount model stores read-only.

---

## Cryptography

- **Algorithm:** Ed25519 (via `cryptography`), detached signatures over a
  canonical JSON manifest of per-file SHA-256 digests.
- **Verification** requires: manifest matches actual files, key present in the
  trust store, signature valid, key not revoked, and signature `created` within
  the key's validity window.
- **Fails closed:** if `cryptography` is absent, verification returns
  `unavailable`, so a `require_signed` policy blocks rather than passes.
- **Trust root caveat:** the Ed25519 key→publisher→country binding is an
  **operator assertion** in the local trust store — integrity + key-attested
  identity, not a transparency-log-backed PKI. For a **verified external root**,
  Purser also verifies **Sigstore (Fulcio/Rekor)** bundles — identity from a
  transparency-log-backed OIDC subject, verified offline against a vendored trust
  root, gated by the `identity` policy (see `core/sigstore_verify.py`).

---

## Residual risk (honest limits)

A **clean verdict is necessary, not sufficient** — and it is only as strong as
the signals that produced it. Purser does **not** defend against:

1. **Novel pickle gadget chains** through allowlisted libraries — mitigate by
   banning pickle via an allowlist policy (`signed-only.yaml`).
2. **Weight/behavioral backdoors** (poisoning, triggers) — a valid, safe-format
   file can still misbehave; this needs model-eval tooling, not container scanning.
3. **Heavily obfuscated payloads** — multi-byte / rolling-key XOR, packed-binary
   endpoints, or `trust_remote_code` source assembled fully at runtime can evade
   name/pattern matching. (Single-byte XOR and base64/hex/base32/base85 encodings
   — plus one gzip/zlib layer and UTF-16 — are decoded and re-analyzed.) Pair with
   an egress-deny sandbox at model-load time.
4. **Spoofed provenance when signing is not required** — origin is advisory
   unless a policy sets `require_signed`.
5. **Graph `declared`-vs-`reachable` dataflow** — Purser flags *declared*
   dangerous ops / custom code in TF / Paddle / CoreML / ONNX graphs (the
   fail-safe choice for a gate); proving a dangerous op is *reachable* at
   runtime needs the framework's graph semantics at model-load, which a no-load
   scanner does not do.
6. **Weak or missing signals** — an upstream verdict can be stale, queued, or
   unavailable (surfaced as `SIGNAL_UNAVAILABLE`, never a silent pass), and a
   model-card attestation is a *claim*, not evidence. Signals only ever add
   findings; none of them certifies safety, and their absence should be read
   as reduced coverage, not as "clean."

Deploy Purser as **one layer of defense-in-depth**, not a sole trust boundary.

## Assurance

- 330 automated tests (unit + API + adversarial/evasion fixtures with inert
  payloads, incl. offline mocked-endpoint tests for every signal source).
- `ruff` lint clean; reproducible hash-pinned builds; deterministic CycloneDX
  SBOM; `trivy` (image) and `osv-scanner` (deps) gates in CI.
