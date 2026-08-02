# Purser is a model supply-chain control plane, not (just) a scanner

*Draft launch post — publish alongside the next release. Target venues: the
project blog/README announcement, r/netsec / r/MachineLearning, Hacker News,
the CNCF Security TAG + MLSecOps Slacks.*

---

Six months ago Purser started as an ML model security scanner: point it at a
`.pkl` or `.onnx` and it tells you whether something malicious is inside.
That problem is real — pickle RCE, `trust_remote_code` payloads, and JFrog's
malicious-model finds on HuggingFace are all documented — but the honest truth
is that *raw scanning* is no longer where the gap is.

## The gap is not detection. It's governance.

If you want a model file scanned today, you have options: picklescan runs on
the Hub itself, ModelScan and ModelAudit cover many formats, and HuggingFace
already runs four scanners (picklescan, ClamAV, Protect AI Guardian, JFrog)
over every upload. Baseline detection is effectively free.

What you *cannot* easily get in open source is what happens **after** the
scan:

- Who is allowed to bring a model into this cluster? From which publishers,
  origins, formats?
- Is this artifact **signed**, and does the signer's identity check out
  against a real trust root?
- What stops a pod from loading a model that was never cleared — or one that
  was swapped after the scan (TOCTOU)?
- When five different tools have opinions about a model, who renders **one
  verdict** and enforces it?

That's control-plane work, not scanner work. It's the gap between "picklescan
on a laptop" and "buy a commercial platform" — and it's where Purser has
quietly been building all along: a policy engine (origin / publisher / name /
format / signer-identity rules), Ed25519 + offline Sigstore provenance, a
CI action, and a Kubernetes `ValidatingAdmissionWebhook` that rejects pods
referencing unapproved model digests.

So we're saying it out loud now: **Purser is the open-source model
supply-chain control plane.** The clearance desk. Signals go in; one
enforced verdict comes out.

## What "signals go in" means concretely

As of this release, Purser's verdict aggregates:

- **Its own static scanner** — ~35 formats, byte/opcode-level, never loads
  the model. Still best-of-breed on exfiltration detection (C2 endpoints,
  webhooks, encoded payloads — most peers only look for code execution).
- **The Hub's upstream verdicts** — scanning an `hf://` repo now also ingests
  HuggingFace's own per-file scan results, so you inherit picklescan, ClamAV,
  Protect AI, and JFrog for free. One rule keeps this honest: upstream
  *unsafe* corroborates; upstream *safe* never downgrades what Purser's own
  analysis found (upstream scanners have documented false negatives).
- **Verified provenance** — Ed25519 signing with a trust store and
  revocation, plus offline Sigstore (Fulcio/Rekor) identity verification.
- **The deep companion** — opt-in pickle gadget-chain and weight
  tampering/steganography heuristics.
- **Attestation gates** — an opt-in check that a model *documents itself*
  (model card, declared eval results), which policy can escalate to blocking.
- **Your signals** — third-party sources plug in via a Python entry point
  (`purser.signals`) and land in the same report, policy, and verdict.

Every signal flows through the same policy engine, and the verdict is
enforced in three places: exit codes in CI, a REST API for
registry/promotion hooks, and the admission webhook at deploy time.

## What Purser is not

No static tool — Purser included — detects **trained backdoors or data
poisoning**: a perfectly valid safetensors file that misbehaves on a trigger
is invisible to any never-execute analysis, and we will not pretend
otherwise. A clean scan means "clear of known malicious content," not
"certified safe." The robust defense against format-borne code execution
remains boring and effective: an allowlist policy that only admits signed,
data-only formats — which Purser enforces.

## Try it

```bash
pip install purser
purser scan hf://prajjwal1/bert-tiny          # scan + upstream verdicts
helm install purser oci://ghcr.io/purser-io/charts/purser  # API + admission
```

There's a live demo Space, a GitHub Action, signed multi-arch images, a
benchmark suite with published FPR numbers (0% over 75 real models), and an
OpenSSF Best Practices passing badge. It's Apache-2.0, single-digit-stars
young, and looking for a second maintainer and early adopters — if the gap
described above is one you have, we'd like to hear what's missing.

*— the Purser maintainers*
