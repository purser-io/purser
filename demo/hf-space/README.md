---
title: Purser — Model Supply-Chain Control Plane
emoji: ⚓
colorFrom: blue
colorTo: indigo
sdk: gradio
sdk_version: "6.15.0"
app_file: app.py
pinned: false
license: apache-2.0
short_description: Scan a model file or HF repo; policy renders the verdict
---

# Purser — live demo

[Purser](https://github.com/purser-io/purser) is the open-source **model
supply-chain control plane**: policy, provenance, and enforcement for ML model
artifacts. This Space runs the real scanner + policy engine on whatever you
give it:

- **Upload a model file** (pickle, PyTorch, Keras, ONNX, safetensors, GGUF, …)
  — nothing is ever deserialized or executed; analysis is byte/opcode-level.
- **Scan a Hub repo** by id (e.g. `prajjwal1/bert-tiny`) — downloads the repo,
  scans every file, and also ingests the Hub's own upstream scan verdicts as a
  corroborating signal.

The verdict (`PASS` / `WARN` / `FAIL` / `BLOCKED`) comes from the bundled
[default policy](https://github.com/purser-io/purser/blob/main/policies/default.yaml);
in real deployments the policy is yours (origin/publisher/format allowlists,
`require_signed`, rule overrides) and the same verdict gates CI and Kubernetes
admission.

> A clean scan means "clear of known malicious content," not "certified safe" —
> see the [security model](https://github.com/purser-io/purser#security-model).
