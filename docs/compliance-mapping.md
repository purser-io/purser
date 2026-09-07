# Compliance mapping

Which control each Purser finding produces evidence for, across the frameworks
enterprise reviewers arrive with.

> [!IMPORTANT]
> **A mapping is an aid to an auditor, not a compliance claim.** Purser
> produces evidence for these controls; it does not by itself satisfy them. A
> `PASS` verdict means "clear of known malicious content", not "compliant".

Every finding carries its controls as tags, so this table is machine-readable
at the point of use:

```bash
purser scan ./model-dir --format json | jq '.files[].findings[].tags'
# [... "owasp-llm:LLM03", "eu-ai-act:AnnexIV-2" ]
```

Tags also ride into the [CycloneDX ML-BOM](../README.md#ai-bill-of-materials-ml-bom)
(`--format cyclonedx`), so the BOM you hand an auditor carries the control
references with it. Disable tagging entirely with `PURSER_COMPLIANCE=0`.

<!-- GENERATED FILE — edit src/purser/data/compliance_map.yaml and run
     `make compliance-doc`. Do not edit by hand. -->

## Mapping granularity

Stated plainly, because precision claims matter in an audit:

- **OWASP ML / LLM ids are exact** — the published Top 10 identifiers.
- **NIST AI RMF is mapped at category level** (`GOVERN-6`, `MAP-4`,
  `MANAGE-3`, `MEASURE-2`), not subcategory. The three categories scoped to
  third-party and supply-chain risk are GOVERN 6, MAP 4 and MANAGE 3. Pinning
  subcategory decimals would imply a precision this mapping has not verified
  against NIST AI 100-1 — refine against your own control matrix.
- **EU AI Act references are Annex IV section numbers** (1–9), the granularity
  Annex IV itself uses.


## Frameworks referenced

### `owasp-ml` — [OWASP Machine Learning Security Top 10 (2023)](https://owasp.org/www-project-machine-learning-security-top-10/)

| Control | Title |
|---|---|
| `owasp-ml:ML01` | Input Manipulation Attack |
| `owasp-ml:ML02` | Data Poisoning Attack |
| `owasp-ml:ML06` | ML Supply Chain Attacks |
| `owasp-ml:ML09` | Output Integrity Attack |

### `owasp-llm` — [OWASP Top 10 for LLM Applications (2025)](https://genai.owasp.org/resource/owasp-top-10-for-llm-applications-2025/)

| Control | Title |
|---|---|
| `owasp-llm:LLM01` | Prompt Injection |
| `owasp-llm:LLM02` | Sensitive Information Disclosure |
| `owasp-llm:LLM03` | Supply Chain |
| `owasp-llm:LLM04` | Data and Model Poisoning |
| `owasp-llm:LLM10` | Unbounded Consumption |

### `nist-ai-rmf` — [NIST AI Risk Management Framework 1.0 (category level)](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf)

| Control | Title |
|---|---|
| `nist-ai-rmf:GOVERN-6` | Policies and processes for third-party AI software and data risk |
| `nist-ai-rmf:MAP-4` | Risks mapped for all AI system components, including third-party |
| `nist-ai-rmf:MANAGE-3` | Risks and benefits from third-party entities are managed |
| `nist-ai-rmf:MEASURE-2` | Trustworthiness characteristics are evaluated and documented |

### `eu-ai-act` — [EU AI Act — Annex IV technical documentation](https://artificialintelligenceact.eu/annex/4/)

| Control | Title |
|---|---|
| `eu-ai-act:AnnexIV-1` | General description of the AI system |
| `eu-ai-act:AnnexIV-2` | Elements and development process, incl. cybersecurity measures |
| `eu-ai-act:AnnexIV-4` | Appropriateness of performance metrics |
| `eu-ai-act:AnnexIV-5` | Risk management system (Article 9) |
| `eu-ai-act:AnnexIV-9` | Post-market monitoring system (Article 72) |

## Applied to every model-artifact finding

Scanning a model artifact at all is third-party supply-chain due
diligence, so these controls are attached to every matched finding
in addition to the specific ones below:

- `owasp-ml:ML06`
- `owasp-llm:LLM03`
- `nist-ai-rmf:GOVERN-6`
- `nist-ai-rmf:MANAGE-3`
- `eu-ai-act:AnnexIV-2`

The one exception is the model-card/eval gate (`CARD_*`), which is
about documentation rather than malicious content — the supply-chain
umbrella would be a poor fit, so it is not applied there.

## Findings → controls

Matched by **longest rule-id prefix**. Controls listed here are in
addition to the umbrella set above unless the row says otherwise.

| Rule-id prefixes | Additional controls | Umbrella |
|---|---|---|
| `PICKLE_`, `PYTORCH_`, `KERAS_`, `TF_`, `TFLITE_`, `ONNX_`, `COREML_`, `OPENVINO_`, `PADDLE_`, `SKOPS_`, `MAR_`, `MLFLOW_`, `CAFFE_`, `PMML_`, `EXECUTORCH_`, `NUMPY_`, `SAFETENSORS_`, `GGUF_BAD_MAGIC` | `nist-ai-rmf:MEASURE-2` | yes |
| `PY_`, `TRC_`, `AUTO_MAP`, `HF_CONFIG_REMOTE_CODE` | `nist-ai-rmf:MEASURE-2` | yes |
| `GGUF_TEMPLATE_INJECTION` | `owasp-llm:LLM01`, `owasp-ml:ML01` | yes |
| `EXFIL_` | `owasp-llm:LLM02`, `nist-ai-rmf:MEASURE-2` | yes |
| `ARCHIVE_ZIP_BOMB`, `DEEP_WEIGHTS_MALFORMED` | `owasp-llm:LLM10` | yes |
| `ARCHIVE_` | `nist-ai-rmf:MEASURE-2` | yes |
| `DEEP_WEIGHTS_`, `DEEP_STEGO` | `owasp-llm:LLM04`, `owasp-ml:ML02`, `owasp-ml:ML09` | yes |
| `DEEP_GADGET_` | `nist-ai-rmf:MEASURE-2` | yes |
| `LOADER_CVE` | `nist-ai-rmf:MEASURE-2`, `eu-ai-act:AnnexIV-9` | yes |
| `HF_UPSTREAM_`, `POLICY_DENYLIST_` | `nist-ai-rmf:MAP-4`, `eu-ai-act:AnnexIV-9` | yes |
| `SIGNATURE_`, `SIGSTORE_`, `PROVENANCE_` | `nist-ai-rmf:MAP-4`, `eu-ai-act:AnnexIV-5` | yes |
| `CARD_` | `nist-ai-rmf:MAP-4`, `eu-ai-act:AnnexIV-1`, `eu-ai-act:AnnexIV-4` | no |

## Coverage this mapping does not claim

Purser is a static artifact scanner. It produces no evidence for
controls about training-data governance, behavioural evaluation,
human oversight, or post-market incident reporting — those need
different tooling, and an auditor should not read a Purser report as
covering them. See [`gap_analysis.md`](../gap_analysis.md) §8 for the
full residual-risk list.
