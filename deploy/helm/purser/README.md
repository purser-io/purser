# Purser Helm chart

Production-ready chart for **Purser** — the model supply-chain control plane. Deploys
the core scanning service and, optionally, the HuggingFace worker and the
deep-analysis companion.

## Install

```bash
# published OCI chart (recommended) — defaults to the ghcr.io/purser-io images
helm install purser oci://ghcr.io/purser-io/charts/purser --version 0.2.1 \
  -n purser --create-namespace

# …or from a source checkout
helm install purser deploy/helm/purser -n purser --create-namespace

# manage the API key yourself / mirror the images
helm install purser oci://ghcr.io/purser-io/charts/purser --version 0.2.1 \
  -n purser --create-namespace \
  --set auth.existingSecret=purser-api-key \
  --set image.repository=my-mirror.example.com/purser

helm test purser -n purser        # runs the /healthz smoke test
```

If you don't supply `auth.existingSecret` or `auth.apiKey`, the chart generates
a random API key into a Secret and **retains it across upgrades** (it won't
rotate on `helm upgrade`).

## What you get

| Enabled by default | Optional (`--set`) |
|---|---|
| Core Deployment (2 replicas), Service, ServiceAccount | HF worker (`hf.enabled`) |
| Policy ConfigMap (mounted, hot-swappable) | Deep companion (`deep.enabled`, auto-wired to core) |
| API-key Secret (generated/retained) | HPA (`autoscaling.enabled`) |
| PodDisruptionBudget, topology spread | Ingress (`ingress.enabled`) |
| Prometheus scrape annotations | ServiceMonitor (`metrics.serviceMonitor.enabled`) |
| Hardened pod/container securityContext | PrometheusRule alerts (`metrics.prometheusRule.enabled`) |
| — | NetworkPolicy (`networkPolicy.enabled`) |
| — | Admission webhook (`admission.enabled`) — deploy-time verdict + digest enforcement |

**Signal sources.** With `hf.enabled`, `hf://` scans also fetch the Hub's own
scan verdicts as a corroborating signal (outbound calls beyond the download
itself). Control via env on the worker, e.g.:

```yaml
config:
  extraEnv:
    - { name: PURSER_SIGNALS, value: "0" }            # fully offline
    - { name: PURSER_CARD_ATTESTATIONS, value: "1" }  # opt-in attestation gate
```

With `metrics.serviceMonitor.enabled` + `metrics.prometheusRule.enabled` against a
Prometheus/Grafana stack, importing [`deploy/grafana/purser-overview.json`](../../grafana/purser-overview.json)
gives a security overview:

<p align="center">
  <img src="https://raw.githubusercontent.com/purser-io/purser/main/assets/grafana-dashboard.png" alt="Purser Grafana dashboard" width="100%" />
</p>

Hardening applied to every workload: non-root `10001:10001`, read-only root FS,
all capabilities dropped, `seccompProfile: RuntimeDefault`, no privilege
escalation, `automountServiceAccountToken: false`, resource requests/limits, and
liveness/readiness/startup probes on `/healthz`.

## Key values

| Key | Default | Notes |
|---|---|---|
| `image.repository` / `image.tag` | `ghcr.io/purser-io/purser` / *appVersion* | pin a digest in prod |
| `replicaCount` | `2` | ignored when `autoscaling.enabled` |
| `auth.enabled` | `true` | require API key on `/v1` |
| `auth.existingSecret` | `""` | recommended: manage keys externally |
| `policy.content` | blocklist policy | rendered to a ConfigMap; edit + `helm upgrade` |
| `config.rateLimitRpm` | `0` | per-client rate limit (0 = off) |
| `audit.mode` | `off` | `stdout` / `syslog` for SIEM |
| `metrics.serviceMonitor.enabled` | `false` | Prometheus Operator |
| `metrics.prometheusRule.enabled` | `false` | starter alert set (Prometheus Operator) |
| `modelStore.enabled` | `false` | mount a PVC for `/v1/scan/path` |
| `deep.enabled` / `hf.enabled` | `false` | optional companions — deploy the `purser-deep` / `purser-hf` images (see the [distributions table](../../../README.md#install-and-cli-usage) for how these images map to the PyPI extras) |
| `admission.enabled` | `false` | ValidatingAdmissionWebhook: require image-digest pinning + approved-model digests at deploy time |
| `admission.approvedDigests` | `[]` | SHA-256s of models that passed a scan (a declared model must be listed) |
| `admission.autoApprove.enabled` | `false` | scan verdicts populate the approved list automatically (PASS approves, FAIL/BLOCKED revokes); mounts the SA token + adds a Role scoped to the one approvals ConfigMap |
| `admission.failurePolicy` | `Fail` | `Ignore` to fail-open at the API-server level |

See [`values.yaml`](values.yaml) for the fully-documented set; `values.schema.json`
validates them at install time.

## Admission webhook (deploy-time enforcement)

`admission.enabled=true` installs a `ValidatingAdmissionWebhook` that closes the
scan→deploy TOCTOU gap: scanning a model in CI proves it was safe *then*; the
webhook enforces at *admission* that (1) every container image is pinned by
`@sha256:` digest and (2) any model a workload declares (annotation
`purser.io/models`) is on the **approved-digest** list — the SHA-256s of models
that passed a Purser scan (`admission.approvedDigests`). A `purser.io/scan-verdict:
FAIL|BLOCKED` annotation is always denied. The chart generates and retains a
self-signed serving cert and wires its CA into the webhook's `caBundle`.

It is **opt-in and fail-safe by default** — only namespaces labeled
`purser.io/admission: enforce` are selected, and within them only pods labeled
`purser.io/enforce: "true"` are checked. Never label `kube-system` or the Purser
namespace. With `failurePolicy: Fail` (the default), a down webhook blocks pod
creation in *selected* namespaces, so keep the selector tight.

```bash
helm upgrade purser oci://ghcr.io/purser-io/charts/purser --version 0.2.1 \
  -n purser --reuse-values \
  --set admission.enabled=true \
  --set 'admission.approvedDigests={<sha256-of-a-passed-model>}'
kubectl label ns my-app purser.io/admission=enforce
```

**Closing the loop (`admission.autoApprove.enabled=true`).** Instead of
operator-managing `admission.approvedDigests`, let verdicts maintain the list:
a `PASS` at any scan endpoint patches each scanned file's SHA-256 into the
approvals ConfigMap through the Kubernetes API, and a later `FAIL`/`BLOCKED`
**revokes** it. The chart then mounts the ServiceAccount token on the core/HF
pods and adds a namespaced Role limited to that one ConfigMap. This makes the
scanner an *approval authority* — leave it off where a human review step is
the point (see `SECURITY.md`, trust boundary 6), and tune which verdicts
approve with `admission.autoApprove.verdicts`.

## Upgrade / uninstall

```bash
helm upgrade purser deploy/helm/purser -n purser -f my-values.yaml
helm uninstall purser -n purser        # the API-key Secret is retained by policy
```
