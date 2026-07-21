# Purser Helm chart

Production-ready chart for **Purser** — the ML model security scanner. Deploys
the core scanning service and, optionally, the HuggingFace worker and the
deep-analysis companion.

## Install

```bash
# published OCI chart (recommended) — defaults to the ghcr.io/purser-io images
helm install purser oci://ghcr.io/purser-io/charts/purser --version 0.1.1 \
  -n purser --create-namespace

# …or from a source checkout
helm install purser deploy/helm/purser -n purser --create-namespace

# manage the API key yourself / mirror the images
helm install purser oci://ghcr.io/purser-io/charts/purser --version 0.1.1 \
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
| Hardened pod/container securityContext | NetworkPolicy (`networkPolicy.enabled`) |

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
| `modelStore.enabled` | `false` | mount a PVC for `/v1/scan/path` |
| `deep.enabled` / `hf.enabled` | `false` | optional companions |

See [`values.yaml`](values.yaml) for the fully-documented set; `values.schema.json`
validates them at install time.

## Upgrade / uninstall

```bash
helm upgrade purser deploy/helm/purser -n purser -f my-values.yaml
helm uninstall purser -n purser        # the API-key Secret is retained by policy
```
