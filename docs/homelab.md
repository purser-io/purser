# Purser for homelabs

Purser is a single, self-contained container with **no callbacks, no accounts,
and no cloud dependency** — which makes a homelab one of its easiest
deployments. This guide covers the paths self-hosters actually use: Ollama,
plain Docker, Compose, Unraid, and K3s.

Everything here works **offline** after the image is pulled.

---

## 1. The one-liner

```bash
docker run --rm -v /path/to/models:/models:ro \
  ghcr.io/purser-io/purser:0.3.0 purser scan /models
```

The image is multi-arch (`linux/amd64` + `linux/arm64`), anonymously pullable,
and cosign-signed. ARM64 means a Raspberry Pi, an Apple-silicon VM, or an ARM
NAS all work unmodified.

Exit codes: `0` pass/warn · `1` findings · `2` policy-blocked · `3` error.

Prefer Python? `pip install purser && purser scan /path/to/models`.

---

## 2. Ollama

Ollama stores models under `~/.ollama/models` as **extensionless
`sha256-<hex>` blobs**. Purser detects formats by **magic bytes rather than
filename**, so it recognises those blobs as GGUF with no extension to go on —
just point it at the store:

```bash
docker run --rm -v ~/.ollama/models:/models:ro \
  ghcr.io/purser-io/purser:0.3.0 purser scan /models
```

What you get on a GGUF blob today: malformed-container detection
(`GGUF_BAD_MAGIC`) and **chat-template injection** (`GGUF_TEMPLATE_INJECTION`)
— an SSTI-style payload in the template metadata that fires when the model is
prompted. Manifests and config JSON in the store are scanned too.

> [!NOTE]
> **Known gap, stated plainly.** The `loader-cves` signal maps *declared
> framework versions* to known load-time CVEs, and its channels today are
> `keras_version` and `transformers_version`. GGUF carries no version string
> Purser can key off, so **GGUF artifacts get format scanning but no
> loader-CVE advisory**. Tracked in [`ROADMAP.md`](../ROADMAP.md).

### Scan on pull

Wrap `ollama pull` so nothing lands unscanned:

```bash
ollama-safe() {
  ollama pull "$1" || return 1
  docker run --rm -v ~/.ollama/models:/models:ro \
    ghcr.io/purser-io/purser:0.3.0 purser scan /models
}
```

---

## 3. Docker Compose

[`docker-compose.yml`](../docker-compose.yml) runs Purser as a long-lived REST
service. It uses the **published images**, so no clone or build is needed —
download just that one file:

```bash
curl -O https://raw.githubusercontent.com/purser-io/purser/main/docker-compose.yml
PURSER_MODELS=~/.ollama/models docker compose up -d
curl localhost:8080/healthz
```

`PURSER_MODELS` points the read-only mount at your store (`/mnt/user/models` on
Unraid, `~/.ollama/models` for Ollama). The policy defaults to the one baked
into the image; set `PURSER_POLICY` and mount `./policies` to use `strict.yaml`
or `signed-only.yaml`.

Optional profiles: `--profile deep` (gadget-chain + weight-tampering
analysis), `--profile hf` (HuggingFace download worker — needs egress).

> Set `PURSER_API_KEY` if the port is reachable from anything you don't
> control. With no key configured the `/v1` endpoints are **open by design**
> for trusted networks.

---

## 4. Unraid

Install from **Community Applications**, or add the template manually:

1. *Docker* → *Add Container* → *Template repositories* →
   `https://github.com/purser-io/purser`
2. Or import [`deploy/unraid/purser.xml`](../deploy/unraid/purser.xml).

Defaults in the template: `/mnt/user/models` mounted read-only at `/models`,
WebUI on `8080`, and the container running as `10001:10001` non-root with a
read-only root filesystem.

To scan on a schedule instead of running a service, use *User Scripts*:

```bash
#!/bin/bash
docker run --rm -v /mnt/user/models:/models:ro \
  ghcr.io/purser-io/purser:0.3.0 purser scan /models --format json \
  > /mnt/user/appdata/purser/last-scan.json
```

---

## 5. K3s

The [Helm chart](../deploy/helm/purser/) works on K3s unchanged. Ingress,
autoscaling, and the admission webhook are **all off by default**, so a
single-node homelab install only needs to drop the replica count from 2:

```bash
helm install purser oci://ghcr.io/purser-io/charts/purser --version 0.3.0 \
  --set replicaCount=1
```

Add `--set admission.enabled=true` when you want models actually *blocked* at
admission rather than merely reported. That turns Purser from a scanner into a
gate, and is the one setting worth understanding before you enable it.

---

## 6. Staying current offline

Loader-CVE intel refreshes independently of the Purser version:

```bash
purser update-intel          # validated HTTPS fetch to ~/.purser/
```

Fully air-gapped? Mirror the dataset and point at it — no egress at all:

```bash
export PURSER_LOADER_CVES=/srv/intel/loader_cves.yaml
# or mirror the whole feed:
export PURSER_INTEL_URL=https://intel.internal/purser/
```

---

## 7. What Purser does *not* do

Worth knowing before you rely on it:

- It **never loads or executes a model** — analysis is byte- and opcode-level.
  A `PASS` means "clear of known malicious content," not "certified safe."
- It does not detect **trained/behavioural backdoors**. A perfectly valid
  safetensors file can still misbehave; that needs evaluation tooling.
- It does not inspect **prompts or inference traffic** — this is artifact
  supply-chain security, not an LLM firewall.

See [`gap_analysis.md`](../gap_analysis.md) §8 for the full residual-risk list.
