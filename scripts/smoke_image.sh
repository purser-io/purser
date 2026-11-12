#!/usr/bin/env bash
# Start an image with its default command and wait for /healthz to answer.
#
# A Trivy-clean image that cannot start is not a fix. The refresh workflow
# bumps apk and lockfile pins unattended — including major versions — so the
# build has to prove the service still boots before a PR claims it is good.
#
# Usage: scripts/smoke_image.sh <image> [timeout-seconds]
set -euo pipefail

image=${1:?usage: smoke_image.sh <image> [timeout-seconds]}
timeout=${2:-45}

# The port comes from the image's own EXPOSE, so this needs no per-image table.
port=$(docker inspect -f '{{range $p, $_ := .Config.ExposedPorts}}{{$p}} {{end}}' "$image" \
  | awk '{print $1}' | cut -d/ -f1)
if [ -z "$port" ]; then
  echo "smoke: $image exposes no port" >&2
  exit 1
fi

cid=$(docker run -d "$image")
trap 'docker rm -f "$cid" >/dev/null 2>&1 || true' EXIT

probe="import urllib.request; urllib.request.urlopen('http://127.0.0.1:${port}/healthz', timeout=2)"
for _ in $(seq 1 "$timeout"); do
  if docker exec "$cid" /venv/bin/python -c "$probe" >/dev/null 2>&1; then
    echo "smoke: $image answers /healthz on :$port"
    exit 0
  fi
  # Exited already: no point waiting out the timeout.
  if [ "$(docker inspect -f '{{.State.Running}}' "$cid" 2>/dev/null)" != "true" ]; then
    break
  fi
  sleep 1
done

echo "smoke: $image did not become healthy on :$port — container log:" >&2
docker logs "$cid" 2>&1 | tail -n 40 >&2
exit 1
