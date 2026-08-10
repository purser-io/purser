# Purser core scanner service — slim image, NO HuggingFace dependency tree.
#
# Multi-stage build on Wolfi (Chainguard's minimal, glibc, low-CVE base):
#   * build stage installs deps from a hash-pinned lockfile into a venv
#     (--require-hashes rejects any package whose hash doesn't match)
#   * final stage is wolfi-base + python runtime only; it copies the venv, so
#     no pip / compilers / build tooling ship in the running image.
#
# The HuggingFace download endpoint (/v1/scan/huggingface) is NOT available in
# this image on purpose; run the separate HF worker (Dockerfile.hf) for that.

# Pinned by digest for reproducible builds (update with: make base-digest).
ARG WOLFI=cgr.dev/chainguard/wolfi-base:latest@sha256:30f03343947c7ae3581fda727a6e2aa7b8ce7009b7bfc2ab8d5c9483ace5812f

FROM ${WOLFI} AS build
WORKDIR /app
# python-dev + build-base only in the build stage (discarded) for any sdist.
# Versions are pinned because `apk add` resolves against the live Wolfi repo —
# the digest pin above does not freeze the toolchain on its own. Refreshed with
# the digest by wolfi-base-check.yml (manual path: `make apk-pins`).
RUN apk add --no-cache \
      python-3.14=3.14.7-r0 \
      python-3.14-dev=3.14.7-r0 \
      py3.14-pip=26.2.1-r0 \
      build-base=1-r9
RUN python3.14 -m venv /venv
ENV PATH="/venv/bin:$PATH"
COPY requirements.lock ./
RUN pip install --no-cache-dir --require-hashes -r requirements.lock
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir --no-deps .
# venv creation seeds pip/setuptools via ensurepip, and the venv is copied into
# the final stage — so they'd ship at runtime despite the "no pip" intent above.
# pip also vendors its own deps (msgpack, setuptools), which the CVE gate flags.
RUN pip uninstall -y setuptools && pip uninstall -y pip

FROM ${WOLFI}
LABEL org.opencontainers.image.title="Purser" \
      org.opencontainers.image.description="Model supply-chain control plane: policy, provenance, and enforcement for ML model artifacts" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.base.name="cgr.dev/chainguard/wolfi-base:latest"

# Runtime python only — no pip, no compilers, no build tooling.
RUN apk add --no-cache \
      python-3.14=3.14.7-r0 \
    && mkdir -p /models /policies \
    && chown -R 10001:10001 /models /policies

COPY --from=build /venv /venv
COPY policies/default.yaml /policies/default.yaml

USER 10001:10001
ENV PATH="/venv/bin:$PATH" \
    PURSER_POLICY=/policies/default.yaml \
    PURSER_SCAN_ROOT=/models \
    PYTHONUNBUFFERED=1

EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD ["/venv/bin/python", "-c", "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8080/healthz')"]

ENTRYPOINT []
CMD ["/venv/bin/uvicorn", "purser.api:app", "--host", "0.0.0.0", "--port", "8080"]
