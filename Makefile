# Purser supply-chain targets. Reproducible builds, SBOMs, image signing.
#
# Requires: uv (locks), docker (build), python. Optional: cosign (sign),
# syft (richer SBOM), trivy (vuln scan) — targets that need them say so.

IMAGE       ?= purser
TAG         ?= dev
REGISTRY    ?=
CORE_IMAGE  := $(REGISTRY)$(IMAGE):$(TAG)
HF_IMAGE    := $(REGISTRY)$(IMAGE)-hf:$(TAG)
VERSION     := $(shell python -c "import tomllib;print(tomllib.load(open('pyproject.toml','rb'))['project']['version'])")

.PHONY: help build-deep lock lock-verify sbom licenses build build-hf build-all buildx-all sign verify-sig scan scan-deps test clean base-digest

help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
	  awk 'BEGIN{FS=":.*?## "}{printf "  %-14s %s\n",$$1,$$2}'

lock: ## Regenerate hash-pinned lockfiles from pyproject.toml
	uv pip compile --generate-hashes --extra sign -o requirements.lock pyproject.toml
	uv pip compile --generate-hashes --extra sign --extra hf -o requirements-hf.lock pyproject.toml
	uv pip compile --generate-hashes --extra deep -o requirements-deep.lock pyproject.toml

lock-verify: ## Fail if lockfiles are stale vs pyproject.toml (CI gate)
	@cp requirements.lock requirements.lock.bak
	@cp requirements-hf.lock requirements-hf.lock.bak
	@$(MAKE) -s lock
	@diff -q requirements.lock requirements.lock.bak >/dev/null && \
	 diff -q requirements-hf.lock requirements-hf.lock.bak >/dev/null && \
	 echo "lockfiles up to date" || (echo "ERROR: lockfiles are stale; run 'make lock'"; \
	  mv requirements.lock.bak requirements.lock; mv requirements-hf.lock.bak requirements-hf.lock; exit 1)
	@rm -f requirements.lock.bak requirements-hf.lock.bak

sbom: ## Generate CycloneDX SBOMs (license-aware) from the lockfiles
	python scripts/gen_sbom.py requirements.lock sbom/purser-core.cdx.json --name $(IMAGE) --version $(VERSION)
	python scripts/gen_sbom.py requirements-hf.lock sbom/purser-hf.cdx.json --name $(IMAGE)-hf --version $(VERSION)
	python scripts/gen_sbom.py requirements-deep.lock sbom/purser-deep.cdx.json --name $(IMAGE)-deep --version $(VERSION)

licenses: sbom ## Regenerate THIRD_PARTY_LICENSES.md from the SBOMs
	python scripts/gen_third_party_licenses.py THIRD_PARTY_LICENSES.md \
	  sbom/purser-core.cdx.json sbom/purser-hf.cdx.json sbom/purser-deep.cdx.json

base-digest: ## Print the current Wolfi base manifest digest (to update the pin)
	@docker buildx imagetools inspect cgr.dev/chainguard/wolfi-base:latest --format '{{.Manifest.Digest}}'

build: ## Build the slim core image (hash-verified deps, no HuggingFace)
	docker build -t $(CORE_IMAGE) -f Dockerfile .

build-hf: ## Build the HuggingFace worker image
	docker build -t $(HF_IMAGE) -f Dockerfile.hf .

build-deep: ## Build the deep-analysis companion image
	docker build -t $(REGISTRY)$(IMAGE)-deep:$(TAG) -f Dockerfile.deep .

build-all: build build-hf build-deep sbom ## Build all images and SBOMs

sign: ## Sign both images with cosign (needs cosign + push access)
	@command -v cosign >/dev/null || { echo "cosign not installed"; exit 1; }
	cosign sign --yes $(CORE_IMAGE)
	cosign sign --yes $(HF_IMAGE)
	cosign attest --yes --predicate sbom/purser-core.cdx.json --type cyclonedx $(CORE_IMAGE)
	cosign attest --yes --predicate sbom/purser-hf.cdx.json --type cyclonedx $(HF_IMAGE)

verify-sig: ## Verify image signatures with cosign
	@command -v cosign >/dev/null || { echo "cosign not installed"; exit 1; }
	cosign verify $(CORE_IMAGE)

buildx-all: ## Multi-arch (amd64+arm64) build+push of both images
	docker buildx build --platform linux/amd64,linux/arm64 --provenance=true \
	  --sbom=true --push -t $(CORE_IMAGE) -f Dockerfile .
	docker buildx build --platform linux/amd64,linux/arm64 --provenance=true \
	  --sbom=true --push -t $(HF_IMAGE) -f Dockerfile.hf .

scan: ## Vulnerability-scan the core image with trivy
	@command -v trivy >/dev/null || { echo "trivy not installed"; exit 1; }
	trivy image --exit-code 1 --severity HIGH,CRITICAL $(CORE_IMAGE)

scan-deps: sbom ## Scan the SBOM dependencies against OSV
	@command -v osv-scanner >/dev/null || { echo "osv-scanner not installed"; exit 1; }
	osv-scanner scan --sbom sbom/purser-core.cdx.json
	osv-scanner scan --sbom sbom/purser-hf.cdx.json

test: ## Run the test suite
	python -m pytest -q

clean:
	rm -f requirements.lock.bak requirements-hf.lock.bak
	rm -rf sbom
