"""Download the pinned benign models into work/benign/ for the FPR benchmark.

Optional — needs the HF extra: `pip install "purser[hf]"`. Resolves each repo's
revision to a commit SHA and records it in benign_models.lock.json for
reproducibility. These are reputable public models used as the negative set;
nothing malicious is downloaded.

    python benchmarks/fetch_benign.py
"""
from __future__ import annotations

import json
from pathlib import Path

import yaml

try:
    from huggingface_hub import HfApi, snapshot_download
except ImportError:  # pragma: no cover
    raise SystemExit("huggingface_hub is required — install with: pip install 'purser[hf]'")

HERE = Path(__file__).parent
PATTERNS = ["*.safetensors", "*.bin", "*.gguf", "*.onnx", "*.h5", "*.pb",
            "*.pkl", "*.pt", "*.pth", "config.json"]


def main() -> None:
    spec = yaml.safe_load((HERE / "benign_models.yaml").read_text())
    cache = HERE / "work" / "benign"
    cache.mkdir(parents=True, exist_ok=True)
    api = HfApi()
    locked = []
    for m in spec["models"]:
        repo, rev = m["repo"], m.get("revision", "main")
        try:
            sha = api.model_info(repo, revision=rev).sha
            dest = cache / repo.replace("/", "__")
            snapshot_download(repo, revision=sha, local_dir=str(dest),
                              allow_patterns=PATTERNS)
        except Exception as e:  # network / gated / missing — skip, keep going
            print(f"skip {repo}: {e}")
            continue
        locked.append({"id": repo.replace("/", "__"), "repo": repo,
                       "revision": sha, "format": m.get("format", "mixed")})
        print(f"fetched {repo} @ {sha[:12]}")
    (HERE / "benign_models.lock.json").write_text(
        json.dumps({"models": locked}, indent=2))
    print(f"\npinned {len(locked)} models -> benign_models.lock.json")


if __name__ == "__main__":
    main()
