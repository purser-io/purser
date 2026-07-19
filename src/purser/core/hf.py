"""Optional HuggingFace Hub integration (requires `purser[hf]`)."""

from __future__ import annotations

import tempfile
from pathlib import Path


class HFNotAvailable(RuntimeError):
    pass


def download_repo(repo_id: str, revision: str | None = None, token: str | None = None) -> Path:
    """Snapshot-download a HF model repo for scanning. Returns the local path."""
    try:
        from huggingface_hub import snapshot_download
    except ImportError as exc:
        raise HFNotAvailable(
            "huggingface_hub is not installed; install purser[hf]"
        ) from exc
    local = snapshot_download(
        repo_id=repo_id,
        revision=revision,
        token=token,
        cache_dir=tempfile.mkdtemp(prefix="purser-hf-"),
    )
    return Path(local)


def parse_hf_uri(uri: str) -> str | None:
    """Return the repo id for hf://org/name style URIs, else None."""
    if uri.startswith("hf://"):
        return uri[len("hf://"):]
    return None
