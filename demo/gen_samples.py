#!/usr/bin/env python3
"""Generate small sample models for trying the Purser CLI.

Stdlib only — no numpy/torch needed. Writes into demo/models/:

  benign (committed):
    clean-model.safetensors   valid safetensors header, no tensors -> PASS
    config.json               benign HuggingFace config -> PASS
    benign.pkl                a plain dict pickle -> PASS

  intentionally malicious (gitignored — generated locally):
    suspicious.pkl            pickle that resolves os.system on load (payload is
                              a harmless `echo`; Purser never executes it) -> FAIL
    exfil-sample.bin          text with a fake Slack webhook + example AWS key
                              to trip the exfiltration engine -> WARN/FAIL

Nothing here is executed. Pickles are *serialized* (safe); the malicious sample
only runs its echo if some *other* tool unpickles it — Purser never does.
"""
from __future__ import annotations

import json
import os
import pickle
import struct
from pathlib import Path

OUT = Path(__file__).parent / "models"


def _safetensors(path: Path) -> None:
    header = json.dumps({"__metadata__": {"format": "pt"}}).encode()
    path.write_bytes(struct.pack("<Q", len(header)) + header)


def _config(path: Path) -> None:
    path.write_text(json.dumps({
        "model_type": "bert",
        "architectures": ["BertModel"],
        "hidden_size": 32,
        "num_hidden_layers": 2,
    }, indent=2))


def _benign_pickle(path: Path) -> None:
    with path.open("wb") as fh:
        pickle.dump({"name": "demo", "weights": [1.0, 2.0, 3.0]}, fh)


class _Reduce:
    """__reduce__ makes unpickling call os.system — flagged by the scanner.
    The payload is a harmless echo; serializing this object does NOT run it."""
    def __reduce__(self):
        return (os.system, ("echo 'purser-demo: this would run on unpickle'",))


def _suspicious_pickle(path: Path) -> None:
    with path.open("wb") as fh:
        pickle.dump(_Reduce(), fh)


def _exfil_sample(path: Path) -> None:
    path.write_text(
        "# not a real model — sample bytes to exercise the exfiltration engine\n"
        "webhook = 'https://hooks.slack.com/services/T00000000/B00000000/"
        "XXXXXXXXXXXXXXXXXXXXXXXX'\n"
        "aws_key = 'AKIAIOSFODNN7EXAMPLE'\n"
    )


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    _safetensors(OUT / "clean-model.safetensors")
    _config(OUT / "config.json")
    _benign_pickle(OUT / "benign.pkl")
    _suspicious_pickle(OUT / "suspicious.pkl")
    _exfil_sample(OUT / "exfil-sample.bin")
    print(f"wrote sample models to {OUT}/")
    for p in sorted(OUT.iterdir()):
        print(f"  {p.name:28} {p.stat().st_size} bytes")


if __name__ == "__main__":
    main()
