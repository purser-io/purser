"""Model file-format detection by magic bytes and extension."""

from __future__ import annotations

import enum
import json
import struct
import zipfile
from pathlib import Path


class ModelFormat(str, enum.Enum):
    PICKLE = "pickle"
    PYTORCH = "pytorch"            # zip-based .pt/.pth/.bin (torch >= 1.6)
    PYTORCH_LEGACY = "pytorch_legacy"  # tar/stream-based legacy torch serialization
    PT2 = "pt2"                    # torch.export archives
    EXECUTORCH = "executorch"      # .pte flatbuffers
    JOBLIB = "joblib"
    NUMPY = "numpy"
    KERAS_H5 = "keras_h5"
    KERAS_V3 = "keras_v3"          # .keras zip archive
    TF_SAVEDMODEL = "tf_savedmodel"
    TFLITE = "tflite"
    TFJS = "tfjs"                  # model.json + weight shards
    ONNX = "onnx"
    SAFETENSORS = "safetensors"
    GGUF = "gguf"
    GGML = "ggml"                  # pre-GGUF legacy quantized formats
    COREML = "coreml"              # .mlmodel / .mlpackage members
    SKOPS = "skops"                # sklearn skops archives
    FLAX_MSGPACK = "flax_msgpack"  # JAX/Flax msgpack checkpoints
    PADDLE = "paddle"              # PaddlePaddle program protobufs
    MXNET = "mxnet"                # MXNet .params
    OPENVINO = "openvino"          # OpenVINO IR .xml
    PMML = "pmml"
    GBM_NATIVE = "gbm_native"      # XGBoost .ubj, CatBoost .cbm, ...
    PYTHON_SOURCE = "python_source"  # bundled .py (trust_remote_code)
    HF_CONFIG = "hf_config"        # config.json etc. (auto_map)
    ARCHIVE = "archive"
    UNKNOWN = "unknown"


# Extensions that are unambiguously pickle containers: content that fails to
# parse as pickle is itself a finding (evasion / corruption).
STRICT_PICKLE_EXTS = {".pkl", ".pickle", ".dill", ".joblib", ".pkls",
                      ".pdparams", ".pdiparams"}
# Extensions commonly-but-not-always pickle (torch, generic weight blobs):
# only treated as pickle when the content looks like one.
LOOSE_PICKLE_EXTS = {".pt", ".pth", ".bin", ".ckpt", ".model"}
PICKLE_EXTS = STRICT_PICKLE_EXTS | LOOSE_PICKLE_EXTS

MODEL_EXTS = PICKLE_EXTS | {
    ".h5", ".hdf5", ".keras", ".onnx", ".safetensors", ".gguf", ".ggml",
    ".npy", ".npz", ".pb", ".tflite", ".pte", ".pt2", ".mlmodel", ".skops",
    ".pdmodel", ".params", ".msgpack", ".flax", ".ubj", ".cbm", ".pmml",
    ".zip", ".tar", ".gz", ".tgz",
}

HDF5_MAGIC = b"\x89HDF\r\n\x1a\n"
GGUF_MAGIC = b"GGUF"
GGML_MAGICS = {b"lmgg", b"fmgg", b"tjgg", b"algg", b"ggml"}
NUMPY_MAGIC = b"\x93NUMPY"
ZIP_MAGIC = b"PK\x03\x04"
TFLITE_ID = b"TFL3"  # flatbuffer identifier at offset 4


def _looks_like_pickle(head: bytes) -> bool:
    if not head:
        return False
    # Protocol 2+ starts with PROTO opcode \x80 followed by version byte.
    if head[0] == 0x80 and len(head) > 1 and 2 <= head[1] <= 5:
        return True
    # Protocol 0/1 commonly starts with (, ], }, c (GLOBAL), etc.
    return head[:1] in (b"(", b"]", b"}", b"c", b"\x8c", b")")


def _looks_like_safetensors(head: bytes) -> bool:
    if len(head) < 10:
        return False
    (header_len,) = struct.unpack("<Q", head[:8])
    if header_len == 0 or header_len > 500_000_000:
        return False
    return head[8:9] in (b"{", b" ")


def _classify_zip(path: Path) -> ModelFormat:
    suffix = path.suffix.lower()
    if suffix == ".pt2":
        return ModelFormat.PT2
    try:
        with zipfile.ZipFile(path) as zf:
            names = zf.namelist()
    except zipfile.BadZipFile:
        return ModelFormat.UNKNOWN
    if suffix == ".skops" or "schema.json" in names:
        return ModelFormat.SKOPS
    if any(n.endswith("data.pkl") for n in names):
        return ModelFormat.PYTORCH
    if any(n.endswith("config.json") for n in names) and any(
        n.endswith(("metadata.json", "model.weights.h5")) for n in names
    ):
        return ModelFormat.KERAS_V3
    if suffix == ".keras":
        return ModelFormat.KERAS_V3
    if suffix == ".npz":
        return ModelFormat.NUMPY
    return ModelFormat.ARCHIVE


def _classify_text(path: Path, suffix: str) -> ModelFormat:
    """Sniff text-based model formats (TF.js manifest, PMML, OpenVINO IR)."""
    try:
        head = path.read_bytes()[:8192].decode("utf-8", "replace")
    except OSError:
        return ModelFormat.UNKNOWN
    if suffix == ".json" or path.name == "model.json":
        if '"weightsManifest"' in head:
            return ModelFormat.TFJS
        if "config" in path.name.lower():
            return ModelFormat.HF_CONFIG
        return ModelFormat.UNKNOWN
    if "<PMML" in head:
        return ModelFormat.PMML
    if "<?xml" in head and "<net" in head:
        return ModelFormat.OPENVINO
    return ModelFormat.UNKNOWN


def detect_format(path: Path) -> ModelFormat:
    """Detect the model format of a file. Magic bytes win over extension."""
    try:
        with open(path, "rb") as fh:
            head = fh.read(16)
    except OSError:
        return ModelFormat.UNKNOWN

    suffix = path.suffix.lower()

    if head.startswith(HDF5_MAGIC):
        return ModelFormat.KERAS_H5
    if head.startswith(GGUF_MAGIC):
        return ModelFormat.GGUF
    if head[:4] in GGML_MAGICS or suffix == ".ggml":
        return ModelFormat.GGML
    if head.startswith(NUMPY_MAGIC):
        return ModelFormat.NUMPY
    if len(head) >= 8 and head[4:8] == TFLITE_ID:
        return ModelFormat.TFLITE
    if head.startswith(ZIP_MAGIC):
        return _classify_zip(path)
    if suffix == ".safetensors":
        # Route by extension even when the header looks wrong — the
        # safetensors scanner reports the malformation.
        return ModelFormat.SAFETENSORS
    if suffix == ".py":
        return ModelFormat.PYTHON_SOURCE
    if suffix in (".json", ".xml", ".pmml") or path.name == "model.json":
        return _classify_text(path, suffix)
    if suffix == ".tflite":
        return ModelFormat.TFLITE  # scanner flags the magic mismatch
    if suffix == ".pte":
        return ModelFormat.EXECUTORCH
    if suffix == ".mlmodel":
        return ModelFormat.COREML
    if suffix == ".pdmodel":
        return ModelFormat.PADDLE
    if suffix in (".msgpack", ".flax"):
        return ModelFormat.FLAX_MSGPACK
    if suffix == ".params":
        return ModelFormat.MXNET
    if suffix in (".ubj", ".cbm"):
        return ModelFormat.GBM_NATIVE
    if suffix == ".onnx":
        return ModelFormat.ONNX
    if suffix == ".pb" or path.name == "saved_model.pb":
        return ModelFormat.TF_SAVEDMODEL
    if suffix in (".tar", ".gz", ".tgz"):
        return ModelFormat.ARCHIVE
    if _looks_like_safetensors(head) and suffix in ("", ".bin"):
        # safetensors saved without extension
        if _validate_safetensors_header(path):
            return ModelFormat.SAFETENSORS
    if _looks_like_pickle(head):
        if suffix == ".joblib":
            return ModelFormat.JOBLIB
        return ModelFormat.PICKLE
    if suffix in STRICT_PICKLE_EXTS:
        # Extension unambiguously claims pickle but content doesn't look like
        # it — let the pickle scanner flag the mismatch.
        return ModelFormat.PICKLE
    # Loose pickle extensions (.bin, .pt, ...) with non-pickle content are
    # weight blobs of some other toolchain — exfil scan only.
    return ModelFormat.UNKNOWN


def _validate_safetensors_header(path: Path) -> bool:
    try:
        with open(path, "rb") as fh:
            (header_len,) = struct.unpack("<Q", fh.read(8))
            if header_len > 100_000_000:
                return False
            header = fh.read(header_len)
        json.loads(header)
        return True
    except Exception:
        return False
