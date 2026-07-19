import json
import pickle
import zipfile
from pathlib import Path

from purser.core.dispatch import scan_file
from purser.core.findings import Severity
from purser.core.formats import ModelFormat, detect_format
from purser.core.scanner import iter_scannable
from tests.conftest import EvilOsSystem


def make(path: Path, data: bytes) -> Path:
    path.write_bytes(data)
    return path


# -- TFLite ------------------------------------------------------------------

def test_tflite_flex_pyfunc(tmp_path: Path):
    p = make(tmp_path / "m.tflite",
             b"\x1c\x00\x00\x00TFL3" + b"\x00" * 32 + b"FlexPyFunc" + b"\x00" * 16)
    assert detect_format(p) == ModelFormat.TFLITE
    _, findings = scan_file(p)
    hits = [f for f in findings if f.rule_id == "TFLITE_FLEX_OP"]
    assert hits and hits[0].severity == Severity.CRITICAL


def test_tflite_generic_flex_is_low(tmp_path: Path):
    p = make(tmp_path / "m.tflite",
             b"\x1c\x00\x00\x00TFL3" + b"\x00" * 32 + b"FlexConv2D" + b"\x00" * 16)
    _, findings = scan_file(p)
    hits = [f for f in findings if f.rule_id == "TFLITE_FLEX_OP"]
    assert hits and hits[0].severity == Severity.LOW


def test_tflite_bad_magic(tmp_path: Path):
    p = make(tmp_path / "fake.tflite", b"\x00" * 64)
    _, findings = scan_file(p)
    assert any(f.rule_id == "TFLITE_BAD_MAGIC" for f in findings)


# -- skops ---------------------------------------------------------------

def _skops(tmp_path: Path, schema: dict, name: str = "m.skops") -> Path:
    p = tmp_path / name
    with zipfile.ZipFile(p, "w") as zf:
        zf.writestr("schema.json", json.dumps(schema))
    return p


def test_skops_dangerous_type(tmp_path: Path):
    p = _skops(tmp_path, {
        "__class__": "system", "__module__": "os", "__loader__": "ObjectNode",
        "content": {},
    })
    assert detect_format(p) == ModelFormat.SKOPS
    _, findings = scan_file(p)
    assert any(
        f.rule_id == "SKOPS_DANGEROUS_TYPE" and f.severity == Severity.CRITICAL
        for f in findings
    )


def test_skops_pickle_fallback(tmp_path: Path):
    p = _skops(tmp_path, {
        "__class__": "GaussianNB", "__module__": "sklearn.naive_bayes",
        "__loader__": "PickleNode", "content": {},
    })
    _, findings = scan_file(p)
    assert any(f.rule_id == "SKOPS_PICKLE_FALLBACK" for f in findings)


def test_skops_clean(tmp_path: Path):
    p = _skops(tmp_path, {
        "__class__": "LogisticRegression", "__module__": "sklearn.linear_model",
        "__loader__": "ObjectNode",
        "content": {"coef_": {"__class__": "ndarray", "__module__": "numpy",
                              "__loader__": "NdArrayNode"}},
    })
    _, findings = scan_file(p)
    assert not [f for f in findings if f.severity >= Severity.MEDIUM]


# -- PaddlePaddle ----------------------------------------------------------

def test_paddle_py_func(tmp_path: Path):
    p = make(tmp_path / "m.pdmodel", b"\x0a\x10prog" + b"py_func" + b"\x00" * 8)
    assert detect_format(p) == ModelFormat.PADDLE
    _, findings = scan_file(p)
    assert any(
        f.rule_id == "PADDLE_PY_OP" and f.severity == Severity.CRITICAL
        for f in findings
    )


def test_paddle_params_are_pickle_scanned(tmp_path: Path):
    p = make(tmp_path / "m.pdparams", pickle.dumps(EvilOsSystem()))
    assert detect_format(p) == ModelFormat.PICKLE
    _, findings = scan_file(p)
    assert any(f.rule_id == "PICKLE_DANGEROUS_IMPORT" for f in findings)


# -- torch.export / ExecuTorch -----------------------------------------------

def test_pt2_embedded_pickle(tmp_path: Path):
    p = tmp_path / "m.pt2"
    with zipfile.ZipFile(p, "w") as zf:
        zf.writestr("archive/data.pkl", pickle.dumps(EvilOsSystem()))
        zf.writestr("archive/version", "1")
    assert detect_format(p) == ModelFormat.PT2
    _, findings = scan_file(p)
    assert any(f.rule_id == "PICKLE_DANGEROUS_IMPORT" for f in findings)


def test_executorch_magic(tmp_path: Path):
    good = make(tmp_path / "ok.pte", b"\x00\x00\x00\x00ET12" + b"\x00" * 32)
    bad = make(tmp_path / "bad.pte", b"\x00" * 64)
    assert detect_format(good) == ModelFormat.EXECUTORCH
    _, findings = scan_file(good)
    assert not [f for f in findings if f.severity >= Severity.MEDIUM]
    _, findings = scan_file(bad)
    assert any(f.rule_id == "EXECUTORCH_BAD_MAGIC" for f in findings)


# -- TF.js -------------------------------------------------------------------

def test_tfjs_shard_traversal(tmp_path: Path):
    p = make(tmp_path / "model.json", json.dumps({
        "format": "layers-model",
        "weightsManifest": [{"paths": ["../../../../home/user/.ssh/id_rsa"],
                             "weights": []}],
    }).encode())
    assert detect_format(p) == ModelFormat.TFJS
    _, findings = scan_file(p)
    assert any(f.rule_id == "TFJS_SHARD_TRAVERSAL" for f in findings)


def test_tfjs_clean(tmp_path: Path):
    p = make(tmp_path / "model.json", json.dumps({
        "format": "layers-model",
        "weightsManifest": [{"paths": ["group1-shard1of1.bin"], "weights": []}],
    }).encode())
    _, findings = scan_file(p)
    assert not [f for f in findings if f.severity >= Severity.MEDIUM]


def test_walker_includes_manifests_and_configs(tmp_path: Path):
    (tmp_path / "model.json").write_text("{}")      # TF.js manifest
    (tmp_path / "config.json").write_text("{}")     # HF config (auto_map lives here)
    (tmp_path / "notes.json").write_text("{}")      # unrelated JSON: skipped
    files = [p.name for p in iter_scannable(tmp_path)]
    assert "model.json" in files
    assert "config.json" in files
    assert "notes.json" not in files


# -- CoreML ------------------------------------------------------------------

def test_coreml_custom_layer(tmp_path: Path):
    p = make(tmp_path / "m.mlmodel", b"\x08\x05\x12\x20" + b"custom_layer" + b"\x00" * 16)
    assert detect_format(p) == ModelFormat.COREML
    _, findings = scan_file(p)
    assert any(f.rule_id == "COREML_CUSTOM_LAYER" for f in findings)


# -- PMML --------------------------------------------------------------------

def test_pmml_extension_script(tmp_path: Path):
    p = make(tmp_path / "m.pmml",
             b'<?xml version="1.0"?><PMML version="4.4">'
             b'<Extension name="x"><script>import os</script></Extension></PMML>')
    assert detect_format(p) == ModelFormat.PMML
    _, findings = scan_file(p)
    assert any(f.rule_id == "PMML_EXTENSION_SCRIPT" for f in findings)


def test_pmml_xxe(tmp_path: Path):
    p = make(tmp_path / "m.pmml",
             b'<?xml version="1.0"?><!DOCTYPE PMML [<!ENTITY x SYSTEM "file:///etc/passwd">]>'
             b'<PMML version="4.4"></PMML>')
    _, findings = scan_file(p)
    assert any(f.rule_id == "PMML_XXE" for f in findings)


# -- identification-only formats ----------------------------------------------

def test_ggml_legacy_identified(tmp_path: Path):
    p = make(tmp_path / "m.bin", b"tjgg" + b"\x00" * 64)
    assert detect_format(p) == ModelFormat.GGML


def test_flax_msgpack_identified(tmp_path: Path):
    p = make(tmp_path / "ckpt.msgpack", b"\x82\xa6params\x80\xa5state\x80")
    assert detect_format(p) == ModelFormat.FLAX_MSGPACK


def test_openvino_identified(tmp_path: Path):
    p = make(tmp_path / "m.xml", b'<?xml version="1.0"?><net name="m" version="11"></net>')
    assert detect_format(p) == ModelFormat.OPENVINO


# -- regression: generic .bin must not be forced through the pickle scanner ---

def test_non_pickle_bin_is_unknown_not_flagged(tmp_path: Path):
    p = make(tmp_path / "weight.bin", b"\x00\x01\x02\x03" * 64)
    assert detect_format(p) == ModelFormat.UNKNOWN
    _, findings = scan_file(p)
    assert not [f for f in findings if f.rule_id == "PICKLE_UNPARSEABLE"]


def test_strict_pickle_ext_still_flagged(tmp_path: Path):
    p = make(tmp_path / "fake.pkl", b"\xff\xfe\x00junk")
    assert detect_format(p) == ModelFormat.PICKLE
    _, findings = scan_file(p)
    assert any(f.rule_id == "PICKLE_UNPARSEABLE" for f in findings)
