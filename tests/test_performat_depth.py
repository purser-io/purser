"""Per-format scanner depth (roadmap #2): Keras non-Lambda custom layers and
OpenVINO IR graph parsing."""

from __future__ import annotations

import json
import zipfile

from purser.core.dispatch import scan_file
from purser.core.formats import ModelFormat
from purser.scanners.formats import KerasH5Scanner, OpenVINOScanner


def _kr(cfg: dict) -> set[str]:
    return {f.rule_id for f in KerasH5Scanner()._scan_config_json(json.dumps(cfg))}


# --------------------------- Keras: v3 (module-aware) -----------------------

def test_keras_v3_builtin_clean():
    cfg = {"module": "keras", "class_name": "Sequential", "config": {"layers": [
        {"module": "keras.layers", "class_name": "Dense", "config": {}},
        {"module": "keras.layers", "class_name": "Conv2D", "config": {}}]}}
    assert _kr(cfg) == set()


def test_keras_v3_custom_module_flagged():
    cfg = {"module": "keras", "class_name": "Functional", "config": {"layers": [
        {"module": "evil_pkg.layers", "class_name": "Backdoor", "config": {},
         "registered_name": "Backdoor"}]}}
    assert "KERAS_CUSTOM_LAYER" in _kr(cfg)


def test_keras_v3_trusted_thirdparty_clean():
    cfg = {"module": "keras", "class_name": "Functional", "config": {"layers": [
        {"module": "transformers.models.bert", "class_name": "TFBertMainLayer",
         "config": {}}]}}
    assert _kr(cfg) == set()


def test_keras_lambda_still_critical():
    cfg = {"class_name": "Model", "config": {"layers": [{"class_name": "Lambda"}]}}
    fs = KerasH5Scanner()._scan_config_json(json.dumps(cfg))
    assert any(f.rule_id == "KERAS_LAMBDA_LAYER" and f.severity.name == "CRITICAL"
               for f in fs)


# --------------------------- Keras: legacy byte fallback --------------------

def test_keras_bytes_builtin_clean():
    data = b'HDF\x00{"class_name": "Sequential", "config": {"layers": [' \
           b'{"class_name": "Dense"}, {"class_name": "BatchNormalization"}]}}'
    assert {f.rule_id for f in KerasH5Scanner()._scan_config_bytes(data)} == set()


def test_keras_bytes_custom_flagged():
    data = b'HDF\x00{"class_name": "Model", "config": {"layers": [' \
           b'{"class_name": "MyBackdoorLayer"}]}}'
    assert "KERAS_CUSTOM_LAYER" in {f.rule_id
                                    for f in KerasH5Scanner()._scan_config_bytes(data)}


def test_keras_v3_file_integration(tmp_path):
    cfg = {"module": "keras", "class_name": "Sequential", "config": {"layers": [
        {"module": "shady.pkg", "class_name": "Evil", "config": {}}]}}
    p = tmp_path / "model.keras"
    with zipfile.ZipFile(p, "w") as z:
        z.writestr("config.json", json.dumps(cfg))
        z.writestr("metadata.json", "{}")
    fmt, findings = scan_file(p)
    assert fmt is ModelFormat.KERAS_V3
    assert any(f.rule_id == "KERAS_CUSTOM_LAYER" for f in findings)


def test_keras_deeply_nested_config_terminates():
    # Adversarial nesting must not hang (walk depth/budget bound).
    node: dict = {"class_name": "Dense"}
    for _ in range(500):
        node = {"class_name": "Wrapper", "config": {"layer": node}}
    KerasH5Scanner()._scan_config_json(json.dumps(node))  # returns, no hang


# --------------------------- OpenVINO IR ------------------------------------

def _ov(xml: str, tmp_path) -> set[str]:
    p = tmp_path / "m.xml"
    p.write_text(xml)
    return {f.rule_id for f in OpenVINOScanner().scan(p)}


def test_openvino_clean(tmp_path):
    xml = ('<?xml version="1.0"?><net name="m"><layers>'
           '<layer id="0" type="Parameter" name="in"><data shape="1,3,224,224"/></layer>'
           '<layer id="1" type="Convolution" name="c"/></layers><edges/></net>')
    assert _ov(xml, tmp_path) == set()


def test_openvino_xxe(tmp_path):
    xml = ('<?xml version="1.0"?><!DOCTYPE net [<!ENTITY x SYSTEM '
           '"file:///etc/passwd">]><net><layers/></net>')
    assert "OPENVINO_XXE" in _ov(xml, tmp_path)


def test_openvino_shared_library_ref(tmp_path):
    xml = ('<?xml version="1.0"?><net><layers><layer type="Custom">'
           '<data path="/opt/x/libbackdoor.so"/></layer></layers></net>')
    p = tmp_path / "m.xml"
    p.write_text(xml)
    findings = OpenVINOScanner().scan(p)
    assert any(f.rule_id == "OPENVINO_EXTERNAL_REF" and f.severity.name == "HIGH"
               for f in findings)


def test_openvino_absolute_path_ref(tmp_path):
    xml = ('<?xml version="1.0"?><net><layers><layer type="X">'
           '<data w="/etc/shadow"/></layer></layers></net>')
    assert "OPENVINO_EXTERNAL_REF" in _ov(xml, tmp_path)


def test_openvino_malformed(tmp_path):
    assert "OPENVINO_MALFORMED" in _ov('<?xml version="1.0"?><net><layers>', tmp_path)


def test_openvino_file_integration(tmp_path):
    xml = ('<?xml version="1.0"?><net name="m"><layers><layer type="Custom">'
           '<data path="/lib/evil.so"/></layer></layers></net>')
    p = tmp_path / "model.xml"
    p.write_text(xml)
    fmt, findings = scan_file(p)
    assert fmt is ModelFormat.OPENVINO
    assert any(f.rule_id == "OPENVINO_EXTERNAL_REF" for f in findings)
