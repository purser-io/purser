from pathlib import Path

from purser.core.dispatch import scan_file
from purser.core.findings import Severity
from purser.core.formats import ModelFormat, detect_format


def test_pytorch_zip_detection_and_scan(evil_pytorch_zip: Path):
    fmt = detect_format(evil_pytorch_zip)
    assert fmt == ModelFormat.PYTORCH
    _, findings = scan_file(evil_pytorch_zip)
    assert any(f.rule_id == "PICKLE_DANGEROUS_IMPORT" for f in findings)


def test_benign_pytorch_zip(benign_pytorch_zip: Path):
    _, findings = scan_file(benign_pytorch_zip)
    assert not [f for f in findings if f.severity >= Severity.HIGH]


def test_safetensors_valid(safetensors_valid: Path):
    assert detect_format(safetensors_valid) == ModelFormat.SAFETENSORS
    _, findings = scan_file(safetensors_valid)
    assert not findings


def test_safetensors_malformed(safetensors_malformed: Path):
    _, findings = scan_file(safetensors_malformed)
    assert any(f.rule_id == "SAFETENSORS_MALFORMED" for f in findings)


def test_keras_lambda(keras_h5_lambda: Path):
    assert detect_format(keras_h5_lambda) == ModelFormat.KERAS_H5
    _, findings = scan_file(keras_h5_lambda)
    assert any(
        f.rule_id == "KERAS_LAMBDA_LAYER" and f.severity == Severity.CRITICAL
        for f in findings
    )


def test_gguf_ssti(gguf_ssti: Path):
    assert detect_format(gguf_ssti) == ModelFormat.GGUF
    _, findings = scan_file(gguf_ssti)
    assert any(f.rule_id == "GGUF_TEMPLATE_INJECTION" for f in findings)


def test_gguf_clean(gguf_clean: Path):
    _, findings = scan_file(gguf_clean)
    assert not [f for f in findings if f.severity >= Severity.MEDIUM]


def test_tf_pyfunc(tf_pyfunc_pb: Path):
    assert detect_format(tf_pyfunc_pb) == ModelFormat.TF_SAVEDMODEL
    _, findings = scan_file(tf_pyfunc_pb)
    assert any(
        f.rule_id == "TF_DANGEROUS_OP" and f.severity == Severity.CRITICAL
        for f in findings
    )


def test_npy_object_array(npy_object_array: Path):
    assert detect_format(npy_object_array) == ModelFormat.NUMPY
    _, findings = scan_file(npy_object_array)
    ids = {f.rule_id for f in findings}
    assert "NUMPY_OBJECT_ARRAY" in ids
    assert "PICKLE_DANGEROUS_IMPORT" in ids, "embedded pickle payload must be scanned"


def test_zip_slip(zip_slip_archive: Path):
    _, findings = scan_file(zip_slip_archive)
    assert any(f.rule_id == "ARCHIVE_PATH_TRAVERSAL" for f in findings)
