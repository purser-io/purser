"""Maps detected formats to scanner instances; helper for nested scanning."""

from __future__ import annotations

import tempfile
from pathlib import Path

from purser.core.findings import Finding, Severity
from purser.core.formats import ModelFormat, detect_format
from purser.scanners.base import Scanner
from purser.scanners.exfil import ExfilScanner
from purser.scanners.extended import (
    CoreMLScanner,
    ExecuTorchScanner,
    PaddleScanner,
    PMMLScanner,
    SkopsScanner,
    TFJSScanner,
    TFLiteScanner,
)
from purser.scanners.formats import (
    GGUFScanner,
    KerasH5Scanner,
    KerasV3Scanner,
    NumpyScanner,
    ONNXScanner,
    PyTorchScanner,
    SafetensorsScanner,
    TFSavedModelScanner,
)
from purser.scanners.pickle_scanner import PickleScanner
from purser.scanners.source import HFConfigScanner, PythonSourceScanner


def scanners_for(fmt: ModelFormat, depth: int = 0) -> list[Scanner]:
    from purser.scanners.archive import ArchiveScanner

    table: dict[ModelFormat, list[Scanner]] = {
        ModelFormat.PICKLE: [PickleScanner()],
        ModelFormat.JOBLIB: [PickleScanner()],
        ModelFormat.PYTORCH: [PyTorchScanner()],
        ModelFormat.PYTORCH_LEGACY: [PickleScanner()],
        ModelFormat.NUMPY: [NumpyScanner()],
        ModelFormat.KERAS_H5: [KerasH5Scanner()],
        ModelFormat.KERAS_V3: [KerasV3Scanner()],
        ModelFormat.TF_SAVEDMODEL: [TFSavedModelScanner()],
        ModelFormat.ONNX: [ONNXScanner()],
        ModelFormat.SAFETENSORS: [SafetensorsScanner()],
        ModelFormat.GGUF: [GGUFScanner()],
        ModelFormat.TFLITE: [TFLiteScanner()],
        ModelFormat.TFJS: [TFJSScanner()],
        ModelFormat.COREML: [CoreMLScanner()],
        ModelFormat.SKOPS: [SkopsScanner(), ArchiveScanner(depth=depth)],
        ModelFormat.PT2: [PyTorchScanner(), ArchiveScanner(depth=depth)],
        ModelFormat.EXECUTORCH: [ExecuTorchScanner()],
        ModelFormat.PADDLE: [PaddleScanner()],
        ModelFormat.PMML: [PMMLScanner()],
        ModelFormat.PYTHON_SOURCE: [PythonSourceScanner()],
        ModelFormat.HF_CONFIG: [HFConfigScanner()],
        # Data-only or opaque formats: identified for policy allowlists;
        # the format-agnostic exfil scan below still covers them.
        ModelFormat.GGML: [],
        ModelFormat.FLAX_MSGPACK: [],
        ModelFormat.MXNET: [],
        ModelFormat.OPENVINO: [],
        ModelFormat.GBM_NATIVE: [],
        ModelFormat.ARCHIVE: [ArchiveScanner(depth=depth)],
        ModelFormat.UNKNOWN: [],
    }
    scanners = table.get(fmt, [])
    scanners.append(ExfilScanner())
    return scanners


def scan_file(path: Path, depth: int = 0) -> tuple[ModelFormat, list[Finding]]:
    fmt = detect_format(path)
    findings: list[Finding] = []
    for scanner in scanners_for(fmt, depth=depth):
        try:
            for f in scanner.scan(path):
                f.file = f.file or str(path)
                findings.append(f)
        except Exception as exc:  # a scanner crash must not kill the scan
            findings.append(Finding(
                rule_id="SCANNER_ERROR",
                severity=Severity.LOW,
                title=f"Scanner `{scanner.name}` failed on this file",
                detail=str(exc),
                file=str(path),
                scanner=scanner.name,
            ))
    return fmt, findings


def scan_bytes_as_file(data: bytes, name: str, depth: int = 0) -> list[Finding]:
    """Scan an in-memory blob (archive member) by staging it to a temp file."""
    suffix = Path(name).suffix or ".bin"
    with tempfile.NamedTemporaryFile(suffix=suffix, delete=True) as tmp:
        tmp.write(data)
        tmp.flush()
        _, findings = scan_file(Path(tmp.name), depth=depth)
    return findings
