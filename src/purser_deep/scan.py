"""Deep-scan dispatch: run the applicable deep analyzers over a file."""

from __future__ import annotations

from pathlib import Path

from purser.core.findings import Finding
from purser.core.formats import ModelFormat, detect_format
from purser_deep.analyzers import gadget, weights

# Formats each deep analyzer is worth running on.
_PICKLE_FORMATS = {
    ModelFormat.PICKLE, ModelFormat.PYTORCH, ModelFormat.PYTORCH_LEGACY,
    ModelFormat.JOBLIB, ModelFormat.NUMPY, ModelFormat.PADDLE,
}
_WEIGHT_FORMATS = {ModelFormat.SAFETENSORS, ModelFormat.NUMPY}


def deep_scan_file(path: Path) -> list[Finding]:
    """Run deep analyzers appropriate to the file's format."""
    path = Path(path)
    fmt = detect_format(path)
    findings: list[Finding] = []
    if fmt in _PICKLE_FORMATS:
        try:
            findings.extend(gadget.analyze_file(path))
        except Exception as exc:  # analyzer must never crash the caller
            findings.append(Finding("DEEP_ANALYZER_ERROR", _low(),
                                    "deep.gadget failed", str(exc), scanner="deep.gadget"))
    if fmt in _WEIGHT_FORMATS:
        try:
            findings.extend(weights.analyze_file(path))
        except Exception as exc:
            findings.append(Finding("DEEP_ANALYZER_ERROR", _low(),
                                    "deep.weights failed", str(exc), scanner="deep.weights"))
    for f in findings:
        f.file = f.file or str(path)
    return findings


def _low():
    from purser.core.findings import Severity
    return Severity.LOW
