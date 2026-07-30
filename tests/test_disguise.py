"""Extension/name disguise must not evade detection.

A payload keeps its teeth even when renamed: magic bytes win over a spoofed
extension, and a directory walk sniffs files hidden under doc/config names.
Payloads are pickle byte streams that only *reference* dangerous callables; the
suite never unpickles anything.
"""
import pickle
from pathlib import Path

from purser.core.dispatch import scan_file
from purser.core.findings import Severity
from purser.core.formats import ModelFormat, detect_format
from purser.core.scanner import iter_scannable
from tests.conftest import EvilOsSystem


def _evil(path: Path) -> Path:
    path.write_bytes(pickle.dumps(EvilOsSystem()))  # protocol 2+ -> starts \x80
    return path


def test_pickle_disguised_as_structured_ext_routes_to_pickle(tmp_path):
    # A protocol-2+ pickle renamed to a structured binary format must be
    # recognized as pickle (magic beats extension) — not waved through.
    for name in ("model.onnx", "weights.pb", "m.pte", "x.mlmodel", "y.pdmodel"):
        assert detect_format(_evil(tmp_path / name)) is ModelFormat.PICKLE, name


def test_proto0_ascii_pickle_disguised_as_onnx_routes_to_pickle(tmp_path):
    # A *protocol-0* (ASCII) pickle has no proto-2 magic, but under a structured
    # extension a genops trial-parse still unmasks it — and it keeps its teeth.
    p = tmp_path / "ascii.onnx"
    p.write_bytes(pickle.dumps(EvilOsSystem(), protocol=0))
    assert detect_format(p) is ModelFormat.PICKLE
    _, findings = scan_file(p)
    assert any(
        f.rule_id == "PICKLE_DANGEROUS_IMPORT" and f.severity >= Severity.HIGH
        for f in findings
    )


def test_real_protobuf_onnx_not_misrouted_to_pickle(tmp_path):
    # FP guard: a genuine protobuf model (ONNX/TF begin with field tags
    # 0x08/0x0a) must stay its own format, never be trial-parsed as a pickle.
    for name in ("real.onnx", "graph.pb"):
        p = tmp_path / name
        p.write_bytes(b"\x08\x07\x12\x0cpytorch-jit\x1a\x02" + b"\x00" * 64)
        fmt = detect_format(p)
        assert fmt is not ModelFormat.PICKLE, f"{name} -> {fmt}"


def test_disguised_pickle_still_flags_dangerous_import(tmp_path):
    _, findings = scan_file(_evil(tmp_path / "embeddings.onnx"))
    assert any(
        f.rule_id == "PICKLE_DANGEROUS_IMPORT" and f.severity >= Severity.HIGH
        for f in findings
    )


def test_directory_walk_sniffs_disguised_doc(tmp_path):
    _evil(tmp_path / "README.md")                       # payload under a doc name
    (tmp_path / "notes.txt").write_text("just documentation, nothing here")
    scanned = {p.name for p in iter_scannable(tmp_path)}
    assert "README.md" in scanned                        # sniffed despite .md
    assert "notes.txt" not in scanned                    # genuine text still skipped


def test_real_safetensors_not_misrouted_to_pickle(safetensors_valid):
    # Guard against false positives: a real safetensors header must never be
    # mistaken for a disguised pickle.
    assert detect_format(safetensors_valid) is ModelFormat.SAFETENSORS
