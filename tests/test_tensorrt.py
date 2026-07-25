"""TensorRT engines are identified as a format and get the exfil scan.

A serialized TensorRT engine (`.engine`/`.plan`/`.trt`) is opaque builder
output with no portable, safely-parseable graph — like OpenVINO/MXNet it is a
data-only format: we identify it (so policy can allow/deny it and reports name
it) and run the format-agnostic exfil scan over its bytes, but there is no
structural scanner.
"""

from purser.core.dispatch import scan_file
from purser.core.formats import ModelFormat, detect_format
from purser.core.policy import Policy
from purser.core.scanner import scan_target

# A slack webhook is a canonical exfil indicator the byte scanner extracts.
_WEBHOOK = b"https://hooks.slack.com/services/T00000000/B00000000/" + b"X" * 24


def _engine(path, payload=b""):
    # Opaque binary blob standing in for engine bytes; not a real engine.
    path.write_bytes(b"\x00\x01\x02\x03\xde\xad\xbe\xef" * 8 + payload)
    return path


def test_tensorrt_extensions_identified(tmp_path):
    for name in ("model.engine", "model.plan", "model.trt"):
        p = _engine(tmp_path / name)
        assert detect_format(p) is ModelFormat.TENSORRT, name


def test_tensorrt_runs_exfil_scan(tmp_path):
    fmt, findings = scan_file(_engine(tmp_path / "model.engine", _WEBHOOK))
    assert fmt is ModelFormat.TENSORRT
    assert any(f.rule_id == "EXFIL_WEBHOOK" for f in findings), findings


def test_tensorrt_benign_engine_passes(tmp_path):
    report = scan_target(_engine(tmp_path / "clean.engine"))
    assert report.verdict.name == "PASS"


def test_tensorrt_format_policy_blocklist(tmp_path):
    p = _engine(tmp_path / "clean.plan")  # benign, blocked purely on format
    policy = Policy.from_dict({
        "name": "no-trt",
        "formats": {"mode": "blocklist", "list": ["tensorrt"]},
    })
    report = scan_target(p, policy=policy)
    assert report.verdict.name == "BLOCKED"
    assert any(f.rule_id == "POLICY_FORMAT_BLOCKED" for f in report.policy_findings)
