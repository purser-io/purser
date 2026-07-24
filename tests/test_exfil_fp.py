"""Regression tests for exfil false positives on binary/quantized weight data.

The validation benchmark flagged benign quantized ONNX models (e.g. Xenova/gpt2)
because chance `hf_...`-shaped runs and hex runs in the weights matched the
secret / encoded-payload heuristics. Real credentials live in short, structured
strings, so those heuristics are gated on entropy.
"""
import binascii

from purser.scanners.exfil import ExfilScanner, _is_weighty


def _scan(data: bytes):
    return ExfilScanner().scan_bytes(data)


# a diverse alphabet -> a high-entropy printable run like quantized weights emit
_ALPHA = "aB3kZ9qX7mW2pL5vT8nR4cD6yH1sJ0uK5eG7wE2rT9yU4iO1pA6sD3fG8hJ"


def test_secret_not_flagged_in_high_entropy_weight_run():
    token = _ALPHA[:34]                       # hf_ + 34 (matches the pattern)
    run = "hf_" + token + "/" + (_ALPHA + _ALPHA)[:40]   # >=64, no space, hi-entropy
    assert _is_weighty(run)
    findings = _scan(b"\x00\x00" + run.encode() + b"\x00\x00")
    assert not [f for f in findings if f.rule_id == "EXFIL_SECRET"]


def test_real_secret_still_flagged_in_structured_string():
    data = b"\x00\x00config: aws_key = AKIAIOSFODNN7EXAMPLE  # prod\x00\x00"
    findings = _scan(data)
    assert any(f.rule_id == "EXFIL_SECRET" for f in findings)


def test_overlong_hf_token_shape_not_flagged():
    # hf_ + 39 alnum in a short printable island (not "weighty") — a chance run
    # in weights, like the one that hard-failed a benign quantized ONNX model.
    # The exact-length pattern must not treat it as a real token.
    run = "hf_" + (_ALPHA + _ALPHA)[:39]
    assert not _is_weighty(run)
    findings = _scan(b"\x00\x00" + run.encode() + b"\x00\x00")
    assert not [f for f in findings if f.rule_id == "EXFIL_SECRET"]


def test_encoded_payload_not_flagged_on_weight_noise():
    # hex/base64 runs in weights that decode to printable-but-meaningless bytes
    # (incl. low-entropy digit soup) must not raise the weak "readable" signal.
    for payload in (_ALPHA.encode(), b"0123401234012340123401234012340123401234"):
        blob = binascii.hexlify(payload)       # >=64 hex chars, decodes to printable
        findings = _scan(b"\x00\x00" + blob + b"\x00\x00")
        assert not [f for f in findings if f.rule_id == "EXFIL_ENCODED_PAYLOAD"]


def test_real_embedded_indicators_still_flagged():
    # the deliberate-payload case must survive: webhook + AWS key + shell idiom
    data = (b"\x00\x01" * 8 +
            b"https://hooks.slack.com/services/T0/B0/XXXXXXXXXXXXXXXXXXXXXXXX\x00" +
            b"AKIAIOSFODNN7EXAMPLE\x00" +
            b"os.system('curl evil')\x00")
    rules = {f.rule_id for f in _scan(data)}
    assert "EXFIL_WEBHOOK" in rules
    assert "EXFIL_SECRET" in rules
    assert "EXFIL_CODE_INDICATOR" in rules
