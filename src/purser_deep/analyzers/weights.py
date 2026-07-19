"""Weight tampering / steganography analyzer.

Reads tensor data **statically** from safetensors and NumPy files (parsing the
header + raw bytes — never loading the model into a framework) and looks for:

  * **Steganography** — data hidden in the least-significant byte of float
    tensors. That byte is mantissa noise to the model but a perfect place to
    smuggle a payload. We extract the low-byte plane and run it through the
    core exfiltration engine; readable URLs/secrets/code/base64 there are a
    strong signal of hidden data (random weights don't produce them).
  * **Non-finite weights** — an unusual fraction of NaN/Inf, a sign of
    corruption or tampering.
  * **Malformed tensors** — declared shape/dtype don't match the data length.

Honest limit: this does NOT detect *trained* backdoors (learned triggers /
poisoning) — that needs behavioral model evaluation, which stays out of scope.
"""

from __future__ import annotations

import json
import math
import struct
from pathlib import Path

from purser.core.findings import Finding, Severity
from purser.scanners.exfil import ExfilScanner
from purser.core.env import env_get

# bytes of tensor data to inspect per file (bounds time/memory)
MAX_TENSOR_BYTES = int(env_get("DEEP_MAX_MB", "256")) * 1024 * 1024
MAX_LSB_BYTES = 8 * 1024 * 1024        # cap the extracted low-byte plane
MAX_FINITE_SAMPLES = 200_000           # elements sampled for the NaN/Inf check

# dtype -> (element size in bytes, float-struct-code or None)
_ST_DTYPES = {
    "F64": (8, "d"), "F32": (4, "f"), "F16": (2, "e"), "BF16": (2, None),
    "I64": (8, None), "I32": (4, None), "I16": (2, None),
    "I8": (1, None), "U8": (1, None), "BOOL": (1, None),
    "F8_E4M3": (1, None), "F8_E5M2": (1, None),
}

_STEGO_RULES = {
    "EXFIL_URL", "EXFIL_SECRET", "EXFIL_WEBHOOK", "EXFIL_IP_ENDPOINT",
    "EXFIL_CODE_INDICATOR", "EXFIL_ENCODED_PAYLOAD",
}


def _low_byte_plane(fh, start: int, end: int, elem_size: int) -> bytes:
    """Extract the little-endian low byte of each element in [start, end)."""
    if elem_size < 2:
        return b""  # 1-byte dtypes have no hidden low-bit plane
    length = min(end - start, MAX_TENSOR_BYTES)
    fh.seek(start)
    raw = fh.read(length)
    plane = raw[::elem_size]  # byte 0 of each little-endian element
    return plane[:MAX_LSB_BYTES]


def _nonfinite_fraction(fh, start: int, end: int, elem_size: int, code: str) -> float:
    if code is None:
        return 0.0
    n = min((end - start) // elem_size, MAX_FINITE_SAMPLES)
    if n <= 0:
        return 0.0
    fh.seek(start)
    raw = fh.read(n * elem_size)
    bad = 0
    try:
        for v in struct.iter_unpack("<" + code, raw[: n * elem_size]):
            x = v[0]
            if math.isnan(x) or math.isinf(x):
                bad += 1
    except struct.error:
        return 0.0
    return bad / n if n else 0.0


def _stego_findings(plane: bytes, where: str) -> list[Finding]:
    if len(plane) < 16:
        return []
    hits = [f for f in ExfilScanner().scan_bytes(plane) if f.rule_id in _STEGO_RULES]
    if not hits:
        return []
    kinds = sorted({f.rule_id for f in hits})
    return [Finding(
        rule_id="DEEP_WEIGHTS_STEGO", severity=Severity.HIGH,
        title=f"Hidden data in tensor low-bit plane ({where})",
        detail=("The least-significant bytes of this tensor decode to "
                f"exfiltration-like content ({kinds}). Trained weights do not "
                "produce readable URLs/secrets/code in their low bits — this "
                "indicates data steganographically hidden in the model."),
        scanner="deep.weights", tags=["steganography", "exfiltration"],
        evidence={"tensor": where, "signals": kinds},
    )]


def _analyze_safetensors(path: Path) -> list[Finding]:
    findings: list[Finding] = []
    with open(path, "rb") as fh:
        head = fh.read(8)
        if len(head) < 8:
            return []
        (hlen,) = struct.unpack("<Q", head)
        if hlen == 0 or hlen > 100 * 1024 * 1024:
            return []
        try:
            header = json.loads(fh.read(hlen))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return []
        data_base = 8 + hlen
        budget = MAX_TENSOR_BYTES
        for name, meta in header.items():
            if name == "__metadata__" or not isinstance(meta, dict):
                continue
            dtype = str(meta.get("dtype", ""))
            offs = meta.get("data_offsets")
            shape = meta.get("shape") or []
            if not (isinstance(offs, list) and len(offs) == 2):
                continue
            elem_size, code = _ST_DTYPES.get(dtype, (0, None))
            start, end = data_base + offs[0], data_base + offs[1]
            nbytes = end - start
            # malformed: declared shape*dtype must match the byte span
            if elem_size:
                expected = elem_size
                for d in shape:
                    expected *= int(d)
                if shape and expected != nbytes:
                    findings.append(Finding(
                        rule_id="DEEP_WEIGHTS_MALFORMED", severity=Severity.MEDIUM,
                        title=f"Tensor `{name[:60]}` size mismatch",
                        detail=(f"shape×dtype = {expected} bytes but the data span "
                                f"is {nbytes} bytes — malformed or hidden trailing data."),
                        scanner="deep.weights", tags=["evasion"],
                        evidence={"tensor": name[:80], "expected": expected, "actual": nbytes},
                    ))
            if budget <= 0:
                continue
            budget -= min(nbytes, MAX_TENSOR_BYTES)
            frac = _nonfinite_fraction(fh, start, end, elem_size, code) if code else 0.0
            if frac > 0.01:
                findings.append(Finding(
                    rule_id="DEEP_WEIGHTS_NONFINITE", severity=Severity.MEDIUM,
                    title=f"Tensor `{name[:60]}` has many non-finite values",
                    detail=f"{frac:.1%} of sampled values are NaN/Inf — corruption or tampering.",
                    scanner="deep.weights", tags=["tampering"],
                    evidence={"tensor": name[:80], "nonfinite_fraction": round(frac, 4)},
                ))
            findings.extend(_stego_findings(_low_byte_plane(fh, start, end, elem_size), name[:60]))
    return findings


def _analyze_npy(path: Path) -> list[Finding]:
    with open(path, "rb") as fh:
        if fh.read(6) != b"\x93NUMPY":
            return []
        fh.read(2)  # version
        (hlen,) = struct.unpack("<H", fh.read(2))
        header = fh.read(hlen).decode("latin1")
        data_start = 10 + hlen
    import re
    m = re.search(r"'descr':\s*'([<>|=]?)(\w)(\d+)'", header)
    if not m:
        return []
    _endian, kind, size = m.group(1), m.group(2), int(m.group(3))
    code = {("f", 8): "d", ("f", 4): "f", ("f", 2): "e"}.get((kind, size))
    findings: list[Finding] = []
    size_on_disk = Path(path).stat().st_size
    with open(path, "rb") as fh:
        start, end = data_start, size_on_disk
        if code:
            frac = _nonfinite_fraction(fh, start, end, size, code)
            if frac > 0.01:
                findings.append(Finding(
                    rule_id="DEEP_WEIGHTS_NONFINITE", severity=Severity.MEDIUM,
                    title="NumPy array has many non-finite values",
                    detail=f"{frac:.1%} of sampled values are NaN/Inf.",
                    scanner="deep.weights", tags=["tampering"],
                    evidence={"nonfinite_fraction": round(frac, 4)},
                ))
        findings.extend(_stego_findings(_low_byte_plane(fh, start, end, size), Path(path).name))
    return findings


def analyze_file(path: Path) -> list[Finding]:
    path = Path(path)
    try:
        with open(path, "rb") as fh:
            head = fh.read(8)
        if head[:6] == b"\x93NUMPY":
            return _analyze_npy(path)
        # safetensors: 8-byte header length then JSON starting with '{'
        if len(head) == 8:
            (hlen,) = struct.unpack("<Q", head)
            if 2 <= hlen <= 100 * 1024 * 1024:
                with open(path, "rb") as fh:
                    fh.seek(8)
                    if fh.read(1) == b"{":
                        return _analyze_safetensors(path)
    except OSError:
        return []
    return []
