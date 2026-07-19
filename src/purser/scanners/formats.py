"""Format-specific scanners: PyTorch, Keras, TensorFlow, ONNX, safetensors,
GGUF, and NumPy.

Each scanner works statically — nothing is deserialized with the target
framework. Optional deps (h5py) are used when present; otherwise a
byte-level heuristic keeps detection working in minimal deployments.
"""

from __future__ import annotations

import json
import re
import struct
import zipfile
from pathlib import Path

from purser.core.findings import Finding, Severity
from purser.scanners.base import Scanner
from purser.scanners.pickle_scanner import PickleScanner


def _path_escapes(value: str) -> bool:
    """True if a path reference points outside its containing directory."""
    if not value:
        return False
    if "://" in value:                              # remote URL
        return True
    if value.startswith("/") or value.startswith("\\"):  # POSIX absolute / UNC
        return True
    if re.match(r"^[A-Za-z]:[\\/]", value):         # Windows drive path
        return True
    parts = value.replace("\\", "/").split("/")
    return ".." in parts                            # parent traversal


class PyTorchScanner(Scanner):
    """Zip-based torch checkpoints: scan every embedded pickle."""

    name = "pytorch"

    def scan(self, path: Path) -> list[Finding]:
        findings: list[Finding] = []
        pickle_scanner = PickleScanner()
        try:
            with zipfile.ZipFile(path) as zf:
                pickle_members = [n for n in zf.namelist() if n.endswith((".pkl", "data.pkl"))]
                if not pickle_members:
                    findings.append(self.finding(
                        "PYTORCH_NO_PICKLE", Severity.INFO,
                        "Zip checkpoint contains no pickle payload",
                    ))
                for member in pickle_members:
                    data = zf.read(member)
                    for f in pickle_scanner.scan_bytes(data, source=member):
                        f.detail = f"[{member}] {f.detail}"
                        f.evidence["member"] = member
                        findings.append(f)
                # torch >= 2.1 can embed arbitrary python source via
                # torch.package / torchscript — flag any .py members
                for member in zf.namelist():
                    if member.endswith(".py"):
                        findings.append(self.finding(
                            "PYTORCH_EMBEDDED_SOURCE", Severity.HIGH,
                            f"Checkpoint embeds Python source `{member}`",
                            "torch.package archives execute embedded modules on "
                            "import; review this code before loading.",
                            tags=["code-execution"], evidence={"member": member},
                        ))
        except zipfile.BadZipFile:
            # Legacy (pre-1.6) torch serialization: raw concatenated pickles.
            findings.extend(pickle_scanner.scan(path))
        return findings


class KerasH5Scanner(Scanner):
    """HDF5 Keras models: Lambda layers carry marshaled Python bytecode."""

    name = "keras_h5"

    def scan(self, path: Path) -> list[Finding]:
        config = self._read_model_config(path)
        if config is not None:
            return self._scan_config_json(config)
        # Fallback: byte-level heuristic when h5py is unavailable.
        data = path.read_bytes()
        findings: list[Finding] = []
        if b'"class_name": "Lambda"' in data or b'"class_name":"Lambda"' in data:
            findings.append(self.finding(
                "KERAS_LAMBDA_LAYER", Severity.CRITICAL,
                "Keras Lambda layer detected (arbitrary code on load)",
                "Lambda layers deserialize marshaled Python bytecode and execute "
                "it when the model is loaded or run.",
                tags=["code-execution"],
            ))
        return findings

    def _read_model_config(self, path: Path) -> str | None:
        try:
            import h5py  # type: ignore
        except ImportError:
            return None
        try:
            with h5py.File(path, "r") as f:
                cfg = f.attrs.get("model_config")
                if cfg is None:
                    return None
                return cfg.decode() if isinstance(cfg, bytes) else str(cfg)
        except Exception:
            return None

    def _scan_config_json(self, config: str) -> list[Finding]:
        findings: list[Finding] = []
        for m in re.finditer(r'"class_name":\s*"(Lambda|TFOpLambda)"', config):
            findings.append(self.finding(
                "KERAS_LAMBDA_LAYER", Severity.CRITICAL,
                f"Keras {m.group(1)} layer detected (arbitrary code on load)",
                "Lambda layers deserialize marshaled Python bytecode and execute "
                "it when the model is loaded or run.",
                tags=["code-execution"],
            ))
        return findings


class KerasV3Scanner(Scanner):
    """.keras (zip) archives: inspect config.json for Lambda layers."""

    name = "keras_v3"

    def scan(self, path: Path) -> list[Finding]:
        findings: list[Finding] = []
        try:
            with zipfile.ZipFile(path) as zf:
                for member in zf.namelist():
                    if member.endswith("config.json"):
                        config = zf.read(member).decode("utf-8", "replace")
                        for f in KerasH5Scanner()._scan_config_json(config):
                            f.scanner = self.name
                            f.evidence["member"] = member
                            findings.append(f)
        except zipfile.BadZipFile:
            findings.append(self.finding(
                "KERAS_V3_MALFORMED", Severity.MEDIUM,
                ".keras file is not a valid zip archive",
                tags=["evasion"],
            ))
        return findings


class TFSavedModelScanner(Scanner):
    """SavedModel protobufs: flag dangerous graph ops without parsing protobuf."""

    name = "tf_savedmodel"

    DANGEROUS_OPS: dict[bytes, tuple[Severity, str]] = {
        b"PyFunc": (Severity.CRITICAL, "executes arbitrary Python at inference time"),
        b"PyFuncStateless": (Severity.CRITICAL, "executes arbitrary Python at inference time"),
        b"EagerPyFunc": (Severity.CRITICAL, "executes arbitrary Python at inference time"),
        b"ReadFile": (Severity.HIGH, "reads arbitrary files from the host"),
        b"WriteFile": (Severity.HIGH, "writes arbitrary files on the host"),
        b"MatchingFiles": (Severity.MEDIUM, "enumerates host filesystem paths"),
        b"DecodeJpeg": (Severity.INFO, "legitimate but expands attack surface"),
    }

    def scan(self, path: Path) -> list[Finding]:
        data = path.read_bytes()
        findings: list[Finding] = []
        for op, (severity, why) in self.DANGEROUS_OPS.items():
            if severity is Severity.INFO:
                continue
            if op in data:
                findings.append(self.finding(
                    "TF_DANGEROUS_OP", severity,
                    f"TensorFlow graph references `{op.decode()}` op",
                    f"This graph op {why}.",
                    tags=["code-execution" if b"PyFunc" in op else "file-access"],
                    evidence={"op": op.decode()},
                ))
        return findings


class ONNXScanner(Scanner):
    """ONNX graphs: custom-domain python ops and external-data path traversal."""

    name = "onnx"

    def scan(self, path: Path) -> list[Finding]:
        data = path.read_bytes()
        findings: list[Finding] = []
        for marker, sev, why in (
            (b"ai.onnx.contrib", Severity.HIGH, "custom python operator domain"),
            (b"com.microsoft.extensions", Severity.MEDIUM, "extension operator domain"),
            (b"PyOp", Severity.HIGH, "python operator"),
        ):
            if marker in data:
                findings.append(self.finding(
                    "ONNX_CUSTOM_OP", sev,
                    f"ONNX model uses {why} `{marker.decode()}`",
                    "Custom operators require out-of-graph code and can execute "
                    "arbitrary Python via onnxruntime-extensions.",
                    tags=["code-execution"], evidence={"marker": marker.decode()},
                ))
        # External-data references are stored as protobuf StringStringEntryProto
        # with key "location". Anchor on that key (encoded as `location` +
        # field-2 tag 0x12 + a 1-byte length) so we inspect actual path values,
        # not ONNX node names — which are legitimately slash-prefixed and would
        # otherwise flood false positives. Flag values that escape the model
        # directory: parent traversal, absolute (POSIX/Windows/UNC), or remote.
        seen: set[str] = set()
        for m in re.finditer(rb"location\x12([\x01-\x7f])", data):
            length = m.group(1)[0]
            value = data[m.end():m.end() + length].decode("ascii", "replace")
            if not _path_escapes(value) or value in seen:
                continue
            seen.add(value)
            findings.append(self.finding(
                "ONNX_EXTERNAL_DATA_TRAVERSAL", Severity.HIGH,
                "ONNX external-data reference escapes the model directory",
                f"Reference `{value[:120]}` is an absolute, parent-relative, or "
                "remote path; loading can read files outside the model directory.",
                tags=["file-access"], evidence={"path": value[:200]},
            ))
            if len(seen) >= 10:  # cap noise on adversarial inputs
                break
        return findings


class SafetensorsScanner(Scanner):
    """Safetensors is a safe format by design — validate structure to catch
    spoofed/malformed headers used against parser bugs."""

    name = "safetensors"

    MAX_HEADER = 100 * 1024 * 1024

    def scan(self, path: Path) -> list[Finding]:
        findings: list[Finding] = []
        size = path.stat().st_size
        with open(path, "rb") as fh:
            head = fh.read(8)
            if len(head) < 8:
                return [self._malformed("file too small for safetensors header")]
            (header_len,) = struct.unpack("<Q", head)
            if header_len > self.MAX_HEADER or header_len > size - 8:
                return [self._malformed(f"header length {header_len} exceeds sane bounds")]
            try:
                header = json.loads(fh.read(header_len))
            except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                return [self._malformed(f"header is not valid JSON: {exc}")]
        if not isinstance(header, dict):
            return [self._malformed("header is not a JSON object")]
        for key, val in header.items():
            if key == "__metadata__":
                continue
            if not isinstance(val, dict) or "data_offsets" not in val:
                findings.append(self._malformed(f"tensor entry `{key[:80]}` missing data_offsets"))
                break
        return findings

    def _malformed(self, why: str) -> Finding:
        return self.finding(
            "SAFETENSORS_MALFORMED", Severity.MEDIUM,
            "Malformed safetensors file",
            f"{why}. Malformed headers are used to exploit parser bugs or to "
            "disguise other formats as safetensors.",
            tags=["evasion"],
        )


class GGUFScanner(Scanner):
    """GGUF models: chat templates are Jinja and can carry template-injection
    payloads that reach Python via SSTI when rendered by permissive engines."""

    name = "gguf"

    SSTI_PATTERNS: list[tuple[re.Pattern[bytes], Severity, str]] = [
        (re.compile(rb"__class__|__mro__|__subclasses__|__globals__|__builtins__"),
         Severity.CRITICAL, "Python object-graph escape in chat template"),
        (re.compile(rb"\bos\.(?:system|popen|environ)\b"), Severity.CRITICAL,
         "OS access attempt in chat template"),
        (re.compile(rb"\{\{[^}]{0,200}\b(?:eval|exec|import)\b"), Severity.HIGH,
         "dynamic code construct inside template expression"),
    ]

    def scan(self, path: Path) -> list[Finding]:
        with open(path, "rb") as fh:
            head = fh.read(24)
            if not head.startswith(b"GGUF"):
                return [self.finding(
                    "GGUF_BAD_MAGIC", Severity.MEDIUM,
                    "File has .gguf extension but wrong magic bytes",
                    tags=["evasion"],
                )]
            # Metadata lives near the start; read a bounded window.
            fh.seek(0)
            window = fh.read(16 * 1024 * 1024)
        findings: list[Finding] = []
        if b"tokenizer.chat_template" in window:
            for pattern, sev, why in self.SSTI_PATTERNS:
                m = pattern.search(window)
                if m:
                    findings.append(self.finding(
                        "GGUF_TEMPLATE_INJECTION", sev,
                        f"GGUF chat template contains {why}",
                        "Chat templates are rendered as Jinja by many runtimes; "
                        "sandbox-escape constructs indicate a template-injection "
                        "payload.",
                        tags=["code-execution", "template-injection"],
                        evidence={"match": m.group().decode("ascii", "replace")[:160]},
                    ))
        return findings


class NumpyScanner(Scanner):
    """.npy/.npz: object arrays embed pickles — scan them."""

    name = "numpy"

    def scan(self, path: Path) -> list[Finding]:
        data = path.read_bytes()
        if data.startswith(b"PK\x03\x04"):  # .npz
            findings: list[Finding] = []
            try:
                with zipfile.ZipFile(path) as zf:
                    for member in zf.namelist():
                        findings.extend(self._scan_npy(zf.read(member), member))
            except zipfile.BadZipFile:
                pass
            return findings
        return self._scan_npy(data, path.name)

    def _scan_npy(self, data: bytes, name: str) -> list[Finding]:
        if not data.startswith(b"\x93NUMPY"):
            return []
        try:
            header_len = struct.unpack("<H", data[8:10])[0]
            header = data[10:10 + header_len].decode("latin1")
        except Exception:
            return [self.finding(
                "NUMPY_MALFORMED", Severity.MEDIUM,
                f"Malformed .npy header in {name}", tags=["evasion"],
            )]
        findings: list[Finding] = []
        if re.search(r"'descr':\s*'?\|?O", header):
            findings.append(self.finding(
                "NUMPY_OBJECT_ARRAY", Severity.HIGH,
                f"NumPy object array in {name} (embedded pickle)",
                "Object-dtype arrays require allow_pickle=True and embed a "
                "pickle stream that executes on load.",
                tags=["nested-payload"], evidence={"member": name},
            ))
            payload = data[10 + header_len:]
            for f in PickleScanner().scan_bytes(payload, source=name):
                f.evidence["member"] = name
                findings.append(f)
        return findings
