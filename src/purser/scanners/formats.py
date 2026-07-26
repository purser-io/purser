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


# Keras layer taxonomy for custom-layer detection (roadmap: per-format depth).
# Keras v3 configs carry a `module` per node — anything outside these namespaces
# is custom code that runs on load. Legacy H5 configs have no `module`, so we
# fall back to a builtin class-name allowlist.
_KERAS_SAFE_TOP_MODULES = frozenset({
    "keras", "tensorflow", "tf_keras", "keras_core", "keras_cv", "keras_nlp",
    "keras_hub", "tf",
    # widely-used, framework-trusted layer providers (loading them is expected)
    "transformers", "tensorflow_hub", "tensorflow_addons", "official", "tfa",
})
_KERAS_CONTAINER_CLASSES = frozenset({"Sequential", "Functional", "Model", "InputLayer"})
_KERAS_BUILTIN_LAYERS = frozenset({
    # core / dense / embedding
    "Dense", "Activation", "Embedding", "Masking", "Flatten", "Reshape", "Permute",
    "RepeatVector", "Identity", "Dropout", "SpatialDropout1D", "SpatialDropout2D",
    "SpatialDropout3D", "ActivityRegularization",
    # convolution
    "Conv1D", "Conv2D", "Conv3D", "Conv1DTranspose", "Conv2DTranspose", "Conv3DTranspose",
    "Convolution1D", "Convolution2D", "Convolution3D", "SeparableConv1D", "SeparableConv2D",
    "DepthwiseConv1D", "DepthwiseConv2D", "Cropping1D", "Cropping2D", "Cropping3D",
    "UpSampling1D", "UpSampling2D", "UpSampling3D", "ZeroPadding1D", "ZeroPadding2D",
    "ZeroPadding3D",
    # pooling
    "MaxPooling1D", "MaxPooling2D", "MaxPooling3D", "AveragePooling1D", "AveragePooling2D",
    "AveragePooling3D", "GlobalMaxPooling1D", "GlobalMaxPooling2D", "GlobalMaxPooling3D",
    "GlobalAveragePooling1D", "GlobalAveragePooling2D", "GlobalAveragePooling3D",
    "MaxPool1D", "MaxPool2D", "MaxPool3D", "AvgPool1D", "AvgPool2D", "AvgPool3D",
    "GlobalMaxPool1D", "GlobalMaxPool2D", "GlobalMaxPool3D", "GlobalAvgPool1D",
    "GlobalAvgPool2D", "GlobalAvgPool3D",
    # recurrent / attention / wrappers
    "LSTM", "GRU", "SimpleRNN", "RNN", "Bidirectional", "TimeDistributed", "ConvLSTM1D",
    "ConvLSTM2D", "ConvLSTM3D", "LSTMCell", "GRUCell", "SimpleRNNCell", "StackedRNNCells",
    "MultiHeadAttention", "Attention", "AdditiveAttention",
    # normalization
    "BatchNormalization", "LayerNormalization", "UnitNormalization", "GroupNormalization",
    # merging
    "Add", "Subtract", "Multiply", "Average", "Maximum", "Minimum", "Concatenate", "Dot",
    # activations
    "ReLU", "LeakyReLU", "PReLU", "ELU", "ThresholdedReLU", "Softmax",
    # regularization / noise
    "GaussianDropout", "GaussianNoise", "AlphaDropout",
    # preprocessing / normalization (keras 3)
    "Normalization", "Discretization", "CategoryEncoding", "Hashing", "StringLookup",
    "IntegerLookup", "TextVectorization", "Rescaling", "Resizing", "CenterCrop",
    "RandomFlip", "RandomRotation", "RandomZoom", "RandomTranslation", "RandomCrop",
    "RandomContrast", "RandomBrightness", "RandomHeight", "RandomWidth",
})


def _keras_module_safe(module: str | None) -> bool:
    if not module:
        return False
    return module.split(".", 1)[0] in _KERAS_SAFE_TOP_MODULES


def _keras_is_custom(class_name: str, module: str | None) -> bool:
    """True if a layer requires non-builtin code to deserialize."""
    if class_name in _KERAS_CONTAINER_CLASSES:
        return False
    if module is not None:                       # keras v3: trust the module field
        return not _keras_module_safe(module)
    return class_name not in _KERAS_BUILTIN_LAYERS  # legacy H5: builtin allowlist


def _keras_walk(doc, depth: int = 0, budget: list[int] | None = None):
    """Yield (class_name, module|None, registered_name) for every object node."""
    if budget is None:
        budget = [5000]
    if depth > 100 or budget[0] <= 0:
        return
    if isinstance(doc, dict):
        cn = doc.get("class_name")
        if isinstance(cn, str):
            budget[0] -= 1
            mod = doc.get("module")
            yield cn, (mod if isinstance(mod, str) else None), doc.get("registered_name")
        for v in doc.values():
            yield from _keras_walk(v, depth + 1, budget)
    elif isinstance(doc, list):
        for v in doc:
            yield from _keras_walk(v, depth + 1, budget)


class KerasH5Scanner(Scanner):
    """HDF5 Keras models: Lambda layers carry marshaled Python bytecode; custom
    (non-builtin) layers require external code to deserialize."""

    name = "keras_h5"

    def scan(self, path: Path) -> list[Finding]:
        config = self._read_model_config(path)
        if config is not None:
            return self._scan_config_json(config)
        # h5py unavailable: sweep the embedded config bytes.
        return self._scan_config_bytes(path.read_bytes())

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

    def _lambda_finding(self, cls: str) -> Finding:
        return self.finding(
            "KERAS_LAMBDA_LAYER", Severity.CRITICAL,
            f"Keras {cls} layer detected (arbitrary code on load)",
            "Lambda layers deserialize marshaled Python bytecode and execute it "
            "when the model is loaded or run.",
            tags=["code-execution"])

    def _scan_config_json(self, config: str) -> list[Finding]:
        findings: list[Finding] = []
        try:
            doc = json.loads(config)
        except (json.JSONDecodeError, ValueError):
            # Unparseable config — fall back to the Lambda substring heuristic.
            for m in re.finditer(r'"class_name":\s*"(Lambda|TFOpLambda)"', config):
                findings.append(self._lambda_finding(m.group(1)))
            return findings

        seen: set[tuple[str, str]] = set()
        for cls, module, _registered in _keras_walk(doc):
            if len(findings) >= 200:
                break
            if cls in ("Lambda", "TFOpLambda"):
                if ("lambda", "") in seen:
                    continue
                seen.add(("lambda", ""))
                findings.append(self._lambda_finding(cls))
            elif _keras_is_custom(cls, module):
                key = (cls, module or "")
                if key in seen:
                    continue
                seen.add(key)
                findings.append(self._custom_finding(cls, module))
        return findings

    def _custom_finding(self, cls: str, module: str | None) -> Finding:
        where = f" from module `{module}`" if module else ""
        return self.finding(
            "KERAS_CUSTOM_LAYER", Severity.MEDIUM,
            f"Custom Keras layer `{cls}`{where} — external code runs on load",
            "Deserializing a non-builtin Keras layer imports and instantiates its "
            "class, running that code when the model is loaded (similar to "
            "trust_remote_code). Verify the providing package is trusted.",
            tags=["code-execution", "provenance"],
            evidence={"class_name": cls, "module": module or ""})

    def _scan_config_bytes(self, data: bytes) -> list[Finding]:
        """h5py-less fallback: the model_config JSON is embedded in the HDF5
        bytes as a string, so sweep it for layer class names and classify with
        the legacy (module-less) builtin allowlist."""
        text = data.decode("latin1", "replace")
        findings: list[Finding] = []
        seen: set[str] = set()
        for m in re.finditer(r'"class_name":\s*"([A-Za-z0-9_.]{1,80})"', text):
            cls = m.group(1)
            if len(findings) >= 200:
                break
            if cls in ("Lambda", "TFOpLambda"):
                if "\x00lambda" in seen:
                    continue
                seen.add("\x00lambda")
                findings.append(self._lambda_finding(cls))
            elif _keras_is_custom(cls, None):
                if cls in seen:
                    continue
                seen.add(cls)
                findings.append(self._custom_finding(cls, None))
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


class OpenVINOScanner(Scanner):
    """OpenVINO IR (.xml graph): XXE-safe structural parse. Flags DOCTYPE/entity
    declarations (XXE / entity-expansion) and references to external shared
    libraries or host paths (custom-extension code-load / call-home vectors).
    Weights live in the sibling `.bin`, which the exfil engine scans."""

    name = "openvino"
    _MAX = 64 * 1024 * 1024
    _LIB_RE = re.compile(r"\.(?:so|dll|dylib)(?:\.\d+)*$", re.IGNORECASE)

    def scan(self, path: Path) -> list[Finding]:
        findings: list[Finding] = []
        try:
            text = path.read_bytes()[: self._MAX].decode("utf-8", "replace")
        except OSError:
            return findings

        # A DOCTYPE/entity in an IR is never legitimate and is the XXE / billion-
        # laughs vector — flag and refuse to parse further.
        if re.search(r"<!DOCTYPE|<!ENTITY", text):
            return [self.finding(
                "OPENVINO_XXE", Severity.HIGH,
                "OpenVINO IR contains a DOCTYPE/ENTITY declaration",
                "Standard IR carries no DTD; entity declarations enable XML "
                "external-entity (XXE) or entity-expansion attacks on a parser.",
                tags=["evasion", "xxe"])]

        import xml.etree.ElementTree as ET
        try:
            root = ET.fromstring(text)
        except ET.ParseError:
            return [self.finding(
                "OPENVINO_MALFORMED", Severity.LOW,
                "OpenVINO IR .xml is not well-formed XML", tags=["evasion"])]

        seen: set[str] = set()
        for el in root.iter():
            values = list(el.attrib.values())
            if el.text:
                values.append(el.text)
            for val in values:
                v = (val or "").strip()
                if not v or len(v) > 4096 or v in seen:
                    continue
                is_lib = bool(self._LIB_RE.search(v))
                # Leave URLs to the exfil engine; flag libs + host/traversal paths.
                if is_lib or (_path_escapes(v) and "://" not in v):
                    seen.add(v)
                    findings.append(self.finding(
                        "OPENVINO_EXTERNAL_REF",
                        Severity.HIGH if is_lib else Severity.MEDIUM,
                        f"OpenVINO IR references an external "
                        f"{'library' if is_lib else 'path'}: {v[:120]}",
                        "A model graph should not reference host shared libraries "
                        "or absolute/traversal paths — a custom-extension (code "
                        "load) or host-access vector.",
                        tags=["code-execution"] if is_lib else ["file-access"],
                        evidence={"ref": v[:200]}))
                    if len(findings) >= 100:
                        return findings
        return findings
