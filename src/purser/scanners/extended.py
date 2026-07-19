"""Extended-format scanners: TFLite, CoreML, skops, ExecuTorch, Paddle,
TF.js, and PMML.

Same design rules as the core scanners: static byte/structure analysis only,
nothing is deserialized with the target framework. Formats with no dedicated
scanner (Flax msgpack, MXNet params, OpenVINO IR, native GBM formats, legacy
GGML) still get format identification for policy allowlists plus the
format-agnostic exfiltration scan.
"""

from __future__ import annotations

import json
import re
import zipfile
from pathlib import Path, PurePosixPath

from purser.core.findings import Finding, Severity
from purser.scanners.base import Scanner
from purser.scanners.pickle_scanner import classify_import, is_known_safe


class TFLiteScanner(Scanner):
    """TFLite flatbuffers: Flex-delegate ops pull in the full TensorFlow
    runtime, including code-execution and file-access kernels."""

    name = "tflite"

    CRITICAL_FLEX = {"PyFunc", "PyFuncStateless", "EagerPyFunc"}
    HIGH_FLEX = {"ReadFile", "WriteFile", "MatchingFiles", "Save", "SaveV2"}

    def scan(self, path: Path) -> list[Finding]:
        data = path.read_bytes()
        if len(data) < 8 or data[4:8] != b"TFL3":
            return [self.finding(
                "TFLITE_BAD_MAGIC", Severity.MEDIUM,
                "File has .tflite extension but wrong flatbuffer identifier",
                "The file is not a TFLite model; mismatched extensions are "
                "used to smuggle other formats past reviewers.",
                tags=["evasion"],
            )]
        findings: list[Finding] = []
        flex_ops = sorted({
            m.group().decode() for m in re.finditer(rb"Flex[A-Z][A-Za-z0-9]{1,48}", data)
        })
        for op in flex_ops:
            base = op[len("Flex"):]
            if base in self.CRITICAL_FLEX:
                sev, why, tags = (Severity.CRITICAL,
                                  "executes arbitrary Python at inference time",
                                  ["code-execution"])
            elif base in self.HIGH_FLEX:
                sev, why, tags = (Severity.HIGH,
                                  "accesses the host filesystem",
                                  ["file-access"])
            else:
                sev, why, tags = (Severity.LOW,
                                  "pulls the full TensorFlow runtime into the "
                                  "interpreter (expanded attack surface)",
                                  ["attack-surface"])
            findings.append(self.finding(
                "TFLITE_FLEX_OP", sev,
                f"TFLite model uses Flex delegate op `{op}`",
                f"This op {why}.",
                tags=tags, evidence={"op": op},
            ))
        return findings


class CoreMLScanner(Scanner):
    """CoreML .mlmodel protobufs.

    Limitation (honest): custom-layer class names are arbitrary strings in
    the protobuf, so detection is marker-based — we flag the MIL/NN custom
    layer markers, which require out-of-model native code to run. Deeper
    inspection would need the CoreML proto schema.
    """

    name = "coreml"

    def scan(self, path: Path) -> list[Finding]:
        data = path.read_bytes()
        findings: list[Finding] = []
        for marker in (b"custom_layer", b"customLayer", b"custom_lib"):
            if marker in data:
                findings.append(self.finding(
                    "COREML_CUSTOM_LAYER", Severity.MEDIUM,
                    "CoreML model declares a custom layer",
                    "Custom layers execute developer-supplied native code when "
                    "the model runs; verify the accompanying implementation.",
                    tags=["native-code"], evidence={"marker": marker.decode()},
                ))
                break
        return findings


class SkopsScanner(Scanner):
    """skops archives: the schema references importable types by module/class
    name — run them through the same dangerous/safe classification as pickle
    imports, and flag pickle-fallback nodes."""

    name = "skops"

    def scan(self, path: Path) -> list[Finding]:
        try:
            with zipfile.ZipFile(path) as zf:
                names = zf.namelist()
                if "schema.json" not in names:
                    return [self.finding(
                        "SKOPS_MALFORMED", Severity.MEDIUM,
                        "skops archive has no schema.json",
                        tags=["evasion"],
                    )]
                schema = json.loads(zf.read("schema.json"))
        except (zipfile.BadZipFile, json.JSONDecodeError) as exc:
            return [self.finding(
                "SKOPS_MALFORMED", Severity.MEDIUM,
                "skops archive could not be parsed",
                str(exc), tags=["evasion"],
            )]

        findings: list[Finding] = []
        seen: set[tuple[str, str]] = set()
        for node in self._walk(schema):
            module = str(node.get("__module__", ""))
            cls = str(node.get("__class__", ""))
            loader = str(node.get("__loader__", ""))
            if "pickle" in loader.lower():
                findings.append(self.finding(
                    "SKOPS_PICKLE_FALLBACK", Severity.HIGH,
                    f"skops schema uses pickle fallback loader `{loader}`",
                    "Pickle-backed nodes reintroduce arbitrary code execution "
                    "into an otherwise-safe format.",
                    tags=["nested-payload"], evidence={"loader": loader},
                ))
            if not module or (module, cls) in seen:
                continue
            seen.add((module, cls))
            verdict = classify_import(module, cls)
            full = f"{module}.{cls}"
            if verdict is not None:
                sev, tags = verdict
                findings.append(self.finding(
                    "SKOPS_DANGEROUS_TYPE", sev,
                    f"skops schema references dangerous type `{full}`",
                    "This type is instantiated when the archive is loaded.",
                    tags=tags, evidence={"module": module, "class": cls},
                ))
            elif not is_known_safe(module, cls):
                findings.append(self.finding(
                    "SKOPS_UNKNOWN_TYPE", Severity.LOW,
                    f"skops schema references unrecognized type `{full}`",
                    "Not on the known-safe list; loading imports this module.",
                    tags=["unknown-import"], evidence={"module": module, "class": cls},
                ))
        return findings

    def _walk(self, node):
        if isinstance(node, dict):
            if "__module__" in node or "__class__" in node or "__loader__" in node:
                yield node
            for v in node.values():
                yield from self._walk(v)
        elif isinstance(node, list):
            for v in node:
                yield from self._walk(v)


class ExecuTorchScanner(Scanner):
    """ExecuTorch .pte flatbuffers: validate the identifier; content is a
    compiled graph with no Python payload surface (exfil scan still runs)."""

    name = "executorch"

    def scan(self, path: Path) -> list[Finding]:
        with open(path, "rb") as fh:
            head = fh.read(8)
        if len(head) < 8 or head[4:6] != b"ET":
            return [self.finding(
                "EXECUTORCH_BAD_MAGIC", Severity.MEDIUM,
                "File has .pte extension but wrong flatbuffer identifier",
                "The file is not an ExecuTorch program; mismatched extensions "
                "are used to smuggle other formats past reviewers.",
                tags=["evasion"],
            )]
        return []


class PaddleScanner(Scanner):
    """PaddlePaddle program protobufs (.pdmodel): the `py_func` / `py_layer`
    ops execute registered Python callables at inference time. Parameter
    files (.pdparams/.pdiparams) are pickle streams handled by the pickle
    scanner via format detection."""

    name = "paddle"

    def scan(self, path: Path) -> list[Finding]:
        data = path.read_bytes()
        findings: list[Finding] = []
        for marker in (b"py_func", b"py_layer"):
            if marker in data:
                findings.append(self.finding(
                    "PADDLE_PY_OP", Severity.CRITICAL,
                    f"Paddle program references `{marker.decode()}` op",
                    "This op executes arbitrary registered Python when the "
                    "program runs.",
                    tags=["code-execution"], evidence={"op": marker.decode()},
                ))
        return findings


class TFJSScanner(Scanner):
    """TensorFlow.js model.json manifests: weights are data-only, but shard
    paths are attacker-controlled and fetched by the loader."""

    name = "tfjs"

    def scan(self, path: Path) -> list[Finding]:
        try:
            manifest = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        except json.JSONDecodeError as exc:
            return [self.finding(
                "TFJS_MALFORMED", Severity.LOW,
                "TF.js manifest is not valid JSON", str(exc), tags=["evasion"],
            )]
        findings: list[Finding] = []
        for group in manifest.get("weightsManifest", []) or []:
            for shard in group.get("paths", []) or []:
                shard_str = str(shard)
                p = PurePosixPath(shard_str.replace("\\", "/"))
                if p.is_absolute() or ".." in p.parts or "://" in shard_str:
                    findings.append(self.finding(
                        "TFJS_SHARD_TRAVERSAL", Severity.HIGH,
                        f"TF.js weight shard path escapes the model directory: `{shard_str[:120]}`",
                        "Loaders resolve shard paths relative to the manifest; "
                        "absolute/parent/remote paths make the loader read or "
                        "fetch attacker-chosen locations.",
                        tags=["file-access", "network"],
                        evidence={"path": shard_str[:300]},
                    ))
        return findings


class PMMLScanner(Scanner):
    """PMML documents: Extension elements can smuggle engine-specific script
    payloads; also guard against external-entity declarations."""

    name = "pmml"

    def scan(self, path: Path) -> list[Finding]:
        text = path.read_bytes()[:16 * 1024 * 1024].decode("utf-8", "replace")
        findings: list[Finding] = []
        if re.search(r"<!ENTITY", text):
            findings.append(self.finding(
                "PMML_XXE", Severity.HIGH,
                "PMML document declares XML entities (possible XXE)",
                "Entity declarations in model documents are used for XXE "
                "attacks against the consuming parser.",
                tags=["file-access"],
            ))
        for m in re.finditer(r"<Extension\b[^>]*>", text):
            window = text[m.start():m.start() + 2000].lower()
            if any(k in window for k in ("script", "python", "exec", "eval", "code")):
                findings.append(self.finding(
                    "PMML_EXTENSION_SCRIPT", Severity.MEDIUM,
                    "PMML Extension element contains script-like content",
                    "Extension elements are engine-specific escape hatches; "
                    "some engines execute embedded code from them.",
                    tags=["code-execution"],
                ))
                break
        return findings
