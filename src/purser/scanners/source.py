"""Static analysis of bundled Python source and HuggingFace config JSON.

The most common real-world model-supply-chain attack is not a malicious
pickle — it is a benign-looking model shipped with `modeling_*.py` /
`configuration_*.py` files that `transformers` executes when the user (or a
downstream library) passes `trust_remote_code=True`. The `auto_map` /
`custom_pipelines` keys in `config.json` are what wire those files in.

`PythonSourceScanner` parses `.py` files with the `ast` module — it never
imports or executes them — and flags dangerous calls (exec/eval, os/subprocess,
sockets and HTTP clients, dynamic import, native code, marshal/pickle,
env-var harvesting, base64/hex deobfuscation). Calls at module scope are
escalated because `transformers` runs them the moment the module is imported.

`HFConfigScanner` flags the config keys that arm remote-code execution and
points at the referenced source files.
"""

from __future__ import annotations

import ast
import json
from pathlib import Path

from purser.core.findings import Finding, Severity
from purser.scanners.base import Scanner

# Exact dotted call names -> (severity, tag).
DANGEROUS_CALLS: dict[str, tuple[Severity, str]] = {
    "exec": (Severity.CRITICAL, "code-execution"),
    "eval": (Severity.CRITICAL, "code-execution"),
    "compile": (Severity.HIGH, "code-execution"),
    "__import__": (Severity.HIGH, "dynamic-import"),
    "importlib.import_module": (Severity.MEDIUM, "dynamic-import"),
    "importlib.__import__": (Severity.HIGH, "dynamic-import"),
    "marshal.loads": (Severity.CRITICAL, "code-execution"),
    "marshal.load": (Severity.CRITICAL, "code-execution"),
    "pickle.loads": (Severity.HIGH, "nested-payload"),
    "pickle.load": (Severity.HIGH, "nested-payload"),
    "os.system": (Severity.CRITICAL, "os-command"),
    "os.popen": (Severity.CRITICAL, "os-command"),
    "os.spawnl": (Severity.CRITICAL, "os-command"),
    "os.spawnv": (Severity.CRITICAL, "os-command"),
    "pty.spawn": (Severity.CRITICAL, "os-command"),
    "socket.socket": (Severity.HIGH, "network"),
    "socket.create_connection": (Severity.HIGH, "network"),
    "ctypes.CDLL": (Severity.CRITICAL, "native-code"),
    "ctypes.WinDLL": (Severity.CRITICAL, "native-code"),
    "cffi.FFI": (Severity.CRITICAL, "native-code"),
    "setattr": (Severity.LOW, "indirection"),
}

# Any call whose dotted name starts with one of these module roots.
NETWORK_ROOTS = (
    "requests.", "urllib.", "urllib2.", "urllib3.", "http.client", "httplib.",
    "httpx.", "aiohttp.", "ftplib.", "smtplib.", "telnetlib.", "paramiko.",
    "websocket.", "websockets.",
)
SUBPROCESS_CALLS = {
    "subprocess.Popen", "subprocess.run", "subprocess.call", "subprocess.check_call",
    "subprocess.check_output", "subprocess.getoutput", "subprocess.getstatusoutput",
}
# base64 / hex / codec decoders — obfuscation layer, escalated when the file
# also contains exec/eval.
DECODER_CALLS = {
    "base64.b64decode", "base64.b85decode", "base64.b32decode", "base64.b16decode",
    "base64.a85decode", "base64.decodebytes", "codecs.decode", "bytes.fromhex",
    "binascii.unhexlify", "binascii.a2b_base64", "zlib.decompress", "gzip.decompress",
}


def _dotted(node: ast.AST) -> str | None:
    """Resolve a call target (Name/Attribute chain) to a dotted string."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return None


def _classify(dotted: str) -> tuple[Severity, str] | None:
    if dotted in DANGEROUS_CALLS:
        return DANGEROUS_CALLS[dotted]
    if dotted in SUBPROCESS_CALLS:
        return (Severity.CRITICAL, "os-command")
    if dotted.startswith("os.exec"):
        return (Severity.CRITICAL, "os-command")
    if dotted.startswith(NETWORK_ROOTS):
        return (Severity.HIGH, "network")
    if dotted in DECODER_CALLS:
        return (Severity.LOW, "obfuscation")
    return None


class _Visitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.func_depth = 0
        self.hits: list[tuple[str, Severity, str, int, bool]] = []
        self.has_exec = False
        self.env_access = False
        self.env_line = 0

    def _enter_func(self, node: ast.AST) -> None:
        self.func_depth += 1
        self.generic_visit(node)
        self.func_depth -= 1

    visit_FunctionDef = _enter_func
    visit_AsyncFunctionDef = _enter_func
    visit_Lambda = _enter_func

    def visit_Call(self, node: ast.Call) -> None:
        dotted = _dotted(node.func)
        if dotted:
            verdict = _classify(dotted)
            if verdict is not None:
                sev, tag = verdict
                if tag == "code-execution" and dotted in ("exec", "eval"):
                    self.has_exec = True
                on_import = self.func_depth == 0
                self.hits.append((dotted, sev, tag, getattr(node, "lineno", 0), on_import))
            # getattr(x, <non-literal>) — indirection to hide attribute access
            if dotted == "getattr" and len(node.args) >= 2 and not isinstance(
                node.args[1], ast.Constant
            ):
                self.hits.append((
                    "getattr(dynamic)", Severity.MEDIUM, "indirection",
                    getattr(node, "lineno", 0), self.func_depth == 0,
                ))
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        if _dotted(node) in ("os.environ",):
            self.env_access = True
            self.env_line = getattr(node, "lineno", 0)
        self.generic_visit(node)


class PythonSourceScanner(Scanner):
    name = "python_source"

    def scan(self, path: Path) -> list[Finding]:
        try:
            source = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            return [self.finding("PY_UNREADABLE", Severity.LOW,
                                 "Python source could not be read", str(exc))]
        return self.scan_source(source)

    def scan_source(self, source: str) -> list[Finding]:
        try:
            tree = ast.parse(source)
        except SyntaxError as exc:
            return [self.finding(
                "PY_UNPARSEABLE", Severity.MEDIUM,
                "Python source could not be parsed",
                f"Syntax error at line {exc.lineno}: {exc.msg}. Unparseable "
                "source bundled with a model can be a Python-2 payload or an "
                "attempt to evade static review.",
                tags=["evasion"],
            )]

        visitor = _Visitor()
        visitor.visit(tree)
        findings: list[Finding] = []
        seen: set[tuple[str, int]] = set()

        for dotted, sev, tag, line, on_import in visitor.hits:
            # Decoder calls are only interesting alongside exec/eval.
            if tag == "obfuscation":
                if not visitor.has_exec:
                    continue
                sev = Severity.HIGH
            key = (dotted, line)
            if key in seen:
                continue
            seen.add(key)
            tags = [tag, "trust-remote-code"]
            when = (
                "at module scope, so it runs the moment the module is imported "
                "(e.g. transformers with trust_remote_code=True)"
                if on_import else
                "inside a function, so it runs when that function is called"
            )
            if on_import:
                tags.append("on-import")
            findings.append(self.finding(
                "PY_DANGEROUS_CALL", sev,
                f"Bundled Python calls `{dotted}`",
                f"The source calls `{dotted}` {when}.",
                tags=tags,
                evidence={"call": dotted, "line": line, "on_import": on_import},
            ))

        if visitor.env_access:
            findings.append(self.finding(
                "PY_ENV_HARVEST", Severity.MEDIUM,
                "Bundled Python reads process environment (`os.environ`)",
                "Reading environment variables in model code is a common way to "
                "harvest secrets/credentials for exfiltration.",
                tags=["secret", "trust-remote-code"],
                evidence={"line": visitor.env_line},
            ))
        return findings


class HFConfigScanner(Scanner):
    """Flag config keys that arm remote-code execution."""

    name = "hf_config"

    KEYS: dict[str, tuple[Severity, str]] = {
        "auto_map": (Severity.HIGH,
                     "maps model/tokenizer classes to bundled Python that is "
                     "executed under trust_remote_code=True"),
        "custom_pipelines": (Severity.MEDIUM,
                             "registers a custom pipeline implemented in bundled "
                             "Python executed under trust_remote_code=True"),
        "trust_remote_code": (Severity.MEDIUM,
                             "config requests remote-code trust"),
    }

    def scan(self, path: Path) -> list[Finding]:
        try:
            doc = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        except (json.JSONDecodeError, OSError):
            return []  # not our concern if it isn't valid JSON
        findings: list[Finding] = []
        for key, (sev, why) in self.KEYS.items():
            refs = _find_key(doc, key)
            if not refs:
                continue
            targets = _auto_map_targets(refs) if key == "auto_map" else []
            detail = f"`{key}` {why}."
            if targets:
                detail += " References: " + ", ".join(sorted(targets)[:10])
            findings.append(self.finding(
                "HF_CONFIG_REMOTE_CODE", sev,
                f"Config declares `{key}` (arms trust_remote_code)",
                detail,
                tags=["trust-remote-code", "code-execution"],
                evidence={"key": key, "targets": sorted(targets)[:20]},
            ))
        return findings


def _find_key(doc: object, target: str) -> list[object]:
    out: list[object] = []
    if isinstance(doc, dict):
        for k, v in doc.items():
            if k == target:
                out.append(v)
            out.extend(_find_key(v, target))
    elif isinstance(doc, list):
        for item in doc:
            out.extend(_find_key(item, target))
    return out


def _auto_map_targets(refs: list[object]) -> set[str]:
    """Extract 'modeling_x.MyClass' style references from auto_map values."""
    targets: set[str] = set()
    for ref in refs:
        values = ref.values() if isinstance(ref, dict) else [ref]
        for v in values:
            for item in (v if isinstance(v, list) else [v]):
                if isinstance(item, str) and "--" not in item and "." in item:
                    targets.add(item)
    return targets
