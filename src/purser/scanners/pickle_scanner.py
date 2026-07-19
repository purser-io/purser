"""Static pickle bytecode analysis.

Parses pickle opcode streams with pickletools.genops (never unpickles) and
flags imports of dangerous callables — the technique proven by picklescan and
modelscan, extended with:

  * STACK_GLOBAL resolution via string/memo tracking (protocol 2+ pickles)
  * multi-pickle streams (legacy torch files concatenate several pickles)
  * a safelist tier: imports that are neither known-bad nor known-good are
    reported as suspicious instead of silently passing
  * REDUCE tracking: distinguishes "dangerous callable referenced" from
    "dangerous callable *invoked on load*"
"""

from __future__ import annotations

import io
import pickletools
from pathlib import Path

from purser.core.findings import Finding, Severity
from purser.scanners.base import Scanner

# Module (or module.attr) -> (severity, tags). A key of "module" matches every
# attribute of that module; "module.attr" matches exactly.
DANGEROUS_GLOBALS: dict[str, tuple[Severity, list[str]]] = {
    # Direct code execution
    "builtins.eval": (Severity.CRITICAL, ["code-execution"]),
    "builtins.exec": (Severity.CRITICAL, ["code-execution"]),
    "builtins.compile": (Severity.CRITICAL, ["code-execution"]),
    "builtins.open": (Severity.HIGH, ["file-access"]),
    "builtins.__import__": (Severity.CRITICAL, ["code-execution"]),
    "builtins.getattr": (Severity.HIGH, ["indirection"]),
    "builtins.apply": (Severity.CRITICAL, ["code-execution"]),
    "builtins.breakpoint": (Severity.HIGH, ["code-execution"]),
    "builtins.input": (Severity.MEDIUM, ["code-execution"]),
    "__builtin__.eval": (Severity.CRITICAL, ["code-execution"]),
    "__builtin__.exec": (Severity.CRITICAL, ["code-execution"]),
    "__builtin__.compile": (Severity.CRITICAL, ["code-execution"]),
    "__builtin__.open": (Severity.HIGH, ["file-access"]),
    "__builtin__.getattr": (Severity.HIGH, ["indirection"]),
    "__builtin__.__import__": (Severity.CRITICAL, ["code-execution"]),
    "operator.attrgetter": (Severity.HIGH, ["indirection"]),
    "operator.methodcaller": (Severity.HIGH, ["indirection"]),
    # OS / process
    "os": (Severity.CRITICAL, ["os-command"]),
    "posix": (Severity.CRITICAL, ["os-command"]),
    "nt": (Severity.CRITICAL, ["os-command"]),
    "subprocess": (Severity.CRITICAL, ["os-command"]),
    "commands": (Severity.CRITICAL, ["os-command"]),
    "popen2": (Severity.CRITICAL, ["os-command"]),
    "pty": (Severity.CRITICAL, ["os-command"]),
    "shutil": (Severity.HIGH, ["file-access"]),
    "sys": (Severity.HIGH, ["os-command"]),
    "platform.popen": (Severity.CRITICAL, ["os-command"]),
    "runpy": (Severity.CRITICAL, ["code-execution"]),
    "importlib": (Severity.CRITICAL, ["code-execution"]),
    "imp": (Severity.CRITICAL, ["code-execution"]),
    "code": (Severity.CRITICAL, ["code-execution"]),
    "ctypes": (Severity.CRITICAL, ["native-code"]),
    "cffi": (Severity.CRITICAL, ["native-code"]),
    "marshal": (Severity.CRITICAL, ["code-execution"]),
    "pickle": (Severity.HIGH, ["nested-payload"]),
    "_pickle": (Severity.HIGH, ["nested-payload"]),
    "dill": (Severity.HIGH, ["nested-payload"]),
    "timeit": (Severity.HIGH, ["code-execution"]),
    "pdb": (Severity.HIGH, ["code-execution"]),
    "bdb": (Severity.HIGH, ["code-execution"]),
    "setuptools": (Severity.HIGH, ["code-execution"]),
    "pip": (Severity.HIGH, ["code-execution"]),
    # Network / exfiltration
    "socket": (Severity.CRITICAL, ["network", "exfiltration"]),
    "ssl": (Severity.HIGH, ["network"]),
    "requests": (Severity.CRITICAL, ["network", "exfiltration"]),
    "requests.api": (Severity.CRITICAL, ["network", "exfiltration"]),
    "urllib": (Severity.CRITICAL, ["network", "exfiltration"]),
    "urllib2": (Severity.CRITICAL, ["network", "exfiltration"]),
    "urllib3": (Severity.CRITICAL, ["network", "exfiltration"]),
    "urllib.request": (Severity.CRITICAL, ["network", "exfiltration"]),
    "http.client": (Severity.CRITICAL, ["network", "exfiltration"]),
    "httplib": (Severity.CRITICAL, ["network", "exfiltration"]),
    "httpx": (Severity.CRITICAL, ["network", "exfiltration"]),
    "aiohttp": (Severity.CRITICAL, ["network", "exfiltration"]),
    "ftplib": (Severity.CRITICAL, ["network", "exfiltration"]),
    "smtplib": (Severity.CRITICAL, ["network", "exfiltration"]),
    "telnetlib": (Severity.CRITICAL, ["network", "exfiltration"]),
    "paramiko": (Severity.CRITICAL, ["network", "exfiltration"]),
    "webbrowser": (Severity.HIGH, ["network"]),
    # ML-framework escape hatches
    "torch.hub": (Severity.HIGH, ["remote-code"]),
    "torch.load": (Severity.HIGH, ["nested-payload"]),
    "torch.serialization.load": (Severity.HIGH, ["nested-payload"]),
    "numpy.testing._private.utils.runstring": (Severity.CRITICAL, ["code-execution"]),
    "keras.utils.generic_utils.func_load": (Severity.CRITICAL, ["code-execution"]),
    "tensorflow.python.keras.utils.generic_utils.func_load": (
        Severity.CRITICAL,
        ["code-execution"],
    ),
    "base64": (Severity.MEDIUM, ["obfuscation"]),
    "codecs": (Severity.LOW, ["obfuscation"]),
}

# Import prefixes considered normal in model files; anything not matching a
# dangerous entry or one of these prefixes is reported as suspicious.
SAFE_PREFIXES = (
    "torch.",
    "torch_",
    "numpy",
    "sklearn.",
    "scipy.",
    "joblib.",
    "pandas.",
    "xgboost",
    "lightgbm",
    "catboost",
    "transformers.",
    "tokenizers",
    "sentence_transformers",
    "collections",
    "copyreg",
    "copy_reg",
    "_codecs",
    "builtins.set",
    "builtins.frozenset",
    "builtins.list",
    "builtins.dict",
    "builtins.tuple",
    "builtins.bytearray",
    "builtins.complex",
    "builtins.slice",
    "builtins.range",
    "builtins.object",
    "builtins.type",
    "builtins.print",
    "__builtin__.set",
    "argparse.Namespace",
    "functools.partial",
    "pathlib.",
    "fsspec",
    "datetime",
    "fractions",
    "decimal",
    "uuid",
    "enum",
    "re.compile",
    "_sre",
    "ordered_dict",
    "typing",
    "dataclasses",
    "gensim",
    "nltk",
    "spacy",
    "thinc",
)

STRING_OPS = {
    "SHORT_BINUNICODE",
    "BINUNICODE",
    "BINUNICODE8",
    "UNICODE",
    "STRING",
    "BINSTRING",
    "SHORT_BINSTRING",
}

SUSPICIOUS_NAME_HINTS = ("eval", "exec", "system", "spawn", "popen", "shell", "import")


def classify_import(module: str, name: str) -> tuple[Severity, list[str]] | None:
    """Return (severity, tags) if the import is dangerous, else None."""
    full = f"{module}.{name}" if name else module
    if full in DANGEROUS_GLOBALS:
        return DANGEROUS_GLOBALS[full]
    if module in DANGEROUS_GLOBALS:
        return DANGEROUS_GLOBALS[module]
    # match parent packages, e.g. urllib.request.urlopen -> urllib.request
    parts = module.split(".")
    for i in range(len(parts) - 1, 0, -1):
        prefix = ".".join(parts[:i])
        if prefix in DANGEROUS_GLOBALS:
            return DANGEROUS_GLOBALS[prefix]
    return None


def is_known_safe(module: str, name: str) -> bool:
    full = f"{module}.{name}"
    return full.startswith(SAFE_PREFIXES) or module.startswith(SAFE_PREFIXES)


class PickleScanner(Scanner):
    name = "pickle"

    def scan(self, path: Path) -> list[Finding]:
        data = path.read_bytes()
        return self.scan_bytes(data, source=str(path))

    def scan_bytes(self, data: bytes, source: str = "") -> list[Finding]:
        findings: list[Finding] = []
        imports: list[tuple[str, str]] = []
        reduce_count = 0
        parse_error: str | None = None
        stream = io.BytesIO(data)
        pickles_parsed = 0

        while stream.tell() < len(data):
            start = stream.tell()
            try:
                ops = self._collect_ops(stream, imports)
                reduce_count += ops
                pickles_parsed += 1
            except Exception as exc:
                if pickles_parsed == 0:
                    parse_error = str(exc)
                break
            if stream.tell() == start:  # no progress; avoid infinite loop
                break
            # Skip padding/nulls between concatenated pickles.
            while stream.tell() < len(data):
                b = stream.read(1)
                if b and b != b"\x00":
                    stream.seek(-1, io.SEEK_CUR)
                    break

        if parse_error is not None:
            findings.append(
                self.finding(
                    "PICKLE_UNPARSEABLE",
                    Severity.MEDIUM,
                    "File claims to be a pickle but could not be parsed",
                    f"Opcode parsing failed: {parse_error}. Malformed pickles can be "
                    "used to exploit deserializer bugs or to evade scanners.",
                    tags=["evasion"],
                )
            )
            return findings

        seen: set[tuple[str, str]] = set()
        for module, ident in imports:
            if (module, ident) in seen:
                continue
            seen.add((module, ident))
            verdict = classify_import(module, ident)
            full = f"{module}.{ident}"
            if verdict is not None:
                severity, tags = verdict
                invoked = reduce_count > 0
                findings.append(
                    self.finding(
                        "PICKLE_DANGEROUS_IMPORT",
                        severity,
                        f"Pickle imports dangerous callable `{full}`",
                        (
                            "The pickle opcode stream imports this callable"
                            + (
                                " and contains REDUCE opcodes, so it is invoked "
                                "automatically when the model is loaded."
                                if invoked
                                else "."
                            )
                        ),
                        tags=tags + (["invoked-on-load"] if invoked else []),
                        evidence={"module": module, "name": ident, "invoked": invoked},
                    )
                )
            elif not is_known_safe(module, ident):
                lowered = full.lower()
                hinted = any(h in lowered for h in SUSPICIOUS_NAME_HINTS)
                findings.append(
                    self.finding(
                        "PICKLE_UNKNOWN_IMPORT",
                        Severity.MEDIUM if hinted else Severity.LOW,
                        f"Pickle imports unrecognized symbol `{full}`",
                        "This import is not on the known-safe list for ML model files. "
                        "Loading the pickle will import and may execute this module's code.",
                        tags=["unknown-import"],
                        evidence={"module": module, "name": ident},
                    )
                )
        return findings

    def _collect_ops(self, stream: io.BytesIO, imports: list[tuple[str, str]]) -> int:
        """Parse one pickle from stream, appending discovered imports.

        Returns the number of REDUCE/INST/OBJ opcodes (callable invocations).
        """
        memo: dict[object, str] = {}
        string_stack: list[str] = []
        last_string: str | None = None
        reduce_ops = 0

        for opcode, arg, _pos in pickletools.genops(stream):
            opname = opcode.name
            if opname in STRING_OPS:
                string_stack.append(arg)
                last_string = arg
            elif opname == "MEMOIZE":
                memo[len(memo)] = last_string
            elif opname in ("PUT", "BINPUT", "LONG_BINPUT"):
                memo[arg] = last_string
            elif opname in ("GET", "BINGET", "LONG_BINGET"):
                val = memo.get(arg)
                if isinstance(val, str):
                    string_stack.append(val)
            elif opname == "GLOBAL":
                parts = str(arg).split(" ", 1)
                imports.append((parts[0], parts[1] if len(parts) > 1 else ""))
            elif opname == "INST":
                parts = str(arg).split(" ", 1)
                imports.append((parts[0], parts[1] if len(parts) > 1 else ""))
                reduce_ops += 1
            elif opname == "STACK_GLOBAL":
                if len(string_stack) >= 2:
                    imports.append((string_stack[-2], string_stack[-1]))
                else:
                    imports.append(("<unresolved>", "<unresolved>"))
                string_stack.clear()
            elif opname in ("REDUCE", "OBJ", "NEWOBJ", "NEWOBJ_EX"):
                if opname == "REDUCE":
                    reduce_ops += 1
        return reduce_ops
