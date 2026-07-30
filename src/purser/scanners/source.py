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


# --------------------------------------------------------------------------
# Intraprocedural taint: catch payloads assembled / resolved at runtime that a
# literal name match misses. Two conservative, low-false-positive analyses:
#   * DATA taint  — values produced by deobfuscation (base64/hex/codec decode)
#     or char-code assembly (`chr`/`bytes([ints])`); flagged only when they
#     reach a dangerous sink or are invoked as a callable.
#   * CALLABLE aliasing — a variable bound to a dangerous callable (`f =
#     os.system`) or to a dynamically-resolved one (`f = getattr(os, <tainted>)`);
#     flagged when it is later called. Benign model code virtually never aliases
#     os/exec/subprocess/... to a name and invokes it, nor decodes-then-executes.
# Each runs per scope (module top-level + each function/lambda independently),
# flow-insensitively (a fixpoint over that scope's assignments) — conservative
# within a scope, but a name in one function can't taint a sibling's same-named
# variable.

# Deliberately narrow: only the code-execution surface. Aliasing/decoding into
# network / dynamic-import / pickle sinks is common in benign library code (and
# those sinks are already name-matched + covered by the exfil engine), so
# including them makes the taint pass noisy. Verified against a real-Python
# corpus (site-packages): this set keeps it near-zero-FP.
_SINK_TAGS = {"code-execution", "os-command", "native-code"}


def _target_names(target: ast.AST) -> list[str]:
    if isinstance(target, ast.Name):
        return [target.id]
    if isinstance(target, (ast.Tuple, ast.List)):
        names: list[str] = []
        for elt in target.elts:
            names.extend(_target_names(elt))
        return names
    if isinstance(target, ast.Starred):
        return _target_names(target.value)
    return []


def _is_taint_source(dotted: str, node: ast.Call) -> bool:
    """A call whose *result* is a deobfuscated / runtime-assembled value."""
    if dotted in DECODER_CALLS or dotted == "chr":
        return True
    if dotted in ("bytes", "bytearray") and node.args and isinstance(
        node.args[0], (ast.List, ast.Tuple, ast.ListComp, ast.GeneratorExp, ast.SetComp)
    ):
        return True
    return False


def _expr_taints(node: ast.AST | None, tainted: set[str]) -> bool:
    """True if evaluating `node` may yield tainted (deobfuscated/assembled) data."""
    if node is None:
        return False
    for sub in ast.walk(node):
        if isinstance(sub, ast.Name) and sub.id in tainted:
            return True
        if isinstance(sub, ast.Call):
            d = _dotted(sub.func)
            if d and _is_taint_source(d, sub):
                return True
    return False


def _scopes(tree: ast.AST):
    """Yield each analysis scope: the module, then every function / lambda.
    Taint is computed per-scope so a variable named `x` in one function can't
    poison an unrelated `x` in a sibling (the whole-module merge is a real FP
    source — e.g. numpy's tests reuse names like `method` across test funcs)."""
    yield tree
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            yield node


def _own_nodes(scope: ast.AST) -> list[ast.AST]:
    """Descendants of `scope` that execute in *this* scope — i.e. not inside a
    nested function / lambda body (those are separate scopes)."""
    if isinstance(scope, ast.Lambda):
        roots = [scope.body]
    else:
        roots = list(getattr(scope, "body", []))
    out: list[ast.AST] = []
    stack = list(roots)
    while stack:
        node = stack.pop()
        # A nested function/lambda is a separate scope — don't include it or
        # descend into its body (its own `_scopes` entry handles it).
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            continue
        out.append(node)
        stack.extend(ast.iter_child_nodes(node))
    return out


def _assignments(nodes: list[ast.AST]):
    for node in nodes:
        if isinstance(node, ast.Assign):
            yield node.targets, node.value, False
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            yield [node.target], node.value, False
        elif isinstance(node, ast.AugAssign):
            yield [node.target], node.value, True
        elif isinstance(node, ast.NamedExpr):
            yield [node.target], node.value, False


def _data_tainted_names(nodes: list[ast.AST]) -> set[str]:
    tainted: set[str] = set()
    changed = True
    while changed:
        changed = False
        for targets, value, is_aug in _assignments(nodes):
            names = [n for t in targets for n in _target_names(t)]
            if not names:
                continue
            aug_self = is_aug and any(n in tainted for n in names)
            if aug_self or _expr_taints(value, tainted):
                for n in names:
                    if n not in tainted:
                        tainted.add(n)
                        changed = True
    return tainted


def _callable_source(value: ast.AST, aliases: dict[str, tuple[Severity, str]],
                     data_tainted: set[str]) -> tuple[Severity, str] | None:
    """If `value` evaluates to a dangerous callable, return its (severity, tag)."""
    if isinstance(value, (ast.Name, ast.Attribute)):
        dotted = _dotted(value)
        if dotted:
            if dotted in ("exec", "eval", "compile"):
                return (Severity.CRITICAL, "code-execution")
            verdict = _classify(dotted)
            if verdict and verdict[1] in _SINK_TAGS:
                return verdict
            if dotted in aliases:                 # y = x (alias of an alias)
                return aliases[dotted]
    if isinstance(value, ast.Call):
        d = _dotted(value.func)
        if d == "getattr" and len(value.args) >= 2 and _expr_taints(value.args[1], data_tainted):
            return (Severity.CRITICAL, "indirection")   # os.system resolved from decoded name
    return None


def _callable_aliases(nodes: list[ast.AST], data_tainted: set[str]) -> dict[str, tuple[Severity, str]]:
    aliases: dict[str, tuple[Severity, str]] = {}
    changed = True
    while changed:
        changed = False
        for targets, value, is_aug in _assignments(nodes):
            if is_aug:
                continue
            info = _callable_source(value, aliases, data_tainted)
            if info is None:
                continue
            for t in targets:
                for n in _target_names(t):
                    if n not in aliases:
                        aliases[n] = info
                        changed = True
    return aliases


def _scope_taint_hits(nodes: list[ast.AST], data_tainted: set[str],
                      aliases: dict[str, tuple[Severity, str]], on_import: bool):
    """Sinks in one scope reached by tainted data or invoked via an aliased /
    dynamically-resolved callable. Returns
    (rule, name, sev, tag, line, on_import, arg_tainted) tuples."""
    hits: list[tuple[str, str, Severity, str, int, bool, bool]] = []
    for node in nodes:
        if not isinstance(node, ast.Call):
            continue
        line = getattr(node, "lineno", 0)
        func = node.func
        arg_tainted = any(_expr_taints(a, data_tainted) for a in node.args) or any(
            _expr_taints(kw.value, data_tainted) for kw in node.keywords)

        # (1) invoking a dynamically-resolved / aliased callable
        if isinstance(func, ast.Name) and func.id in aliases:
            sev, tag = aliases[func.id]
            hits.append(("PY_DYNAMIC_CALL", func.id, sev, tag, line, on_import, arg_tainted))
        elif isinstance(func, ast.Call) and _dotted(func.func) == "getattr" \
                and len(func.args) >= 2 and _expr_taints(func.args[1], data_tainted):
            hits.append(("PY_DYNAMIC_CALL", "getattr", Severity.CRITICAL,
                         "indirection", line, on_import, arg_tainted))
        # (2) a known dangerous sink fed a tainted argument
        elif arg_tainted:
            dotted = _dotted(func)
            if dotted:
                tag = None
                if dotted in ("exec", "eval", "compile"):
                    tag = "code-execution"
                else:
                    verdict = _classify(dotted)
                    if verdict and verdict[1] in _SINK_TAGS:
                        tag = verdict[1]
                if tag:
                    # every _SINK_TAGS tag is a code-execution surface -> CRITICAL
                    hits.append(("PY_TAINTED_FLOW", dotted, Severity.CRITICAL, tag,
                                 line, on_import, True))
    return hits


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

        findings.extend(self._taint_findings(tree))
        return findings

    def _taint_findings(self, tree: ast.AST) -> list[Finding]:
        """Dataflow pass: payloads assembled/deobfuscated at runtime or invoked
        via an aliased/dynamically-resolved callable — what a literal name match
        alone would miss or under-rate."""
        hits: list[tuple[str, str, Severity, str, int, bool, bool]] = []
        for scope in _scopes(tree):
            own = _own_nodes(scope)
            data_tainted = _data_tainted_names(own)
            aliases = _callable_aliases(own, data_tainted)
            # Run per-scope even with no tainted *variables* — an inline source in
            # a sink argument (e.g. `exec(b64decode(...))`) has no binding but is
            # still a staged payload.
            hits.extend(_scope_taint_hits(own, data_tainted, aliases, scope is tree))
        out: list[Finding] = []
        seen: set[tuple[str, str, int]] = set()
        for rule, name, sev, tag, line, on_import, arg_tainted in hits:
            key = (rule, name, line)
            if key in seen:
                continue
            seen.add(key)
            scope = (" at module scope (runs the moment the module is imported)"
                     if on_import else " inside a function")
            if rule == "PY_DYNAMIC_CALL":
                title = "Bundled Python invokes a runtime-resolved callable"
                detail = (
                    f"`{name}` is a callable resolved at runtime — aliased from a "
                    "dangerous call or assembled/decoded — and is then invoked"
                    f"{scope}. This evades a static match on the literal call name"
                    + (", and it is called with a deobfuscated argument" if arg_tainted else "")
                    + "."
                )
            else:  # PY_TAINTED_FLOW
                title = f"Deobfuscated data flows into `{name}`"
                detail = (
                    f"A runtime-assembled / deobfuscated value is passed to `{name}`"
                    f"{scope} — a staged payload a literal-argument scan would miss."
                )
            tags = [tag, "taint", "trust-remote-code"]
            if on_import:
                tags.append("on-import")
            out.append(self.finding(rule, sev, title, detail, tags=tags,
                                    evidence={"name": name, "line": line,
                                              "on_import": on_import,
                                              "arg_tainted": arg_tainted}))
        return out


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
