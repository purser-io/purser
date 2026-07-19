"""Deep pickle gadget-chain heuristics.

The core `PickleScanner` flags *known-dangerous imports*. This analyzer is the
complementary, higher-recall pass: it looks at how the opcode stream is
*composed* to catch gadget chains that use only individually-innocent pieces —
the technique real pickle exploits use to slip past import allowlists.

Still 100% static: `pickletools.genops`, never unpickled. Findings are
heuristic (higher false-positive tolerance) and prefixed `DEEP_GADGET_*`.
"""

from __future__ import annotations

import io
import pickletools
from pathlib import Path

from purser.core.findings import Finding, Severity

# "Pivot" primitives: callables that let an attacker reach arbitrary behavior
# indirectly, so they're dangerous *even when imported from a trusted module*.
# When one of these is invoked (REDUCE), it's a strong gadget-composition signal.
PIVOTS = {
    "getattr", "setattr", "apply", "eval", "exec", "vars", "globals",
    "builtins.getattr", "builtins.setattr", "builtins.eval", "builtins.exec",
    "builtins.apply", "builtins.vars", "builtins.globals", "builtins.__import__",
    "__builtin__.getattr", "__builtin__.apply", "__builtin__.eval",
    "operator.attrgetter", "operator.methodcaller", "operator.itemgetter",
    "functools.partial", "functools.reduce", "functools.reduce",
    "importlib.import_module", "importlib.__import__", "operator.call",
}

STRING_OPS = {
    "SHORT_BINUNICODE", "BINUNICODE", "BINUNICODE8", "UNICODE",
    "STRING", "BINSTRING", "SHORT_BINSTRING",
}
REDUCE_OPS = {"REDUCE", "OBJ", "NEWOBJ", "NEWOBJ_EX", "INST", "BUILD"}


def _iter_imports_and_ops(data: bytes):
    """Yield (imports, reduce_count, opcode_count) across concatenated pickles."""
    stream = io.BytesIO(data)
    imports: list[str] = []
    reduce_count = 0
    op_count = 0
    string_stack: list[str] = []
    last_string: str | None = None
    memo: dict[int, str] = {}
    n = len(data)
    while stream.tell() < n:
        start = stream.tell()
        try:
            for opcode, arg, _pos in pickletools.genops(stream):
                op_count += 1
                name = opcode.name
                if name in STRING_OPS:
                    string_stack.append(arg)
                    last_string = arg
                elif name == "MEMOIZE":
                    memo[len(memo)] = last_string
                elif name in ("PUT", "BINPUT", "LONG_BINPUT"):
                    memo[arg] = last_string
                elif name in ("GET", "BINGET", "LONG_BINGET"):
                    v = memo.get(arg)
                    if isinstance(v, str):
                        string_stack.append(v)
                elif name in ("GLOBAL", "INST"):
                    parts = str(arg).split(" ", 1)
                    imports.append(f"{parts[0]}.{parts[1]}" if len(parts) > 1 else parts[0])
                elif name == "STACK_GLOBAL":
                    if len(string_stack) >= 2:
                        imports.append(f"{string_stack[-2]}.{string_stack[-1]}")
                    string_stack.clear()
                if name in REDUCE_OPS:
                    reduce_count += 1
        except Exception:
            break
        if stream.tell() == start:
            break
        while stream.tell() < n:
            b = stream.read(1)
            if b and b != b"\x00":
                stream.seek(-1, io.SEEK_CUR)
                break
    return imports, reduce_count, op_count


def _matches_pivot(full: str) -> bool:
    if full in PIVOTS:
        return True
    tail = full.rsplit(".", 1)[-1]
    return tail in {"getattr", "setattr", "apply", "eval", "exec",
                    "attrgetter", "methodcaller", "partial", "import_module"}


def analyze(data: bytes) -> list[Finding]:
    findings: list[Finding] = []
    try:
        imports, reduce_count, op_count = _iter_imports_and_ops(data)
    except Exception:
        return findings
    if not imports and reduce_count == 0:
        return findings

    invoked = reduce_count > 0
    pivots = sorted({i for i in imports if _matches_pivot(i)})
    if pivots and invoked:
        findings.append(Finding(
            rule_id="DEEP_GADGET_PIVOT", severity=Severity.HIGH,
            title="Pickle uses indirection primitive(s) as a gadget",
            detail=("The stream imports and invokes indirection primitive(s) "
                    f"{pivots} — these reach arbitrary behavior even from "
                    "trusted modules, the hallmark of a gadget chain that "
                    "evades import allowlists."),
            scanner="deep.gadget", tags=["code-execution", "gadget"],
            evidence={"pivots": pivots, "reduce_count": reduce_count},
        ))

    # Object-graph complexity: many distinct imports combined with many
    # constructor invocations is unusual for a plain weights pickle.
    distinct = sorted(set(imports))
    if invoked and len(distinct) >= 8 and reduce_count >= 8:
        findings.append(Finding(
            rule_id="DEEP_GADGET_COMPLEX", severity=Severity.MEDIUM,
            title="Pickle builds a complex object graph",
            detail=(f"{len(distinct)} distinct imports and {reduce_count} "
                    "constructor/reduce ops — unusually complex for stored "
                    "weights; review what it constructs on load."),
            scanner="deep.gadget", tags=["gadget"],
            evidence={"distinct_imports": len(distinct), "reduce_count": reduce_count},
        ))

    # Deeply-nested attribute imports (a.b.c.d.e) are atypical and often used to
    # reach obscure callables.
    deep_attr = sorted({i for i in imports if i.count(".") >= 4})
    if deep_attr:
        findings.append(Finding(
            rule_id="DEEP_GADGET_DEEP_IMPORT", severity=Severity.LOW,
            title="Pickle imports via unusually deep attribute paths",
            detail=f"Deeply-nested imports: {deep_attr[:5]}",
            scanner="deep.gadget", tags=["gadget"],
            evidence={"imports": deep_attr[:20]},
        ))
    return findings


def analyze_file(path: Path) -> list[Finding]:
    return analyze(Path(path).read_bytes())
