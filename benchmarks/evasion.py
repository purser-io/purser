"""Adversarial evasion suite for the Purser validation benchmark (Phase 3 of
the now-complete validation arc).

Where the known-answer corpus (`kat.py`) asks "does Purser flag a plainly
malicious sample?", this asks the harder question: "does it still flag the
malicious payload when the attacker actively hides it?" Each sample is a genuine
(inert) malicious payload wrapped in one evasion technique — a spoofed
extension, a nested archive, an encoded/obfuscated exfil string, a STACK_GLOBAL
pickle, etc.

Every sample is tagged `resisted` (Purser claims to defeat this technique) or
not. Evasion **recall over the resisted set must stay 100%** — a miss there is a
regression and fails the gate. The non-resisted samples are *known* residuals
from `ROADMAP.md` (packed-binary C2 endpoints); they are reported honestly as "evaded" so the
frontier is visible and measured, not hidden.

    python benchmarks/evasion.py                 # report
    python benchmarks/evasion.py --min-recall 100  # gate (CI); exit 1 on regression

Payloads are inert (`os.system("true")` etc.) and never executed — Purser only
inspects bytes. Nothing here is committed; it is generated into work/.
"""
from __future__ import annotations

import os

import argparse
import base64
import json
import pickle
import struct
import time
import zipfile
import zlib
from pathlib import Path

from purser.core.policy import Policy
from purser.core.scanner import scan_target

HERE = Path(__file__).parent
WORK = HERE / "work" / "evasion"
RESULTS = HERE / "results"
DETECTED = {"MEDIUM", "HIGH", "CRITICAL"}

_WEBHOOK = b"https://hooks.slack.com/services/T00000000/B00000000/" + b"X" * 24


class _OsSystem:
    def __reduce__(self):
        import os
        return (os.system, ("true",))


def _stack_global_reduce(module: str, name: str, arg: str = "true") -> bytes:
    """A protocol-4 pickle that resolves its callable via the STACK_GLOBAL
    opcode (module + name pushed as separate strings) instead of GLOBAL — the
    classic way to dodge scanners that only pattern-match the GLOBAL opcode."""
    def su(s: str) -> bytes:  # SHORT_BINUNICODE
        b = s.encode()
        return b"\x8c" + bytes([len(b)]) + b
    return (b"\x80\x04" + su(module) + su(name) + b"\x93"  # STACK_GLOBAL
            + su(arg) + b"\x85" + b"R" + b".")            # TUPLE1, REDUCE, STOP


def _object_npy() -> bytes:
    """A hand-built object-dtype .npy carrying an embedded pickle (no numpy dep)."""
    payload = pickle.dumps(_OsSystem())
    hd = "{'descr': '|O', 'fortran_order': False, 'shape': (1,), }".encode("latin1")
    hd += b" " * (64 - ((10 + len(hd) + 1) % 64)) + b"\n"
    return b"\x93NUMPY\x01\x00" + struct.pack("<H", len(hd)) + hd + payload


def _xor(data: bytes, key: int = 0x5A) -> bytes:
    return bytes(b ^ key for b in data)


def build(dest: Path) -> list[dict]:
    """Materialize the evasion corpus under `dest`; return manifest entries."""
    dest.mkdir(parents=True, exist_ok=True)
    entries: list[dict] = []

    def add(cid: str, path: Path, technique: str, resisted: bool, note: str = "") -> None:
        entries.append({"id": cid, "path": str(path), "technique": technique,
                        "resisted": resisted, "note": note})

    pkl2 = pickle.dumps(_OsSystem())  # protocol-2 (0x80 0x02), strong magic

    # ---- resisted: disguise (magic beats a spoofed extension) ----
    (dest / "evil.onnx").write_bytes(pkl2)
    add("spoof-onnx", dest / "evil.onnx", "pickle payload under a .onnx extension", True,
        "magic bytes beat the spoofed extension")
    (dest / "weights.pb").write_bytes(pkl2)
    add("spoof-pb", dest / "weights.pb", "pickle payload under a .pb extension", True)

    d = dest / "docdir"
    d.mkdir(exist_ok=True)
    (d / "NOTICE.md").write_bytes(pkl2)
    add("spoof-docname", d, "pickle hidden under a doc filename in a directory", True,
        "directory walk sniffs magic bytes of skipped extensions")

    # ---- resisted: nested archive (recursive, depth-capped member scan) ----
    inner = dest / "_inner.zip"
    with zipfile.ZipFile(inner, "w") as z:
        z.writestr("model/data.pkl", pkl2)
        z.writestr("model/version", "3")
    outer = dest / "nested.zip"
    with zipfile.ZipFile(outer, "w") as z:
        z.writestr("bundle/inner.zip", inner.read_bytes())
    inner.unlink()
    add("nested-zip", outer, "malicious pickle inside a zip inside a zip", True)

    # ---- resisted: numpy object array wrapped in an .npz (zip) ----
    npz = dest / "arrs.npz"
    with zipfile.ZipFile(npz, "w") as z:
        z.writestr("arr_0.npy", _object_npy())
    add("npz-object", npz, "object-dtype numpy array (embedded pickle) inside an .npz", True)

    # ---- resisted: STACK_GLOBAL + module aliasing ----
    (dest / "stack.pkl").write_bytes(_stack_global_reduce("os", "system"))
    add("stack-global", dest / "stack.pkl", "STACK_GLOBAL opcode (protocol 4) callable resolution", True)
    (dest / "posix.pkl").write_bytes(_stack_global_reduce("posix", "system"))
    add("posix-alias", dest / "posix.pkl", "posix.system alias via STACK_GLOBAL", True)

    # ---- resisted: encoded / wide-string exfil ----
    (dest / "b32.bin").write_bytes(b"WGHT" + b"\x00" * 8 + base64.b32encode(_WEBHOOK))
    add("exfil-base32", dest / "b32.bin", "webhook encoded as base32", True)
    (dest / "hex.bin").write_bytes(b"WGHT" + b"\x00" * 8 + _WEBHOOK.hex().encode())
    add("exfil-hex", dest / "hex.bin", "webhook encoded as hex", True)
    (dest / "zlib.bin").write_bytes(
        b"WGHT" + b"\x00" * 8 + base64.b64encode(zlib.compress(_WEBHOOK)))
    add("exfil-b64zlib", dest / "zlib.bin", "webhook as base64(zlib(...))", True)
    (dest / "utf16.bin").write_bytes(b"WGHT" + b"\x00" * 8 + _WEBHOOK.decode().encode("utf-16-le"))
    add("exfil-utf16", dest / "utf16.bin", "webhook as a UTF-16 (wide) string", True)
    (dest / "b85.bin").write_bytes(b"WGHT" + b"\x00" * 8 + base64.b85encode(_WEBHOOK))
    add("exfil-base85", dest / "b85.bin", "webhook encoded as base85", True)
    (dest / "xor.bin").write_bytes(b"WGHT" + b"\x00" * 8 + _xor(_WEBHOOK))
    add("exfil-xor", dest / "xor.bin", "webhook obfuscated with a single-byte XOR key", True,
        "delta-signature search recovers the key, then confirms the decoded indicator")

    # ---- resisted: trust_remote_code with an encoded exec in the source ----
    trc = dest / "trc"
    trc.mkdir(exist_ok=True)
    (trc / "config.json").write_text(json.dumps(
        {"model_type": "x", "auto_map": {"AutoModel": "modeling_x.M"}}))
    (trc / "modeling_x.py").write_text(
        "import base64\nexec(base64.b64decode('aW1wb3J0IG9zCm9zLnN5c3RlbSgndHJ1ZScp'))\n")
    add("trc-b64-exec", trc, "auto_map source that base64-decodes then exec()s", True)

    # ---- resisted: source hiding exec behind getattr/__import__ + char codes ----
    (dest / "obf_source.py").write_text(
        "import builtins\n"
        "f = getattr(builtins, ''.join(chr(c) for c in (101,120,101,99)))\n"
        "f(getattr(__import__(''.join(chr(c) for c in (98,97,115,101,54,52))), 'b64decode')"
        "('aW1wb3J0IG9zCm9zLnN5c3RlbSgndHJ1ZScp').decode())\n")
    add("obf-source", dest / "obf_source.py",
        "source hiding exec behind getattr/__import__ + char-code assembly", True,
        "AST scanner flags getattr/__import__ indirection")

    # ---- resisted: dangerous callable aliased to a variable, then invoked ----
    (dest / "alias_source.py").write_text(
        "import os\nsink = os.system\nsink('true')\n")
    add("alias-callable", dest / "alias_source.py",
        "os.system aliased to a plain variable then invoked", True,
        "taint pass follows the alias — a literal name match sees only `sink(...)`")

    # ---- resisted: protocol-0 (ASCII) pickle under a structured extension ----
    (dest / "ascii.onnx").write_bytes(pickle.dumps(_OsSystem(), protocol=0))
    add("proto0-spoof-onnx", dest / "ascii.onnx",
        "protocol-0 (ASCII) pickle under a .onnx extension", True,
        "genops trial-parse routes it to the pickle scanner (real ONNX/pb start 0x08/0x0a)")

    # ================= known-open residuals (ROADMAP; not gated) =================
    (dest / "packed.bin").write_bytes(
        b"WGHT" + b"\x00" * 8 + struct.pack(">4sH", bytes([203, 0, 113, 7]), 4444))
    add("packed-endpoint", dest / "packed.bin", "C2 IP:port packed as raw bytes (no ASCII/UTF-16)", False,
        "packed-binary endpoints aren't extracted (ROADMAP)")
    return entries


def _detected(report) -> bool:
    ms = report.max_severity
    return bool(ms and ms.name in DETECTED)


def evaluate(policy: Policy) -> list[dict]:
    out = []
    for e in build(WORK):
        t = time.perf_counter()
        r = scan_target(e["path"], policy=policy)
        out.append({**e, "detected": _detected(r), "verdict": r.verdict.name,
                    "max_severity": r.max_severity.name if r.max_severity else None,
                    "rules": sorted({f.rule_id for f in r.all_findings}),
                    "seconds": round(time.perf_counter() - t, 4)})
    return out


def report(results: list[dict]) -> str:
    resisted = [r for r in results if r["resisted"]]
    known_open = [r for r in results if not r["resisted"]]
    det = sum(r["detected"] for r in resisted)
    recall = det / len(resisted) * 100 if resisted else 0.0
    caught_open = [r for r in known_open if r["detected"]]

    L = [
        "# Purser evasion resistance (Phase 3)",
        "",
        f"- Evasion recall on **resisted** techniques: **{recall:.1f}%** ({det}/{len(resisted)})",
        f"- Known-open residuals exercised: {len(known_open)} "
        f"({len(caught_open)} caught anyway, {len(known_open) - len(caught_open)} evaded — expected, tracked in ROADMAP)",
        "",
        "## Techniques Purser claims to resist (gated — must stay 100%)",
        "",
        "| Technique | Detected | Max severity | Example rules |",
        "|---|---|---|---|",
    ]
    for r in resisted:
        mark = "✅" if r["detected"] else "❌ **MISS**"
        L.append(f"| {r['technique']} | {mark} | {r['max_severity'] or '—'} | "
                 f"{', '.join(r['rules'][:2]) or '—'} |")
    L += [
        "",
        "## Known-open residuals (reported, not gated — see ROADMAP)",
        "",
        "| Technique | Outcome | Note |",
        "|---|---|---|",
    ]
    for r in known_open:
        outcome = "caught anyway ✅" if r["detected"] else "evaded (expected)"
        L.append(f"| {r['technique']} | {outcome} | {r['note']} |")
    L.append("")
    misses = [r for r in resisted if not r["detected"]]
    if misses:
        L += ["## ⚠️ Regressions (resisted techniques that now evade)", ""]
        L += [f"- `{r['id']}` — {r['technique']} (verdict {r['verdict']})" for r in misses]
        L.append("")
    return "\n".join(L)


def main() -> int:
    ap = argparse.ArgumentParser(description="Purser adversarial evasion suite")
    ap.add_argument("--policy", default=None)
    ap.add_argument("--min-recall", type=float, default=None,
                    help="fail (exit 1) if evasion recall on resisted techniques drops below this %%")
    args = ap.parse_args()
    policy = Policy.load(args.policy) if args.policy else Policy.default()

    results = evaluate(policy)
    RESULTS.mkdir(parents=True, exist_ok=True)
    (RESULTS / "evasion.json").write_text(json.dumps(results, indent=2))
    rep = report(results)
    (RESULTS / "evasion.md").write_text(rep)
    print(rep)

    resisted = [r for r in results if r["resisted"]]
    det = sum(r["detected"] for r in resisted)
    recall = det / len(resisted) * 100 if resisted else 0.0
    if args.min_recall is not None and recall < args.min_recall:
        missed = [r["id"] for r in resisted if not r["detected"]]
        print(f"\nEVASION GATE FAILED: recall {recall:.1f}% < floor {args.min_recall:.1f}% "
              f"(evaded: {', '.join(missed)})")
        return 1
    return 0


if __name__ == "__main__":
    # Measure the static core only: keep external signal sources out
    # of the published numbers (see benchmarks/README.md).
    os.environ.setdefault("PURSER_SIGNALS", "0")
    raise SystemExit(main())
