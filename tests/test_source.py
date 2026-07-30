"""Tests for the bundled-Python (trust_remote_code) and HF-config scanners."""

import json
import textwrap
from pathlib import Path

from purser.core.dispatch import scan_file
from purser.core.findings import Severity, Verdict
from purser.core.formats import ModelFormat, detect_format
from purser.core.scanner import iter_scannable, scan_target
from purser.scanners.source import PythonSourceScanner


def scan_py(src: str) -> list:
    return PythonSourceScanner().scan_source(textwrap.dedent(src))


def rules(findings):
    return {f.rule_id for f in findings}


# -- detection ---------------------------------------------------------------

def test_py_detected(tmp_path: Path):
    p = tmp_path / "modeling_x.py"
    p.write_text("import torch\n")
    assert detect_format(p) == ModelFormat.PYTHON_SOURCE


def test_config_json_detected(tmp_path: Path):
    p = tmp_path / "config.json"
    p.write_text("{}")
    assert detect_format(p) == ModelFormat.HF_CONFIG


# -- dangerous calls ---------------------------------------------------------

def test_os_system_on_import_is_critical():
    findings = scan_py("import os\nos.system('id')\n")
    hit = [f for f in findings if f.rule_id == "PY_DANGEROUS_CALL"]
    assert hit and hit[0].severity == Severity.CRITICAL
    assert hit[0].evidence["on_import"] is True
    assert "on-import" in hit[0].tags


def test_call_inside_function_still_flagged_not_on_import():
    findings = scan_py("""
        import subprocess
        def forward(self, x):
            subprocess.run(['sh', '-c', 'x'])
            return x
    """)
    hit = [f for f in findings if f.rule_id == "PY_DANGEROUS_CALL"]
    assert hit
    assert all(f.evidence["on_import"] is False for f in hit)


def test_exec_and_eval():
    assert "PY_DANGEROUS_CALL" in rules(scan_py("exec('x=1')\n"))
    assert "PY_DANGEROUS_CALL" in rules(scan_py("eval('1+1')\n"))


def test_network_calls():
    findings = scan_py("import requests\nrequests.post('http://x/y', data={})\n")
    assert any(f.evidence.get("call", "").startswith("requests.") for f in findings)


def test_dynamic_import_and_getattr_indirection():
    findings = scan_py("""
        import importlib
        m = importlib.import_module('o'+'s')
        getattr(m, 'sys'+'tem')('id')
    """)
    ids = rules(findings)
    assert "PY_DANGEROUS_CALL" in ids
    assert any("indirection" in f.tags for f in findings)


def test_base64_exec_obfuscation_escalated():
    findings = scan_py("""
        import base64
        exec(base64.b64decode('cHJpbnQoMSk='))
    """)
    decoder = [f for f in findings if "obfuscation" in f.tags]
    assert decoder and decoder[0].severity == Severity.HIGH


def test_base64_without_exec_not_flagged():
    findings = scan_py("import base64\nx = base64.b64decode('aGVsbG8=')\n")
    assert not [f for f in findings if "obfuscation" in f.tags]


def test_env_harvest():
    findings = scan_py("import os\ntoken = os.environ['HF_TOKEN']\n")
    assert "PY_ENV_HARVEST" in rules(findings)


def test_benign_modeling_py_is_clean():
    findings = scan_py("""
        import torch
        import torch.nn as nn

        class MyModel(nn.Module):
            def __init__(self, cfg):
                super().__init__()
                self.lin = nn.Linear(cfg.h, cfg.h)

            def forward(self, x):
                return self.lin(x)
    """)
    assert not [f for f in findings if f.severity >= Severity.MEDIUM]


def test_syntax_error_flagged():
    findings = scan_py("def broken(:\n")
    assert "PY_UNPARSEABLE" in rules(findings)


# -- taint / dataflow (runtime-assembled & aliased payloads) -----------------

def _taint(findings):
    return {f.rule_id for f in findings} & {"PY_DYNAMIC_CALL", "PY_TAINTED_FLOW"}


def test_taint_alias_of_dangerous_callable():
    # `sink = os.system; sink(...)` — the literal name match sees only an
    # assignment and a call to `sink`; the taint pass follows the alias.
    findings = scan_py("import os\nsink = os.system\nsink('id')\n")
    hit = [f for f in findings if f.rule_id == "PY_DYNAMIC_CALL"]
    assert hit and hit[0].severity == Severity.CRITICAL
    assert hit[0].evidence["on_import"] is True
    assert "taint" in hit[0].tags and "on-import" in hit[0].tags


def test_taint_alias_of_alias():
    findings = scan_py("import os\na = os.system\nb = a\nb('id')\n")
    assert "PY_DYNAMIC_CALL" in rules(findings)


def test_taint_dynamic_getattr_from_assembled_name():
    # os.system resolved via a char-code-assembled getattr name, then invoked.
    findings = scan_py(
        "import os\nname = bytes([115,121,115,116,101,109]).decode()\n"
        "getattr(os, name)('id')\n")
    hit = [f for f in findings if f.rule_id == "PY_DYNAMIC_CALL"]
    assert hit and hit[0].severity == Severity.CRITICAL


def test_taint_two_step_dynamic_callable():
    findings = scan_py(
        "import os\nn = ''.join(chr(c) for c in (115,121,115,116,101,109))\n"
        "fn = getattr(os, n)\nfn('id')\n")
    assert "PY_DYNAMIC_CALL" in rules(findings)


def test_taint_deobfuscated_payload_into_exec_inline():
    findings = scan_py("import base64\nexec(base64.b64decode('cHJpbnQoMSk='))\n")
    hit = [f for f in findings if f.rule_id == "PY_TAINTED_FLOW"]
    assert hit and hit[0].severity == Severity.CRITICAL


def test_taint_decoded_arg_into_os_system():
    findings = scan_py(
        "import base64, os\ncmd = base64.b64decode(BLOB).decode()\nos.system(cmd)\n")
    hit = [f for f in findings if f.rule_id == "PY_TAINTED_FLOW"]
    assert hit and hit[0].severity == Severity.CRITICAL
    assert hit[0].evidence["arg_tainted"] is True


def test_taint_flow_inside_function_not_on_import():
    findings = scan_py("""
        import os
        def load(self):
            sink = os.system
            sink('id')
    """)
    hit = [f for f in findings if f.rule_id == "PY_DYNAMIC_CALL"]
    assert hit and all(f.evidence["on_import"] is False for f in hit)


# -- taint: false-positive guards (benign patterns must stay clean) ----------

def test_taint_benign_dynamic_getattr_not_flagged():
    # The ubiquitous benign pattern: resolve a layer/activation by a plain name.
    findings = scan_py("""
        def build(nn, name, x):
            act = getattr(nn, name)
            return act(x)
    """)
    assert not _taint(findings)


def test_taint_benign_decode_into_non_sink():
    findings = scan_py("import base64\nw = base64.b64decode(BLOB)\nmodel.load(w)\n")
    assert not _taint(findings)


def test_taint_benign_alias_of_safe_callable():
    findings = scan_py("fn = self.forward\nfn(x)\n")
    assert not _taint(findings)


def test_taint_benign_string_concat_and_bytes_construction():
    findings = scan_py("""
        p = 'models/' + 'weights.bin'
        header = bytes([0, 0, 0, 1])
        open(p, 'rb').write(header)
    """)
    assert not _taint(findings)


# -- HF config auto_map ------------------------------------------------------

def test_auto_map_via_scan(tmp_path: Path):
    p = tmp_path / "config.json"
    p.write_text(json.dumps({
        "auto_map": {"AutoModel": "modeling_my.MyModel"},
    }))
    _, findings = scan_file(p)
    hit = [f for f in findings if f.rule_id == "HF_CONFIG_REMOTE_CODE"]
    assert hit and hit[0].severity == Severity.HIGH
    assert "modeling_my.MyModel" in hit[0].evidence["targets"]


def test_benign_config_clean(tmp_path: Path):
    p = tmp_path / "config.json"
    p.write_text(json.dumps({"hidden_size": 768, "num_layers": 12}))
    _, findings = scan_file(p)
    assert not [f for f in findings if f.severity >= Severity.MEDIUM]


# -- integration -------------------------------------------------------------

def test_directory_scan_includes_py_and_config(tmp_path: Path):
    (tmp_path / "modeling_evil.py").write_text("import os\nos.system('id')\n")
    (tmp_path / "config.json").write_text(json.dumps(
        {"auto_map": {"AutoModel": "modeling_evil.Evil"}}))
    (tmp_path / "model.safetensors").write_bytes(b"\x00" * 16)
    names = [Path(p).name for p in iter_scannable(tmp_path)]
    assert "modeling_evil.py" in names
    assert "config.json" in names

    report = scan_target(tmp_path)
    ids = {f.rule_id for f in report.all_findings}
    assert "PY_DANGEROUS_CALL" in ids
    assert "HF_CONFIG_REMOTE_CODE" in ids
    assert report.verdict in (Verdict.FAIL, Verdict.BLOCKED)
