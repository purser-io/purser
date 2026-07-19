from pathlib import Path

from purser.core.findings import Severity
from purser.scanners.pickle_scanner import PickleScanner


def rules(findings):
    return {f.rule_id for f in findings}


def test_detects_os_system(evil_os_pickle: Path):
    findings = PickleScanner().scan(evil_os_pickle)
    dangerous = [f for f in findings if f.rule_id == "PICKLE_DANGEROUS_IMPORT"]
    assert dangerous, "os.system import must be flagged"
    assert any(f.severity == Severity.CRITICAL for f in dangerous)
    assert any(f.evidence.get("invoked") for f in dangerous), "REDUCE must mark invoked-on-load"


def test_detects_eval_protocol0(evil_eval_pickle_proto0: Path):
    findings = PickleScanner().scan(evil_eval_pickle_proto0)
    assert any(
        f.rule_id == "PICKLE_DANGEROUS_IMPORT" and f.severity == Severity.CRITICAL
        for f in findings
    )


def test_detects_network_exfil(evil_exfil_pickle: Path):
    findings = PickleScanner().scan(evil_exfil_pickle)
    hits = [f for f in findings if "exfiltration" in f.tags]
    assert hits, "urllib.request import must be tagged as exfiltration"


def test_benign_pickle_is_clean(benign_pickle: Path):
    findings = PickleScanner().scan(benign_pickle)
    assert not [f for f in findings if f.severity >= Severity.MEDIUM]


def test_stack_global_resolution():
    # Craft a protocol-4 style pickle manually using STACK_GLOBAL:
    # frame-less minimal stream: PROTO 4, SHORT_BINUNICODE 'os',
    # SHORT_BINUNICODE 'system', STACK_GLOBAL, STOP
    data = b"\x80\x04" + b"\x8c\x02os" + b"\x8c\x06system" + b"\x93" + b"."
    findings = PickleScanner().scan_bytes(data)
    assert any(
        f.rule_id == "PICKLE_DANGEROUS_IMPORT"
        and f.evidence.get("module") == "os"
        for f in findings
    )


def test_unknown_import_flagged():
    data = b"\x80\x04" + b"\x8c\x08weirdlib" + b"\x8c\x07doStuff" + b"\x93" + b"."
    findings = PickleScanner().scan_bytes(data)
    assert any(f.rule_id == "PICKLE_UNKNOWN_IMPORT" for f in findings)


def test_corrupt_pickle_flagged(tmp_path: Path):
    p = tmp_path / "junk.pkl"
    p.write_bytes(b"\x80\x04\xff\xff\xff\xff")
    findings = PickleScanner().scan(p)
    assert any(f.rule_id == "PICKLE_UNPARSEABLE" for f in findings)
