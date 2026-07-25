"""Regression guard for the Phase-3 adversarial evasion corpus.

The full evasion report lives in `benchmarks/evasion.py` (run in scheduled CI);
this pulls the same corpus into the unit suite so any regression in the
techniques Purser claims to resist fails a normal `pytest` run, not just the
weekly benchmark.
"""

from __future__ import annotations

import sys
from pathlib import Path

_BENCH = Path(__file__).resolve().parent.parent / "benchmarks"
if str(_BENCH) not in sys.path:
    sys.path.insert(0, str(_BENCH))

import evasion  # noqa: E402  (benchmarks/ added to path above)

from purser.core.policy import Policy  # noqa: E402
from purser.core.scanner import scan_target  # noqa: E402

_DETECTED = {"MEDIUM", "HIGH", "CRITICAL"}


def _detected(path: str) -> bool:
    ms = scan_target(path, policy=Policy.default()).max_severity
    return bool(ms and ms.name in _DETECTED)


def test_resisted_techniques_all_detected(tmp_path):
    entries = evasion.build(tmp_path)
    resisted = [e for e in entries if e["resisted"]]
    assert len(resisted) >= 12, "evasion corpus shrank unexpectedly"
    misses = [e["id"] for e in resisted if not _detected(e["path"])]
    assert not misses, f"evasion regression — resisted techniques now evading: {misses}"


def test_known_open_residuals_are_labeled(tmp_path):
    # The suite must keep exercising the documented residuals so the frontier
    # stays measured; they are not asserted detected (that's the point).
    entries = evasion.build(tmp_path)
    open_ids = {e["id"] for e in entries if not e["resisted"]}
    assert {"exfil-base85", "exfil-xor", "packed-endpoint"} <= open_ids
