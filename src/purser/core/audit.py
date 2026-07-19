"""Structured audit logging.

Emits one JSON record per scan — target, verdict, severity counts, provenance,
duration, finding rule-ids — suitable for a SIEM. Output is controlled by env:

  PURSER_AUDIT           off | stdout | syslog   (default: off)
  PURSER_SYSLOG_ADDRESS  "/dev/log" (default) or "host:port" for a UDP collector
  PURSER_SYSLOG_FACILITY facility name (default: "user")

stdlib-only (``logging.handlers.SysLogHandler``); no external dependency.
"""

from __future__ import annotations

import json
import logging
import logging.handlers
from datetime import datetime, timezone

from purser.core.env import env_get
from purser.core.findings import ScanReport

_logger = logging.getLogger("purser.audit")
_logger.propagate = False
_current_mode: str | None = None


def _mode() -> str:
    return (env_get("AUDIT", "off") or "off").lower()


def _facility() -> int:
    name = (env_get("SYSLOG_FACILITY", "user") or "user").lower()
    return logging.handlers.SysLogHandler.facility_names.get(name, logging.handlers.SysLogHandler.LOG_USER)


def _configure(mode: str) -> None:
    """(Re)attach the handler matching the current mode."""
    global _current_mode
    if mode == _current_mode:
        return
    for h in list(_logger.handlers):
        _logger.removeHandler(h)
    if mode == "syslog":
        addr = env_get("SYSLOG_ADDRESS", "/dev/log") or "/dev/log"
        if ":" in addr:
            host, port = addr.rsplit(":", 1)
            address: object = (host, int(port))
        else:
            address = addr
        handler: logging.Handler = logging.handlers.SysLogHandler(
            address=address, facility=_facility()
        )
        handler.setFormatter(logging.Formatter("purser %(message)s"))
    elif mode == "stdout":
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter("%(message)s"))
    else:  # off
        handler = logging.NullHandler()
    _logger.addHandler(handler)
    _logger.setLevel(logging.INFO)
    _current_mode = mode


def build_record(report: ScanReport) -> dict:
    """The structured audit record for a scan (also handy for tests)."""
    max_sev = report.max_severity
    return {
        "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "event": "model_scan",
        "target": report.target,
        "verdict": report.verdict.value,
        "policy": report.policy_name,
        "origin": report.origin,
        "publisher": report.publisher,
        "provenance_verified": report.provenance_verified,
        "files": len(report.files),
        "severity_counts": report.severity_counts(),
        "max_severity": max_sev.name if max_sev is not None else None,
        "duration_seconds": round(report.duration_seconds, 3),
        "finding_rule_ids": sorted({f.rule_id for f in report.all_findings})[:20],
    }


def record_scan(report: ScanReport) -> None:
    """Emit the audit record if auditing is enabled; never raises."""
    mode = _mode()
    if mode not in ("stdout", "syslog"):
        return
    try:
        _configure(mode)
        _logger.info(json.dumps(build_record(report), separators=(",", ":")))
    except Exception:
        # auditing must never break a scan
        pass
