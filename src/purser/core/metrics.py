"""Prometheus metrics — a tiny in-process registry (no external dependency).

Domain-specific series for an ML-model security scanner, chosen to drive useful
Prometheus/Grafana panels: outcomes by verdict, threats by category, scans by
model format, policy blocks by reason, signature/provenance outcomes, origin
country, throughput, errors, and live concurrency. Thread-safe.
"""

from __future__ import annotations

import threading

from purser import __version__
from purser.core.findings import ScanReport

_LOCK = threading.Lock()

# Ascending, cumulative histogram buckets (seconds).
_BUCKETS: tuple[float, ...] = (0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60)

# rule_id -> policy-block reason (label value)
_BLOCK_REASON = {
    "POLICY_ORIGIN_BLOCKED": "origin",
    "POLICY_ORIGIN_UNKNOWN": "origin_unknown",
    "POLICY_FORMAT_BLOCKED": "format",
    "POLICY_PUBLISHER_BLOCKED": "publisher",
    "POLICY_PUBLISHER_NOT_ALLOWED": "publisher",
    "POLICY_MODEL_BLOCKED": "name",
    "POLICY_MODEL_NOT_ALLOWED": "name",
    "POLICY_SIGNATURE_REQUIRED": "signature",
}
_ERROR_RULES = {"SCANNER_ERROR", "DEEP_UNAVAILABLE", "DEEP_ANALYZER_ERROR", "PY_UNREADABLE"}

_scans: dict[str, int] = {}          # verdict -> count
_sev: dict[str, int] = {}            # severity -> count
_cat: dict[str, int] = {}            # threat category (finding tag) -> count
_fmt: dict[str, int] = {}            # model format -> file count
_blocks: dict[str, int] = {}         # policy block reason -> count
_prov: dict[str, int] = {}           # signature/provenance status -> count
_origin: dict[str, int] = {}         # origin country code -> count
_rejects: dict[str, int] = {}        # API request rejection reason -> count
_bytes = 0
_errors = 0
_inflight = 0
_dur_bucket: dict[float, int] = {b: 0 for b in _BUCKETS}
_dur_sum = 0.0
_dur_count = 0


def reset() -> None:
    """Clear all metrics (used by tests)."""
    global _bytes, _errors, _inflight, _dur_sum, _dur_count
    with _LOCK:
        for d in (_scans, _sev, _cat, _fmt, _blocks, _prov, _origin, _rejects):
            d.clear()
        for b in _BUCKETS:
            _dur_bucket[b] = 0
        _bytes = _errors = _inflight = 0
        _dur_sum = 0.0
        _dur_count = 0


def record_scan(report: ScanReport) -> None:
    global _bytes, _errors, _dur_sum, _dur_count
    with _LOCK:
        _scans[report.verdict.value] = _scans.get(report.verdict.value, 0) + 1
        for sev, count in report.severity_counts().items():
            if count:
                _sev[sev] = _sev.get(sev, 0) + count
        for fr in report.files:
            _fmt[fr.format] = _fmt.get(fr.format, 0) + 1
            _bytes += max(0, fr.size)
            if fr.error:
                _errors += 1
        for f in report.all_findings:
            cat = f.tags[0] if f.tags else "other"
            _cat[cat] = _cat.get(cat, 0) + 1
            if f.rule_id in _ERROR_RULES:
                _errors += 1
        for f in report.policy_findings:
            reason = _BLOCK_REASON.get(f.rule_id)
            if reason:
                _blocks[reason] = _blocks.get(reason, 0) + 1
        status = str(report.metadata.get("signature_status", "unknown")) or "unknown"
        _prov[status] = _prov.get(status, 0) + 1
        origin = (report.origin or "unknown").upper()
        _origin[origin] = _origin.get(origin, 0) + 1
        d = float(report.duration_seconds)
        _dur_sum += d
        _dur_count += 1
        for b in _BUCKETS:
            if d <= b:
                _dur_bucket[b] += 1


def inc_inflight() -> None:
    global _inflight
    with _LOCK:
        _inflight += 1


def dec_inflight() -> None:
    global _inflight
    with _LOCK:
        _inflight = max(0, _inflight - 1)


def reject(reason: str) -> None:
    with _LOCK:
        _rejects[reason] = _rejects.get(reason, 0) + 1


def _block(name: str, help_: str, mtype: str, label: str, data: dict[str, int]) -> list[str]:
    out = [f"# HELP {name} {help_}", f"# TYPE {name} {mtype}"]
    for key, val in sorted(data.items()):
        out.append(f'{name}{{{label}="{key}"}} {val}')
    return out


def render() -> str:
    with _LOCK:
        snap = {
            "scans": dict(_scans), "sev": dict(_sev), "cat": dict(_cat),
            "fmt": dict(_fmt), "blocks": dict(_blocks), "prov": dict(_prov),
            "origin": dict(_origin), "rejects": dict(_rejects),
            "bytes": _bytes, "errors": _errors, "inflight": _inflight,
            "buckets": dict(_dur_bucket), "dsum": _dur_sum, "dcount": _dur_count,
        }
    # ensure the common verdict/severity label values always appear (for stable
    # Grafana panels even before any scan of that type).
    for v in ("PASS", "WARN", "FAIL", "BLOCKED", "ERROR"):
        snap["scans"].setdefault(v, 0)
    for s in ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"):
        snap["sev"].setdefault(s, 0)

    lines: list[str] = [
        "# HELP purser_build_info Build information.",
        "# TYPE purser_build_info gauge",
        f'purser_build_info{{version="{__version__}"}} 1',
    ]
    lines += _block("purser_scans_total", "Scans completed, by verdict.", "counter", "verdict", snap["scans"])
    lines += _block("purser_findings_total", "Findings emitted, by severity.", "counter", "severity", snap["sev"])
    lines += _block("purser_findings_by_category_total", "Findings by threat category (finding tag).", "counter", "category", snap["cat"])
    lines += _block("purser_scan_files_total", "Files scanned, by detected model format.", "counter", "format", snap["fmt"])
    lines += _block("purser_policy_blocks_total", "Policy blocks, by reason.", "counter", "reason", snap["blocks"])
    lines += _block("purser_provenance_total", "Scans by signature/provenance status.", "counter", "status", snap["prov"])
    lines += _block("purser_scans_by_origin_total", "Scans by country of origin.", "counter", "origin", snap["origin"])
    lines += _block("purser_requests_rejected_total", "API requests rejected, by reason.", "counter", "reason", snap["rejects"])

    lines += [
        "# HELP purser_bytes_scanned_total Total bytes across scanned files.",
        "# TYPE purser_bytes_scanned_total counter",
        f"purser_bytes_scanned_total {snap['bytes']}",
        "# HELP purser_scan_errors_total Scanner/analyzer errors encountered.",
        "# TYPE purser_scan_errors_total counter",
        f"purser_scan_errors_total {snap['errors']}",
        "# HELP purser_scans_in_progress Scans currently running.",
        "# TYPE purser_scans_in_progress gauge",
        f"purser_scans_in_progress {snap['inflight']}",
        "# HELP purser_scan_duration_seconds Scan wall-clock duration.",
        "# TYPE purser_scan_duration_seconds histogram",
    ]
    for b in _BUCKETS:
        le = repr(b) if b != int(b) else str(int(b))
        lines.append(f'purser_scan_duration_seconds_bucket{{le="{le}"}} {snap["buckets"][b]}')
    lines.append(f'purser_scan_duration_seconds_bucket{{le="+Inf"}} {snap["dcount"]}')
    lines.append(f"purser_scan_duration_seconds_sum {snap['dsum']}")
    lines.append(f"purser_scan_duration_seconds_count {snap['dcount']}")
    return "\n".join(lines) + "\n"
