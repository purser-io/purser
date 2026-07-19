"""Data-exfiltration and embedded-secret detection.

Extracts printable strings from model binaries and matches indicators:
outbound endpoints (URLs, webhooks, IP:port), credentials (cloud keys,
private keys, tokens), and encoded payloads (base64 blobs that decode to
text/code). Model weights are high-entropy, so every pattern requires
structural validation to keep the false-positive rate down — a bare
entropy heuristic is deliberately not used.
"""

from __future__ import annotations

import base64
import binascii
import gzip
import re
import zlib
from pathlib import Path

from purser.core.findings import Finding, Severity
from purser.scanners.base import Scanner
from purser.core.env import env_get

# Total bytes scanned per file before we stop and report truncation.
# Overridable so large-model deployments can raise it.
MAX_SCAN_BYTES = int(env_get("MAX_SCAN_MB", "4096")) * 1024 * 1024
WINDOW_BYTES = 64 * 1024 * 1024      # read/scan the file in windows of this size
WINDOW_OVERLAP = 4096                # carry-over so indicators can't hide on a seam
STRING_MIN_LEN = 8

# Cap on distinct findings emitted per file — bounds memory/output on
# adversarial inputs crafted to explode the finding set (item 7).
MAX_FINDINGS = int(env_get("MAX_FINDINGS_PER_FILE", "500"))

_STRINGS_RE = re.compile(rb"[\x20-\x7e]{%d,}" % STRING_MIN_LEN)
# UTF-16 (wide) printable runs — a common way to hide ASCII indicators
# (Windows payloads, deliberate evasion) from a byte-level ASCII string scan.
_WIDE_LE_RE = re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % STRING_MIN_LEN)
_WIDE_BE_RE = re.compile(rb"(?:\x00[\x20-\x7e]){%d,}" % STRING_MIN_LEN)

URL_RE = re.compile(
    r"\b(?:https?|ftp|wss?)://[a-zA-Z0-9\-._~%]+(?::\d+)?(?:/[^\s\"'<>{}|\\^`\[\]]*)?",
)
IP_PORT_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d):(\d{2,5})\b"
)
# No trailing \b: it would exclude the '='-padding (a non-word char), leaving a
# fragment that fails to decode. Greedy padding capture handles it instead.
BASE64_RE = re.compile(r"\b[A-Za-z0-9+/]{64,}={0,2}")
HEX_RE = re.compile(r"\b(?:[0-9a-fA-F]{2}){32,}\b")  # >=64 hex chars
BASE32_RE = re.compile(r"\b[A-Z2-7]{64,}={0,6}")     # RFC 4648 base32

BENIGN_URL_HOSTS = (
    "github.com", "raw.githubusercontent.com", "huggingface.co", "hf.co",
    "arxiv.org", "pytorch.org", "tensorflow.org", "keras.io", "www.w3.org",
    "opensource.org", "apache.org", "creativecommons.org", "example.com",
    "schemas.android.com", "json-schema.org", "docs.python.org", "python.org",
    "wikipedia.org", "en.wikipedia.org", "openai.com", "medium.com", "ns.adobe.com",
)

WEBHOOK_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("Slack webhook", re.compile(r"hooks\.slack\.com/services/T[A-Za-z0-9]+/B[A-Za-z0-9]+")),
    ("Discord webhook", re.compile(r"discord(?:app)?\.com/api/webhooks/\d+/")),
    ("Telegram bot API", re.compile(r"api\.telegram\.org/bot\d+:[A-Za-z0-9_-]+")),
]

SECRET_PATTERNS: list[tuple[str, re.Pattern[str], Severity]] = [
    ("AWS access key ID", re.compile(r"\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b"), Severity.CRITICAL),
    ("Private key material", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"), Severity.CRITICAL),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"), Severity.CRITICAL),
    ("Slack token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), Severity.CRITICAL),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"), Severity.HIGH),
    ("HuggingFace token", re.compile(r"\bhf_[A-Za-z0-9]{34,}\b"), Severity.HIGH),
    ("OpenAI API key", re.compile(r"\bsk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}\b"), Severity.CRITICAL),
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"), Severity.MEDIUM),
]

CODE_INDICATORS: list[tuple[str, re.Pattern[str], Severity]] = [
    ("network client call", re.compile(r"\b(?:requests\.(?:post|get|put)|urllib\.request\.urlopen|urlopen\(|socket\.socket|http\.client)"), Severity.HIGH),
    ("dynamic code execution", re.compile(r"\b(?:exec|eval)\s*\(|__import__\s*\(|compile\s*\("), Severity.HIGH),
    ("shell command", re.compile(r"\bos\.(?:system|popen|exec[lv]p?e?)\s*\(|subprocess\.(?:run|call|Popen|check_output)"), Severity.HIGH),
    ("reverse-shell idiom", re.compile(r"/dev/tcp/|nc -e |bash -i >& |sh -i >&"), Severity.CRITICAL),
    ("env-var harvesting", re.compile(r"os\.environ|getenv\s*\("), Severity.MEDIUM),
]


def iter_strings(data: bytes):
    """Yield printable strings from data: ASCII runs plus UTF-16 (wide) runs.

    A generator so callers can stream over a large window without materializing
    every string at once (item 7). Wide-string extraction (item 8) catches
    indicators deliberately hidden from an ASCII-only scan.
    """
    for m in _STRINGS_RE.finditer(data):
        yield m.group().decode("ascii", "replace")
    for m in _WIDE_LE_RE.finditer(data):
        yield m.group().decode("utf-16-le", "replace")
    for m in _WIDE_BE_RE.finditer(data):
        yield m.group().decode("utf-16-be", "replace")


def extract_strings(data: bytes) -> list[str]:
    return list(iter_strings(data))


def _strict_mode() -> bool:
    return env_get("EXFIL_STRICT", "").lower() in ("1", "true", "yes")


def _benign_hosts() -> tuple[str, ...]:
    """Effective benign-host allowlist. Extendable/replaceable via env so an
    operator can close the 'allowlisted host as exfil channel' gap (item 8):
      * PURSER_EXFIL_STRICT=1 -> no allowlist (every URL is flagged)
      * PURSER_EXFIL_ALLOWLIST=a.com,b.com -> use ONLY these hosts
      * PURSER_EXFIL_ALLOWLIST_ADD=c.com -> add to the built-in list
    """
    if _strict_mode():
        return ()
    override = env_get("EXFIL_ALLOWLIST")
    if override is not None:
        return tuple(h.strip().lower() for h in override.split(",") if h.strip())
    extra = env_get("EXFIL_ALLOWLIST_ADD", "")
    additions = tuple(h.strip().lower() for h in extra.split(",") if h.strip())
    return BENIGN_URL_HOSTS + additions


def _is_benign_url(url: str, allowed: tuple[str, ...] | None = None) -> bool:
    if allowed is None:
        allowed = _benign_hosts()
    if not allowed:
        return False
    m = re.match(r"^[a-z]+://([^/:]+)", url, re.IGNORECASE)
    if not m:
        return False
    host = m.group(1).lower()
    return any(host == b or host.endswith("." + b) for b in allowed)


def _decoded_text_verdict(raw: bytes) -> tuple[Severity, str] | None:
    """Given decoded bytes, decide whether the plaintext looks like a payload."""
    if not raw:
        return None
    printable = sum(1 for b in raw if 0x20 <= b <= 0x7E or b in (0x09, 0x0A, 0x0D))
    if printable / len(raw) < 0.85:
        return None  # decodes to binary noise — almost certainly weight data
    text = raw.decode("ascii", "replace")
    for label, pattern, _sev in CODE_INDICATORS:
        if pattern.search(text):
            return (Severity.CRITICAL, f"decodes to text containing a {label}")
    if URL_RE.search(text) and not all(_is_benign_url(u) for u in URL_RE.findall(text)):
        return (Severity.HIGH, "decodes to text containing a non-allowlisted URL")
    if "import " in text or "#!/" in text:
        return (Severity.HIGH, "decodes to script-like text")
    return (Severity.LOW, "decodes to readable text (possible encoded payload)")


def _maybe_decompress(raw: bytes) -> bytes | None:
    """If raw is a gzip/zlib stream, return the decompressed bytes, else None."""
    if raw[:2] == b"\x1f\x8b":  # gzip magic
        try:
            return gzip.decompress(raw)
        except (OSError, EOFError, zlib.error):
            return None
    if raw[:1] == b"\x78" and raw[1:2] in (b"\x01", b"\x9c", b"\xda"):  # zlib
        try:
            return zlib.decompress(raw)
        except zlib.error:
            return None
    return None


def _decoded_text_verdict_layered(raw: bytes) -> tuple[Severity, str] | None:
    """Analyze decoded bytes, transparently peeling one gzip/zlib layer."""
    inner = _maybe_decompress(raw)
    if inner is not None:
        verdict = _decoded_text_verdict(inner)
        if verdict is not None:
            sev, why = verdict
            return (sev, f"decompresses then {why}")
        return None
    return _decoded_text_verdict(raw)


def _decoded_payload_verdict(blob: str) -> tuple[Severity, str] | None:
    try:
        raw = base64.b64decode(blob, validate=True)
    except (binascii.Error, ValueError):
        return None
    return _decoded_text_verdict_layered(raw)


def _decoded_hex_verdict(blob: str) -> tuple[Severity, str] | None:
    try:
        raw = binascii.unhexlify(blob)
    except (binascii.Error, ValueError):
        return None
    return _decoded_text_verdict_layered(raw)


def _decoded_b32_verdict(blob: str) -> tuple[Severity, str] | None:
    try:
        raw = base64.b32decode(blob)
    except (binascii.Error, ValueError):
        return None
    return _decoded_text_verdict_layered(raw)


class ExfilScanner(Scanner):
    """Scans raw file bytes for exfiltration indicators. Format-agnostic."""

    name = "exfil"

    def scan(self, path: Path) -> list[Finding]:
        size = path.stat().st_size
        findings: list[Finding] = []
        seen_keys: set[tuple] = set()
        scanned = 0
        carry = b""
        with open(path, "rb") as fh:
            while scanned < MAX_SCAN_BYTES:
                chunk = fh.read(min(WINDOW_BYTES, MAX_SCAN_BYTES - scanned))
                if not chunk:
                    break
                scanned += len(chunk)
                window = carry + chunk
                for f in self.scan_bytes(window):
                    # dedup across windows (the overlap re-sees seam strings)
                    key = (f.rule_id, tuple(sorted(f.evidence.items())))
                    if key in seen_keys:
                        continue
                    seen_keys.add(key)
                    findings.append(f)
                carry = window[-WINDOW_OVERLAP:]
        if size > scanned:
            findings.append(self.finding(
                "SCAN_TRUNCATED", Severity.MEDIUM,
                "File larger than the exfiltration scan limit — tail not scanned",
                f"Scanned the first {scanned} of {size} bytes "
                f"(limit PURSER_MAX_SCAN_MB={MAX_SCAN_BYTES // (1024 * 1024)} MB). "
                "Content beyond the limit was not inspected; raise the limit to "
                "scan it fully.",
                tags=["coverage-gap"],
                evidence={"scanned_bytes": scanned, "file_bytes": size},
            ))
        return findings

    def scan_bytes(self, data: bytes) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[tuple[str, str]] = set()
        allowed = _benign_hosts()

        def add(rule_id: str, severity: Severity, title: str, detail: str,
                tags: list[str], key: str, evidence: dict) -> None:
            if (rule_id, key) in seen or len(findings) >= MAX_FINDINGS:
                return
            seen.add((rule_id, key))
            findings.append(self.finding(rule_id, severity, title, detail,
                                         tags=tags, evidence=evidence))

        # Stream over strings (generator) rather than building a full list, and
        # stop early once the finding cap is hit — bounds memory on hostile input.
        for s in iter_strings(data):
            if len(findings) >= MAX_FINDINGS:
                break
            for label, pattern in WEBHOOK_PATTERNS:
                for m in pattern.finditer(s):
                    add("EXFIL_WEBHOOK", Severity.CRITICAL,
                        f"{label} endpoint embedded in model data",
                        "Webhook endpoints inside model binaries are a common "
                        "data-exfiltration channel.",
                        ["exfiltration", "network"], m.group()[:120],
                        {"match": m.group()[:200]})

            for m in URL_RE.finditer(s):
                url = m.group()
                if _is_benign_url(url, allowed):
                    continue
                add("EXFIL_URL", Severity.MEDIUM,
                    "Non-allowlisted URL embedded in model data",
                    "Model weights should not need to reference external endpoints. "
                    "Verify this URL is expected for this model.",
                    ["exfiltration", "network"], url[:120], {"url": url[:300]})

            for m in IP_PORT_RE.finditer(s):
                port = int(m.group(1))
                if port in (80, 443, 8080) or port > 10:
                    add("EXFIL_IP_ENDPOINT", Severity.HIGH,
                        f"Hard-coded IP:port endpoint `{m.group()}` in model data",
                        "Hard-coded socket endpoints in model files indicate "
                        "call-home or reverse-shell behavior.",
                        ["exfiltration", "network"], m.group(), {"endpoint": m.group()})

            for label, pattern, sev in SECRET_PATTERNS:
                for m in pattern.finditer(s):
                    add("EXFIL_SECRET", sev,
                        f"{label} embedded in model data",
                        "Credentials inside a model artifact indicate either a "
                        "data leak or staged exfiltration material.",
                        ["secret"], m.group()[:64], {"type": label, "match": m.group()[:80]})

            for label, pattern, sev in CODE_INDICATORS:
                for m in pattern.finditer(s):
                    add("EXFIL_CODE_INDICATOR", sev,
                        f"Embedded source code with {label}",
                        f"Found `{m.group()[:80]}` inside model data — model "
                        "artifacts should not contain executable source.",
                        ["code-execution"], f"{label}:{m.group()[:60]}",
                        {"indicator": label, "match": m.group()[:200]})

            for m in BASE64_RE.finditer(s):
                verdict = _decoded_payload_verdict(m.group())
                if verdict is None:
                    continue
                sev, why = verdict
                add("EXFIL_ENCODED_PAYLOAD", sev,
                    f"Base64 blob in model data ({why})",
                    "Long base64 strings that decode cleanly to text are a "
                    "common obfuscation layer for payloads or staged data.",
                    ["obfuscation"], m.group()[:48], {"reason": why, "sample": m.group()[:96]})

            for m in HEX_RE.finditer(s):
                verdict = _decoded_hex_verdict(m.group())
                if verdict is None:
                    continue
                sev, why = verdict
                add("EXFIL_ENCODED_PAYLOAD", sev,
                    f"Hex-encoded blob in model data ({why})",
                    "Long hex strings that decode cleanly to text are a common "
                    "obfuscation layer for payloads or staged data.",
                    ["obfuscation"], m.group()[:48], {"reason": why, "sample": m.group()[:96]})

            for m in BASE32_RE.finditer(s):
                verdict = _decoded_b32_verdict(m.group())
                if verdict is None:
                    continue
                sev, why = verdict
                add("EXFIL_ENCODED_PAYLOAD", sev,
                    f"Base32-encoded blob in model data ({why})",
                    "Long base32 strings that decode cleanly to text are a common "
                    "obfuscation layer for payloads or staged data.",
                    ["obfuscation"], m.group()[:48], {"reason": why, "sample": m.group()[:96]})

        return findings
