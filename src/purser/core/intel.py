"""End-user intel updates — the `freshclam` analogue for the loader-CVE dataset.

The vendored dataset ships frozen at release time; the repo refreshes weekly,
but a pip/container user shouldn't have to upgrade Purser to get this week's
loader CVEs. `purser update-intel` fetches the latest dataset over HTTPS into
a user-local path that the `loader-cves` source prefers over the vendored
copy:

    resolution order:  PURSER_LOADER_CVES (explicit)
                       → ~/.purser/loader_cves.yaml (updated via this module)
                       → the vendored dataset (ships with the package)

Design constraints, kept deliberately:
  * **Never at scan time.** Fetching happens only when the user runs
    `purser update-intel` — scans stay offline; a stale dataset degrades to
    a *hint*, never a network call.
  * **Data, not code.** The fetched file is parsed as YAML, schema-validated
    (every entry needs cve/framework/affected), and atomically written;
    nothing in it is ever executed. A file that fails validation is rejected
    and the previous dataset stays in place.
  * **Air-gap friendly.** `PURSER_INTEL_URL` can point at an internal mirror;
    or skip the command entirely and drop a file via `PURSER_LOADER_CVES`.
"""

from __future__ import annotations

import re
import urllib.request
from datetime import date, datetime
from pathlib import Path

import yaml

from purser.core.env import env_get

DEFAULT_INTEL_URL = ("https://raw.githubusercontent.com/purser-io/purser/"
                     "main/src/purser/data/loader_cves.yaml")

_REFRESH_RE = re.compile(r"Last refreshed:\s*(\d{4}-\d{2}-\d{2})")
STALE_AFTER_DAYS = 90


def intel_url() -> str:
    return env_get("INTEL_URL", DEFAULT_INTEL_URL) or DEFAULT_INTEL_URL


def user_intel_path() -> Path:
    base = env_get("INTEL_DIR", "")
    root = Path(base) if base else Path.home() / ".purser"
    return root / "loader_cves.yaml"


def validate_dataset(text: str) -> list[dict]:
    """Parse + schema-check a dataset; raises ValueError on anything off."""
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ValueError(f"not valid YAML: {exc}") from exc
    if not isinstance(data, list) or not data:
        raise ValueError("dataset must be a non-empty list of entries")
    entries = []
    for i, e in enumerate(data):
        if not isinstance(e, dict):
            raise ValueError(f"entry {i} is not a mapping")
        for key in ("cve", "framework", "affected"):
            if not e.get(key):
                raise ValueError(f"entry {i} missing required key {key!r}")
        entries.append(e)
    return entries


def refreshed_on(text: str) -> date | None:
    m = _REFRESH_RE.search(text)
    if not m:
        return None
    try:
        return datetime.strptime(m.group(1), "%Y-%m-%d").date()
    except ValueError:
        return None


def update(url: str | None = None, dest: Path | None = None) -> dict:
    """Fetch, validate, atomically install. Returns a summary dict."""
    url = url or intel_url()
    dest = dest or user_intel_path()
    req = urllib.request.Request(url, headers={"Accept": "text/plain"})
    with urllib.request.urlopen(req, timeout=30) as resp:  # nosec B310
        text = resp.read().decode()
    entries = validate_dataset(text)
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_suffix(".tmp")
    tmp.write_text(text)
    tmp.replace(dest)
    stamp = refreshed_on(text)
    return {"path": str(dest), "entries": len(entries),
            "refreshed": stamp.isoformat() if stamp else "unknown",
            "url": url}


def active_dataset() -> tuple[str, str]:
    """(description, text) of the dataset the loader-cves source will use."""
    override = env_get("LOADER_CVES", "")
    if override:
        return f"env:{override}", Path(override).read_text()
    user = user_intel_path()
    if user.exists():
        return f"user:{user}", user.read_text()
    from importlib import resources
    return "vendored", (resources.files("purser.data") / "loader_cves.yaml").read_text()


def staleness_hint() -> str | None:
    """A one-line nudge when the active dataset is old. Never raises."""
    try:
        source, text = active_dataset()
        stamp = refreshed_on(text)
        if stamp is None:
            return None
        age = (date.today() - stamp).days
        if age <= STALE_AFTER_DAYS:
            return None
        return (f"loader-CVE dataset ({source}) is {age} days old — "
                "run `purser update-intel` to refresh")
    except Exception:
        return None
