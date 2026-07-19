"""Model provenance: determine publisher and country of origin.

Resolution order (first hit wins):
  1. explicit origin passed by the caller (--origin / API field)
  2. a sidecar provenance file next to the model (`<name>.provenance.yaml`
     or `provenance.yaml` in the model directory)
  3. publisher lookup in the bundled + user-extendable origin database
     (publisher inferred from an hf-style repo id `org/name` when given)

The bundled database maps well-known model publishers to ISO 3166-1
alpha-2 country codes. Users extend or override it via the policy dir
(`origins.yaml`) or the PURSER_ORIGINS env var.
"""

from __future__ import annotations

from dataclasses import dataclass
from importlib import resources
from pathlib import Path

import yaml
from purser.core.env import env_get


@dataclass
class Provenance:
    publisher: str | None = None
    origin: str | None = None  # ISO 3166-1 alpha-2
    source: str = "unknown"    # explicit | sidecar | database | unknown


def _load_bundled_db() -> dict[str, str]:
    try:
        text = (resources.files("purser.data") / "org_countries.yaml").read_text()
    except (FileNotFoundError, ModuleNotFoundError):
        return {}
    doc = yaml.safe_load(text) or {}
    return {str(k).lower(): str(v).upper() for k, v in (doc.get("publishers") or {}).items()}


def _load_user_db() -> dict[str, str]:
    candidates = []
    env = env_get("ORIGINS")
    if env:
        candidates.append(Path(env))
    candidates.append(Path("/etc/purser/origins.yaml"))
    for cand in candidates:
        if cand.is_file():
            doc = yaml.safe_load(cand.read_text()) or {}
            return {
                str(k).lower(): str(v).upper()
                for k, v in (doc.get("publishers") or {}).items()
            }
    return {}


def origin_db() -> dict[str, str]:
    db = _load_bundled_db()
    db.update(_load_user_db())  # user entries override bundled ones
    return db


def _sidecar_for(target: Path) -> Path | None:
    if target.is_dir():
        cand = target / "provenance.yaml"
        return cand if cand.is_file() else None
    for cand in (
        target.with_suffix(target.suffix + ".provenance.yaml"),
        target.parent / "provenance.yaml",
    ):
        if cand.is_file():
            return cand
    return None


def resolve(
    target: Path | None = None,
    explicit_origin: str | None = None,
    publisher: str | None = None,
    repo_id: str | None = None,
) -> Provenance:
    if repo_id and not publisher and "/" in repo_id:
        publisher = repo_id.split("/", 1)[0]

    if explicit_origin:
        return Provenance(publisher=publisher, origin=explicit_origin.upper(), source="explicit")

    if target is not None:
        sidecar = _sidecar_for(target)
        if sidecar is not None:
            try:
                doc = yaml.safe_load(sidecar.read_text()) or {}
            except yaml.YAMLError:
                doc = {}
            origin = doc.get("origin") or doc.get("country")
            pub = doc.get("publisher") or publisher
            if origin:
                return Provenance(
                    publisher=pub, origin=str(origin).upper(), source="sidecar"
                )
            publisher = pub or publisher

    if publisher:
        db = origin_db()
        origin = db.get(publisher.lower())
        if origin:
            return Provenance(publisher=publisher, origin=origin, source="database")

    return Provenance(publisher=publisher, origin=None, source="unknown")
