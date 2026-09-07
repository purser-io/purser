#!/usr/bin/env python3
"""Generate docs/compliance-mapping.md from the vendored compliance map.

`src/purser/data/compliance_map.yaml` is the single source of truth: it drives
both the `owasp-llm:LLM03`-style tags Purser appends to findings and the
reviewer-facing table written here. Generating the doc means the tags a
reviewer greps for and the table they read cannot drift apart.

Deterministic: same input, byte-identical output. A test asserts the committed
doc matches, so a mapping change that skips regeneration fails CI.

Usage:
    python scripts/gen_compliance_doc.py docs/compliance-mapping.md
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import yaml  # noqa: E402

MAP = Path(__file__).resolve().parents[1] / "src/purser/data/compliance_map.yaml"

HEADER = """\
# Compliance mapping

Which control each Purser finding produces evidence for, across the frameworks
enterprise reviewers arrive with.

> [!IMPORTANT]
> **A mapping is an aid to an auditor, not a compliance claim.** Purser
> produces evidence for these controls; it does not by itself satisfy them. A
> `PASS` verdict means "clear of known malicious content", not "compliant".

Every finding carries its controls as tags, so this table is machine-readable
at the point of use:

```bash
purser scan ./model-dir --format json | jq '.files[].findings[].tags'
# [... "owasp-llm:LLM03", "eu-ai-act:AnnexIV-2" ]
```

Tags also ride into the [CycloneDX ML-BOM](../README.md#ai-bill-of-materials-ml-bom)
(`--format cyclonedx`), so the BOM you hand an auditor carries the control
references with it. Disable tagging entirely with `PURSER_COMPLIANCE=0`.

<!-- GENERATED FILE — edit src/purser/data/compliance_map.yaml and run
     `make compliance-doc`. Do not edit by hand. -->

## Mapping granularity

Stated plainly, because precision claims matter in an audit:

- **OWASP ML / LLM ids are exact** — the published Top 10 identifiers.
- **NIST AI RMF is mapped at category level** (`GOVERN-6`, `MAP-4`,
  `MANAGE-3`, `MEASURE-2`), not subcategory. The three categories scoped to
  third-party and supply-chain risk are GOVERN 6, MAP 4 and MANAGE 3. Pinning
  subcategory decimals would imply a precision this mapping has not verified
  against NIST AI 100-1 — refine against your own control matrix.
- **EU AI Act references are Annex IV section numbers** (1–9), the granularity
  Annex IV itself uses.
"""


def _framework_tables(doc: dict) -> list[str]:
    out = ["", "## Frameworks referenced", ""]
    for fid, spec in (doc.get("frameworks") or {}).items():
        spec = spec or {}
        out.append(f"### `{fid}` — [{spec.get('name', fid)}]({spec.get('url', '')})")
        out.append("")
        out.append("| Control | Title |")
        out.append("|---|---|")
        for cid, title in (spec.get("controls") or {}).items():
            out.append(f"| `{fid}:{cid}` | {title} |")
        out.append("")
    return out


def _umbrella_section(doc: dict) -> list[str]:
    umbrella = [str(c) for c in (doc.get("umbrella") or [])]
    if not umbrella:
        return []
    return [
        "## Applied to every model-artifact finding",
        "",
        "Scanning a model artifact at all is third-party supply-chain due",
        "diligence, so these controls are attached to every matched finding",
        "in addition to the specific ones below:",
        "",
        *(f"- `{c}`" for c in umbrella),
        "",
        "The one exception is the model-card/eval gate (`CARD_*`), which is",
        "about documentation rather than malicious content — the supply-chain",
        "umbrella would be a poor fit, so it is not applied there.",
        "",
    ]


def _rule_table(doc: dict) -> list[str]:
    out = [
        "## Findings → controls",
        "",
        "Matched by **longest rule-id prefix**. Controls listed here are in",
        "addition to the umbrella set above unless the row says otherwise.",
        "",
        "| Rule-id prefixes | Additional controls | Umbrella |",
        "|---|---|---|",
    ]
    for rule in doc.get("rules") or []:
        prefixes = ", ".join(f"`{p}`" for p in (rule.get("prefixes") or []))
        controls = ", ".join(f"`{c}`" for c in (rule.get("controls") or [])) or "—"
        umbrella = "no" if rule.get("no_umbrella") else "yes"
        out.append(f"| {prefixes} | {controls} | {umbrella} |")
    out.append("")
    return out


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    doc = yaml.safe_load(MAP.read_text()) or {}
    lines = [HEADER.rstrip(), ""]
    lines += _framework_tables(doc)
    lines += _umbrella_section(doc)
    lines += _rule_table(doc)
    lines += [
        "## Coverage this mapping does not claim",
        "",
        "Purser is a static artifact scanner. It produces no evidence for",
        "controls about training-data governance, behavioural evaluation,",
        "human oversight, or post-market incident reporting — those need",
        "different tooling, and an auditor should not read a Purser report as",
        "covering them. See [`gap_analysis.md`](../gap_analysis.md) §8 for the",
        "full residual-risk list.",
        "",
    ]
    Path(argv[1]).write_text("\n".join(lines).rstrip() + "\n")
    print(f"wrote {argv[1]}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
