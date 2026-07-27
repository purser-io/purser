# CNCF Landscape entry — prepared (submission deferred)

Purser fits the CNCF Landscape under **Provisioning → Security & Compliance**
(ML supply-chain / model scanning). This file holds the ready-to-submit entry so
it can go in the moment the inclusion bar is met.

## Status: prepared, not yet submitted

The [CNCF Landscape](https://github.com/cncf/landscape) has real inclusion gates
Purser does not clear **yet**:

1. **Traction.** The landscape generally expects meaningful adoption
   (historically ~300+ GitHub stars, or other notability). Purser is at single
   digits today.
2. **Organization + Crunchbase.** Every landscape item must map to an
   organization with a `crunchbase` URL in `landscape.yml`. Purser has no backing
   org/Crunchbase entry yet.

Submitting before these are in place would be closed as premature — the same
call we made for the awesome-list (watchlist first). Revisit once adoption grows
and an org/Crunchbase page exists. (The lighter-weight visibility step —
`awesome-ai-security-tools` — is already in flight via its watchlist.)

## The entry (add to `landscape.yml` when ready)

Under the `Provisioning` category, `Security & Compliance` subcategory:

```yaml
- item:
    name: Purser
    homepage_url: https://purser-io.io
    repo_url: https://github.com/purser-io/purser
    logo: purser.svg
    description: >-
      Static security scanner for ML model artifacts: malicious-code and
      data-exfiltration detection across 35+ formats, with a policy engine
      (country of origin, publisher, format), signed/verified provenance, and
      CI + Kubernetes admission enforcement.
    license: Apache-2.0
    # crunchbase: https://www.crunchbase.com/organization/<org>   # required — add org first
    # twitter / project_org as applicable
```

## Logo

CNCF requires a single-color-friendly **SVG**. Use
[`assets/brand/purser-mark.svg`](../assets/brand/purser-mark.svg) (contribute it
as `hosted_logos/purser.svg`), verified with the landscape's `svg` linter
(no embedded raster, no external refs).

## Submitting (when the gates are met)

1. Register/confirm the organization's Crunchbase page.
2. Fork `cncf/landscape`, add the item YAML above under Security & Compliance,
   and add `hosted_logos/purser.svg`.
3. Open a PR; the landscape CI validates the logo + required fields.
