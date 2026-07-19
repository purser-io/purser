# Brand: **Purser**

The chosen name, logo, and brand for the project — selected with
market/name research in mind (steer clear of the crowded
`*guard` / `*guardian` / `model*` space and taken PyPI names) and to fit the
**Kubernetes** and **GitLab** world the tool lives in.

> This is the working brand and it **has been applied to the codebase** — the
> package, CLI, images, and env vars are now `purser` / `PURSER_*`. **Legal
> clearance is still pending** (see *Owning the name*); do not publish to PyPI /
> a public registry or launch publicly until the trademark search clears.

---

## TL;DR

- **Name:** **Purser**
- **Mark:** a clearance **stamp/seal** — a ring with a "cleared" check over a
  manifest bar ([`assets/brand/purser-mark.svg`](assets/brand/purser-mark.svg),
  [lockup](assets/brand/purser-logo.svg))
- **Tagline:** *"Nothing boards without clearing the Purser."*
- **One-liner:** *Purser checks a model's manifest and clearance before it comes
  aboard your cluster.*

---

## Why "Purser"

A ship's **purser** keeps the cargo **manifest**, verifies it, and clears cargo
to come aboard. That maps onto all three things this tool does, in one word:

- **Scan** — inspect the cargo (the model) before it's loaded.
- **Provenance / signing** — the keeper of the manifest / bill of lading (our
  Ed25519 signatures and trust store).
- **Policy** — the officer who enforces the rules on what's allowed aboard.

Why it fits the constraints:

- **Clears the research pitfalls.** It's outside the saturated
  `guard/guardian/model/scan/shield` space, so it doesn't collide with the
  same-purpose `ModelGuard` project or Protect AI's *Guardian*. It reads as a
  **brand**, not a description — which is what makes a mark defensible.
- **Native to Kubernetes.** Cloud-native tooling is proudly nautical (Helm,
  Harbor, Argo, the K8s ship's wheel). "Purser" belongs beside them.
- **Clean namespace.** Unlike Plimsoll (blocked by an AI-adjacent
  `plimsoll.network`) and the rejected options below, no PyPI package, no
  AI/ML-security tool, and no AI-adjacent company named "Purser" was found.
- **Own-able logo.** A clearance **stamp** is distinctive and directly on-story —
  and it is *not* a shield, padlock, keyhole, hexagon, or yellow face (the
  clichés/overlaps the research flagged).

### Names considered & rejected
| Name | Why not |
|---|---|
| ModelGuard *(former name)* | Same-name, same-purpose GitHub project; PyPI taken; near Protect AI "Guardian". |
| Plimsoll | Great fit, but `plimsoll.network` is an AI-adjacent trademark risk. |
| Ballast, Bosun, Bulkhead | Taken on PyPI (Bosun is also a monitoring tool). |
| Gangway | A Kubernetes OIDC / Prow component — direct ecosystem collision. |
| Cairn | Clean, kept as **backup** (metaphor is more generic: a trusted waypoint). |

---

## Availability snapshot (as of this research)

| Channel | Finding | Status |
|---|---|---|
| PyPI `purser` | No Python package found | 🟢 appears free |
| GitHub / ML-AI-security tool | None found named Purser | 🟢 clear in our niche |
| AI-adjacent company/squatter | None found | 🟢 (the Plimsoll problem is absent) |
| `.com` domain | Verify (likely needs `.dev`/`.io` or `getpurser`/`usepurser`) | 🟡 |
| Semantics | "purser" also = a ship's finance officer | 🟡 faint fintech connotation, harmless here |

**Still required** before adopting in code: a formal **USPTO TESS** search +
counsel (classes 9 software / 42 SaaS), and reserving PyPI + GitHub org + a
domain together. The greens are encouraging, not a legal clearance.

---

## Logo & mark

**Concept — the clearance stamp.** A seal ring with a "cleared" check above a
manifest bar, and a tinted band below the bar (the "stamped/cleared" fill).

- Files: [`purser-mark.svg`](assets/brand/purser-mark.svg) (icon / favicon),
  [`purser-logo.svg`](assets/brand/purser-logo.svg) (mark + wordmark).
- One simple geometric form → crisp at favicon size and in a single colour
  (CI-badge / stamp use). Ties directly to our signing/provenance story.

**Do:** use the seal alone as an app icon; keep clear space ≈ ½ the seal
diameter; use one-colour (ink or white) versions on busy backgrounds.

**Don't:** wrap it in a shield; recolour to alarm-red; stretch the seal to an
oval; put the cyan check on low-contrast backgrounds.

---

## Colour palette

Maritime and calm — assurance, not alarm (deliberately not security-red).

| Role | Name | Hex | Use |
|---|---|---|---|
| Primary | Ink Navy | `#0E2A47` | seal, wordmark, headings |
| Accent | Waterline Cyan | `#16B3C6` | the check, links, highlights |
| Dark bg | Deep Sea | `#071B2E` | dark-mode canvas |
| Light bg | Paper | `#FFFFFF` | light-mode canvas |
| Muted text | Slate | `#5B7085` | secondary text |

In dark mode, render the seal in Paper with the Cyan check.

## Typography

- **Wordmark & headings:** a geometric-humanist sans — **Inter** or **Space
  Grotesk** (open-licensed). Convert the wordmark to outlines in the shipped SVG
  so it doesn't depend on the viewer's fonts.
- **Code / CLI:** a mono — **JetBrains Mono** or **IBM Plex Mono**.

---

## Naming system

Renaming `modelguard` → `purser` across the suite:

| Thing | Today | Proposed |
|---|---|---|
| Project / PyPI package | `modelguard` | `purser` |
| CLI command | `modelguard scan …` | `purser scan …` |
| Core image | `modelguard` | `purser` |
| HF worker image | `modelguard-hf` | `purser-hf` |
| Deep companion | `modelguard-deep` | `purser-deep` *(codename **Sounding** — a "sounding" measures the depths → deep analysis)* |
| Env prefix | `MODELGUARD_*` | `PURSER_*` |
| Signed attestation | signature | keep; may be styled the *bill of lading* |
| Policy | policy | keep |

Verdicts (PASS/WARN/FAIL/BLOCKED) and finding IDs stay as-is.

## Voice & taglines

Calm, plain, confident — an officer who clears your cargo, not an alarm.

- *Nothing boards without clearing the Purser.*
- *Cleared for loading.*
- *Check the manifest before it comes aboard.*
- *The manifest check for AI models.*

---

## Owning the name (clearance & namespace plan)

"Owning" Purser means three things at once: a **trademark** in our class,
**control of the namespaces**, and **brand governance** so the open-source
licence doesn't give the name away.

**Phase 0 — stake the claim now (hours, ~$100):** register PyPI `purser`
(placeholder release), the GitHub org, a container-registry org, and a domain
(`purser.dev`/`.io`, plus defensive `get`/`use` variants); grab handles; start a
dated "first use in commerce" record.

**Phase 1 — before public launch:** a clearance search in **Nice classes 9 & 42**
(USPTO TESS + counsel); add **`TRADEMARKS.md`** (Apache-2.0 §6 grants **no**
trademark rights, so we keep the code open while reserving name/logo); use **™**;
lock down logo copyright (outlined wordmark, written IP assignment if a designer
is used).

**Phase 2 — register (months, ~$250–350/class + counsel):** file use- or
intent-to-use application(s); Madrid Protocol for other markets; assign all IP to
the owning entity.

**Phase 3 — keep it:** register **®** when granted; set a trademark watch;
enforce consistently.

Purser's runway looks cleaner than Plimsoll's (no AI-adjacent squatter found),
but a formal search is still the gate.

---

## Applying the rebrand (done)

The rename has been applied across the codebase: the `pyproject.toml` name +
console script (`purser`), the `purser` / `purser_deep` packages, all env vars
(`PURSER_*`), image names (`purser`, `purser-hf`, `purser-deep`), the Kubernetes
manifests, and the docs. This file intentionally still mentions "ModelGuard"
as the former name.

**Not yet done (gated on legal review):** publishing to PyPI / a public
registry, and the trademark filing — see *Owning the name*.

---

## Sources
- [PyPI](https://pypi.org/) · [USPTO trademark search](https://www.uspto.gov/trademarks/search)
- Rejected-name checks: [Bosun (monitoring)](https://github.com/bosun-monitor/bosun) · [Gangway (Kubernetes OIDC)](https://github.com/vmware-archive/gangway) · [ballast (PyPI)](https://pypi.org/project/ballast/) · [bulkhead (PyPI)](https://pypi.org/project/bulkhead/)
