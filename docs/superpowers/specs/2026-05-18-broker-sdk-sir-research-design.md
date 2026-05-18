# Spec: SIR research pass — data-broker SDKs and aggregators

**Issue:** [#168](https://github.com/yasirhamza/AndroDR/issues/168) (parent: data-broker SDK detection rule pack).
**Sibling spec:** [`2026-05-17-data-broker-sdk-scanner-design.md`](2026-05-17-data-broker-sdk-scanner-design.md) (scanner extension that emits `embeddedComponentClasses` / `embeddedNativeLibs`; landed as PR #183).
**Scope of this spec:** **only** the research pass that produces 8 per-SDK Structured Intelligence Records (SIRs) from authoritative sources. No SIGMA rules, no Kotlin, no DNS rule authoring. Each downstream rule pack gets its own spec → plan → PR cycle in subsequent sessions.
**Date:** 2026-05-18

---

## Why

The scanner extension shipped yesterday added `embedded_component_class` and `embedded_native_lib` fields to `AppTelemetry`. The fields are inert until the rule corpus contains entries that match against them. The `installed_app` rule pack for data-broker SDKs is the first consumer, and the rule author cannot write durable, well-cited rules without first having SIRs that pin down:

- The specific manifest class-name prefix or native-lib filename for each SDK
- The vendor's own description of the SDK (provenance.vendor_page)
- At least one independent research source per SDK (provenance.independent_sources)

This pass produces those SIRs as JSON artifacts on disk so the next session's `update-rules-author` invocation has structured, citable input.

## Target list

Eight entities, drawn from issue #168 minus the "unnamed Florida broker" (which by definition cannot be researched as a named threat — it stays as motivation in #168, not a research target):

| # | Entity | Type | Anchors which rule pack | Notes |
|---|---|---|---|---|
| 1 | X-Mode / Outlogic | On-device SDK | `installed_app` | Canonical case — FTC settlement, well-documented, public class prefixes |
| 2 | Venntel | On-device SDK | `installed_app` | Senate hearings, ICE/FBI procurement disclosures |
| 3 | Mobilewalla | On-device SDK | `installed_app` | Vendor SDK page + Exodus Privacy traces |
| 4 | Adsquare | On-device SDK | `installed_app` | Vendor SDK page |
| 5 | Predicio | On-device SDK | `installed_app` | Reardon (Calgary) academic research |
| 6 | Cuebiq | On-device SDK | `installed_app` | NYT *Times Privacy Project* exposé + vendor SDK |
| 7 | Gravy Analytics | Aggregator | `dns` (future) | Parent of Venntel/Unacast; DNS-only SIR expected |
| 8 | Babel Street / LocateX | Consumer | `dns` (future) | Buys broker data; DNS-only SIR expected |

The two aggregator entries (Gravy, Babel Street) are not expected to yield `embedded_component_class` or `embedded_native_lib` indicators — they purchase data rather than ship a collector. They are still researched here so the future `dns` rule pack session does not have to repeat web search across overlapping territory.

## SIR shape and persistence

**File layout:**

```
docs/superpowers/research/2026-05-18-broker-sdks/
├── README.md
├── outlogic.json
├── venntel.json
├── mobilewalla.json
├── adsquare.json
├── predicio.json
├── cuebiq.json
├── gravy-analytics.json
└── babel-street.json
```

One file per SDK, kebab-case slug, `.json`. README.md is a short index pointing to this spec, the scanner spec, the SIR files, and issue #168.

**Per-file schema** — each file holds a single SIR object (not the `{sirs:[...], updated_cursors:{}}` envelope used in the live `update-rules-research-threat` pipeline). Top-level keys:

| Key | Type | Required | Notes |
|---|---|---|---|
| `source.feed` | string | yes | Always `"threat_research"` |
| `source.url` | string | yes | Primary source URL |
| `threat.name` | string | yes | SDK/entity name as listed in the target table |
| `threat.families` | string[] | yes | Aliases (e.g., `["X-Mode Social", "Outlogic"]`); empty array if none |
| `threat.description` | string | yes | 2–3 sentence summary anchored on the broker-pipeline role |
| `indicators` | object[] | yes | IOCs with per-IOC `source_urls`; never invented |
| `attack_techniques` | object[] | yes | ATT&CK Mobile mappings (likely `T1430 Location Tracking`, `T1437 Application Layer Protocol`); empty array allowed |
| `behavioral_signals` | string[] | yes | Detectable behaviors; empty array allowed |
| `confidence` | string | yes | `"high"` (2+ sources, or 1 structured source) or `"medium"` (1 unstructured source only), matching the research-threat skill's rules |
| `requires_verification` | boolean | yes | `true` for aggregator SIRs by definition; `true` for SDK SIRs built from a single unstructured source |
| `provenance.vendor_page` | string \| null | yes | URL to the SDK vendor's own page. May be `null` if the vendor's site is genuinely unreachable (404 / domain parked); the description must explain. |
| `provenance.independent_sources` | string[] | yes | ≥1 URLs to independent research (Exodus Privacy, Reardon paper, FTC docs, news investigations) |

Per-IOC source tagging is mandatory: each `indicators[]` entry includes `source_urls: string[]` so the rule author can cite specific provenance per indicator.

**Why per-file JSON, not a single bundle:** matches the fan-out pattern (one subagent writes one file, no merge step), reviewable per-SDK in git diff, and the next session's `update-rules-author` can either consume them individually or `cat` them into an array.

**Threat-name vs slug for compound entries:** for `X-Mode / Outlogic` and `Babel Street / LocateX`, the file slug uses the current canonical name (`outlogic.json`, `babel-street.json`) and the SIR's `threat.name` matches the slug (`"Outlogic"`, `"Babel Street"`). The former alias is captured in `threat.families` (`["X-Mode Social", "X-Mode"]` and `["LocateX"]` respectively). The dispatching prompt passes both names so the research subagent searches across the rebrand.

## Dispatch pattern

Eight parallel `Agent` tool calls in a single message, all with `subagent_type: general-purpose`. The `update-rules-research-threat` skill is a slash command, not a built-in agent type, so each subagent's prompt embeds the skill's instructions verbatim alongside the SDK-specific brief.

Parallelism is mandatory — sequential would burn ~8× the wall time for no benefit (no shared state, no ordering dependency between SDKs). Matches the discover-mode fan-out pattern in `.claude/commands/update-rules.md`.

**Per-subagent prompt structure:**

1. **Identity:** "You are a threat researcher producing one SIR for `<SDK name>`."
2. **Skill body:** verbatim contents of `.claude/commands/update-rules-research-threat.md`.
3. **Project-specific overrides:**
   - Output a single SIR object (not the `{sirs:[...], updated_cursors:{}}` envelope)
   - Include `provenance.vendor_page` and `provenance.independent_sources` (≥1) per the schema above
   - For aggregator targets (Gravy, Babel Street), set `requires_verification: true` and acknowledge that indicators will be DNS-shaped or behavioral-only
4. **Write target:** `docs/superpowers/research/2026-05-18-broker-sdks/<slug>.json`
5. **Return value:** the JSON written, plus a one-line confidence summary, so the dispatcher can spot-check before moving on
6. **Hard rules** (lifted from the skill):
   - Never invent IOCs
   - Only extract from sources fetched during this dispatch
   - Never include IOCs from training data
   - Tag every IOC with the source URL it came from

**Throttling mitigation:** if WebSearch rate-limits during the 8-way fan-out, fall back to two batches of 4. Runtime contingency, not a design change.

## Two-reviewer cycle

Per the project's standing review rule, the 8 SIRs go through both reviewers in parallel **after** all dispatches return and **before** anything is committed:

- **Spec-compliance reviewer:** verifies every SIR matches the schema above. Checks: `source.feed == "threat_research"`, all required keys present, `provenance.independent_sources` length ≥ 1, no envelope wrapper, aggregator SIRs flagged `requires_verification: true`, file at the expected path with the expected slug.
- **Harsh-quality reviewer:** spot-checks IOCs against their cited URLs (does the source actually say this?), looks for fabricated class prefixes or hallucinated `.so` names, flags single-source SDK claims that should be `requires_verification: true`, calls out vague behavioral_signals that won't anchor a SIGMA rule, and rejects descriptions that read like LLM filler instead of evidence.

Failures from either reviewer block the commit. Affected SIR(s) get re-dispatched with the reviewer feedback in the prompt and re-reviewed before the cycle can close.

## Acceptance criteria

- [ ] `docs/superpowers/research/2026-05-18-broker-sdks/` exists with 8 `.json` files (one per SDK in the target table) plus `README.md`.
- [ ] Every SIR validates against the schema: `source.feed == "threat_research"`, `threat.name`, `threat.description` (2–3 sentences), `indicators[]` with per-IOC `source_urls`, `provenance.vendor_page`, `provenance.independent_sources[]` length ≥ 1, top-level `confidence` and `requires_verification`.
- [ ] The 2 aggregator SIRs (`gravy-analytics.json`, `babel-street.json`) have `requires_verification: true` and contain DNS-shaped indicators or behavioral_signals only — no `embedded_component_class` / `embedded_native_lib` claims.
- [ ] At least 4 of the 6 SDK SIRs contain ≥1 concrete on-device anchor (manifest class-name prefix or native lib filename) suitable for `embedded_component_class|contains:` or `embedded_native_lib|contains:`. SDKs where no concrete anchor surfaces get `requires_verification: true` with behavioral_signals only — the rule author will record a `telemetry_gap` decision in the next session.
- [ ] Both reviewer cycles (spec-compliance, harsh-quality) pass before commit.
- [ ] Committed on a topic branch (`feat/168-broker-sdk-sirs`) and merged via PR to `main`. Per the project's CI-wait pattern, admin-merge after local checks pass.
- [ ] No code or YAML rules authored in this pass — research artifacts only. Scanner is already shipped; rule authoring is the next session.

## Out of scope

- Authoring the `installed_app` rule pack against the new fields — separate brainstorm → spec → plan → implementation cycle, consuming the 6 SDK SIRs.
- Authoring the `dns` rule pack — separate cycle, consuming the 2 aggregator SIRs plus any DNS indicators harvested from the 6 SDK SIRs.
- The combination rule (`sensitive permission + broker SDK`) — gated on the `installed_app` pack landing first.
- On-device validation against installed apps containing these SDKs — possible but not required for this research pass.
- Updating `feed-state.json` cursors — this is an off-pipeline research pass, not a feed sweep.

## Handoff to next session

The README.md in the research directory points to:
1. This spec
2. The scanner-extension spec (`2026-05-17-data-broker-sdk-scanner-design.md`)
3. The 8 SIR files
4. Issue #168

The next session opens by reading the README, then invokes `update-rules-author` against the 6 SDK SIRs to produce the `installed_app` rule pack. The 2 aggregator SIRs sit unused until the `dns` rule pack session opens.
