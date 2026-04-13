# Sub-plan 2: Author Quality — Researcher IOC Confidence + Logsource Taxonomy

**Issue:** #108
**Epic:** #104
**Depends on:** #105, #106, #107 (Bundle 1 — all merged)
**Date:** 2026-04-13

---

## Problem

The AI rule pipeline works end-to-end (proven in Bundle 1), but two quality gaps
remain in the authoring stage:

1. **F7 — Hallucinated IOC risk.** The threat researcher skill assigns confidence
   levels (`high`/`medium`) but both levels flow through to the Rule Author
   identically. A single blog post mentioning a domain can become an IOC with no
   gate or flag.

2. **F9 — No logsource field taxonomy.** The Rule Author has no reference for
   what fields each logsource service actually provides. It may produce rules
   using field names that don't exist in the corresponding `toFieldMap()`
   implementation, and there's no way to catch this until a human reads the rule.

Additionally, a source name inconsistency exists: `allowed-sources.json` uses
`amnesty-tech` while the Rule Author skill and bundled IOC data use
`amnesty-investigations`. The upstream repo is
[AmnestyTech/investigations](https://github.com/AmnestyTech/investigations);
the canonical name should be `amnesty-investigations`.

---

## Decisions (resolved during brainstorming)

| # | Decision | Choice | Rationale |
|---|----------|--------|-----------|
| 1 | `requires_verification` routing | Decision manifest entry (Option B) | Keeps pipeline unified; Rule Author already has decision-flagging; human reviewer sees the call |
| 2 | Taxonomy shape | Static YAML file + cross-check test (Approach B) | First-class artifact in validation dir; testable; consistent with `rule-schema.json` pattern; stepping stone to formal schema later |
| 3 | Structured source definition | Any source in `allowed-sources.json` delivered via feed ingester | Feed ingesters produce machine-parsed structured data; web-searched blog posts are unstructured |
| 4 | Amnesty source name | `amnesty-investigations` | Matches upstream repo name (`AmnestyTech/investigations`) and existing IOC data entries |

---

## Design

### 1. Threat Researcher — Cross-Source Verification Gate

**Current behavior:** Step 3 of `update-rules-research-threat.md` assigns
`confidence: "high"` (2+ sources or 1 structured) or `"medium"` (1 unstructured
source), but both flow through to the Rule Author identically.

**New behavior:**

- IOCs from feed ingesters (any source in `allowed-sources.json`) are
  **structured** — `confidence: "high"`, flow through normally.
- IOCs from web-searched blog posts are **unstructured** — if corroborated by a
  second source, `confidence: "high"`; if single-source, tagged
  `requires_verification: true` in the SIR output.
- The SIR indicator object gains a `requires_verification` boolean field.
- The skill's "Rules" section gets a hard rule: *"Single unstructured-source IOCs
  MUST be tagged `requires_verification: true`."*

**Downstream effect:** The Rule Author sees the flag and records a decision
manifest entry of type `ioc_confidence` — either "include despite single-source
(reasoning: ...)" or "skip (insufficient evidence)". The human reviewer sees
this in the decision manifest and can override.

### 2. Logsource Field Taxonomy

A new `logsource-taxonomy.yml` in `android-sigma-rules/validation/` declares
every field available per logsource service.

**Structure:**

```yaml
product: androdr
services:
  app_scanner:
    model_class: AppTelemetry
    fields:
      package_name: { type: string, description: "Android package name" }
      app_name: { type: string, description: "User-visible app label" }
      cert_hash: { type: string, description: "SHA-256 of signing certificate" }
      # ... all 20 fields from AppTelemetry.toFieldMap()
  device_auditor:
    model_class: DeviceTelemetry
    fields:
      check_id: { type: string }
      # ... all 13 fields
  dns_monitor:
    model_class: DnsEvent
    fields:
      domain: { type: string }
      # ... all 5 fields
  # ... remaining 6 services (process_monitor, file_scanner,
  #     receiver_audit, accessibility, appops, network_monitor)
```

**Cross-check test:** New `LogsourceTaxonomyCrossCheckTest.kt` in
`app/src/test/`. For each service in the taxonomy, it instantiates the
corresponding telemetry model, calls `toFieldMap()`, and asserts the field
names match exactly — no extra fields in Kotlin that aren't in the taxonomy,
no taxonomy fields that don't exist in Kotlin. Same fail-the-build pattern as
`BundledRulesSchemaCrossCheckTest`.

### 3. Rule Author — `telemetry_gap` Decision Type and Taxonomy Consumption

Two additions to `update-rules-author.md`:

**Taxonomy reference instruction** (added to Rule Generation Strategy section):

> "Before writing any `detection:` block, read
> `android-sigma-rules/validation/logsource-taxonomy.yml` for the target
> service. Only use field names listed there. If the SIR describes a behavior
> that requires a field not in the taxonomy, do NOT invent the field — record a
> `telemetry_gap` decision instead."

**New `telemetry_gap` decision type** (added to Decision Flagging section):

```yaml
decisions:
  - rule_id: null
    field: "rule_creation"
    type: "telemetry_gap"
    chosen: "skip"
    alternative: "create rule using field 'battery_drain_rate'"
    reasoning: "SIR describes rapid battery drain detection but app_scanner
                has no battery_drain_rate field in taxonomy"
    missing_field: "battery_drain_rate"
    suggested_service: "app_scanner"
```

The `missing_field` and `suggested_service` fields feed back into AndroDR's
development roadmap — a structured signal for "the AI pipeline wanted this
telemetry but we don't collect it yet."

**Source name fix:** The allowed sources list in the skill is updated to use
`amnesty-investigations` consistently. `allowed-sources.json` is also fixed.

### 4. Validation Re-run and Measurable Improvement

After skill edits land, re-run `/update-rules source stalkerware` and compare
against Bundle 1c output on three dimensions:

| Dimension | Expected in 1c | Expected after this sub-plan |
|-----------|----------------|------------------------------|
| Field accuracy | Unchecked — may use out-of-taxonomy fields | Zero out-of-taxonomy fields; any gaps recorded as `telemetry_gap` decisions |
| IOC confidence | Single-source IOCs flow through silently | Single-source IOCs flagged `requires_verification`; Rule Author records `ioc_confidence` decision |
| Decision manifest | No `telemetry_gap` or `ioc_confidence` entries | New decision types present where appropriate |

"Measurably improved" is qualitative but structured — the three dimensions above
are the checklist. If the re-run shows the same issues as 1c, the skill edits
need revision.

No new rules are required from the re-run. The goal is demonstrating observable
quality improvement in pipeline output.

---

## File Manifest

| File | Change |
|------|--------|
| `.claude/commands/update-rules-research-threat.md` | Add `requires_verification` gate, structured vs unstructured source definition |
| `.claude/commands/update-rules-author.md` | Add taxonomy reference instruction, `telemetry_gap` decision type, fix source names |
| `third-party/android-sigma-rules/validation/logsource-taxonomy.yml` | **New** — field taxonomy per logsource service |
| `third-party/android-sigma-rules/validation/allowed-sources.json` | Fix `amnesty-tech` → `amnesty-investigations` |
| `app/src/test/.../LogsourceTaxonomyCrossCheckTest.kt` | **New** — validates taxonomy matches `toFieldMap()` |
| `app/src/main/res/raw/known_bad_packages.json` | Fix any `amnesty-tech` source entries to `amnesty-investigations` |

## Out of Scope

- No changes to Kotlin telemetry model classes
- No changes to the evaluator, parser, or rule engine
- No new SIGMA rules authored
- No schema-first redesign (future work for public rules repo)
- No changes to feed ingesters or `feed-state.json`
