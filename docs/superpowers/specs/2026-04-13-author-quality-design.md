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

Additionally, two naming inconsistencies need fixing:

- **Source name:** `allowed-sources.json` and the submodule IOC data files
  (`package-names.yml`, `c2-domains.yml`, `cert-hashes.yml`) use `amnesty-tech`,
  while the Rule Author skill uses `amnesty-investigations`. The upstream repo is
  [AmnestyTech/investigations](https://github.com/AmnestyTech/investigations);
  the canonical name should be `amnesty-investigations`. The rename must be
  atomic across `allowed-sources.json` and all IOC data files to avoid breaking
  `validate-ioc-data.py`.

- **Service names in `validate-rule.py`:** The `valid_services` whitelist uses
  `accessibility` and `appops`, but the runtime (`SigmaRuleEngine.kt`) uses
  `accessibility_audit` and `appops_audit`. It also omits 5 services added via
  `TelemetryFieldMaps.kt`: `wakelock_parser`, `battery_daily`,
  `package_install_history`, `platform_compat`, `db_info`. This is updated as
  part of the taxonomy work (the cross-check test validates the taxonomy, and
  `validate-rule.py` should derive its whitelist from the same taxonomy).

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
  second source, `confidence: "high"`; if single-source, the **SIR itself** is
  tagged `requires_verification: true`.
- The `requires_verification` flag lives at SIR level, not per-indicator. This is
  a deliberate design choice: the current SIR schema (`sir-schema.json`) stores
  indicators as flat string arrays (`package_names: string[]`, `domains: string[]`),
  so per-indicator metadata would require a breaking schema change to all ingesters.
  In practice, a single unstructured source (blog post) produces one SIR, and all
  IOCs within it share the same evidence basis — SIR-level granularity is sufficient.
- The SIR schema gains an optional top-level `requires_verification` boolean field.
- The skill's "Rules" section gets a hard rule: *"If a SIR is built from a single
  unstructured source, set `requires_verification: true` at the SIR level."*

**Downstream effect:** The Rule Author sees the flag and records a decision
manifest entry with a new `type` field set to `ioc_confidence` — either "include
despite single-source (reasoning: ...)" or "skip (insufficient evidence)". The
human reviewer sees this in the decision manifest and can override.

**Decision manifest schema extension:** The existing decision manifest format has
`field`, `chosen`, `alternative`, `reasoning`. This sub-plan adds an optional
`type` field (values: `ioc_confidence`, `telemetry_gap`, or omitted for existing
decision types). This is forward-compatible with the `decisions-schema.json`
planned in Bundle 3 (#109, F6).

### 2. Logsource Field Taxonomy

A new `logsource-taxonomy.yml` in `android-sigma-rules/validation/` declares
every field available per logsource service.

**Structure:**

All 15 services with `toFieldMap()` implementations are included, using their
exact runtime string names from `SigmaRuleEngine.kt`. Each service has a
`status` field indicating whether it is wired into the rule engine:

```yaml
product: androdr
services:
  # --- Member-function toFieldMap() (data model classes) ---
  app_scanner:
    model_class: AppTelemetry
    field_map: member                   # toFieldMap() is a member function
    status: active                      # has evaluateApps() in SigmaRuleEngine
  device_auditor:
    model_class: DeviceTelemetry
    field_map: member
    status: active
  dns_monitor:
    model_class: DnsEvent
    field_map: member
    status: active
  process_monitor:
    model_class: ProcessTelemetry
    field_map: member
    status: active
  file_scanner:
    model_class: FileArtifactTelemetry
    field_map: member
    status: active
  receiver_audit:
    model_class: ReceiverTelemetry
    field_map: member
    status: active
  accessibility_audit:
    model_class: AccessibilityTelemetry
    field_map: member
    status: active
  appops_audit:
    model_class: AppOpsTelemetry
    field_map: member
    status: active
  network_monitor:
    model_class: NetworkTelemetry
    field_map: member
    status: unwired                     # toFieldMap() exists but NO evaluate
                                        # method in SigmaRuleEngine — rules
                                        # targeting this service cannot fire

  # --- Extension-function toFieldMap() (TelemetryFieldMaps.kt) ---
  tombstone_parser:
    model_class: TombstoneEvent
    field_map: extension                # internal fun TombstoneEvent.toFieldMap()
    status: active
  wakelock_parser:
    model_class: WakelockAcquisition
    field_map: extension
    status: active
  battery_daily:
    model_class: BatteryDailyEvent
    field_map: extension
    status: active
  package_install_history:
    model_class: PackageInstallHistoryEntry
    field_map: extension
    status: active
  platform_compat:
    model_class: PlatformCompatChange
    field_map: extension
    status: active
  db_info:
    model_class: DatabasePathObservation
    field_map: extension
    status: active
```

Each service entry will also contain a `fields:` block with `{ type, description }`
per field. The full field lists are derived from the corresponding `toFieldMap()`
implementations during plan execution.

**Implementation notes for the taxonomy YAML:**

- Field names come from `toFieldMap()` map keys, NOT from Kotlin property names.
  Some keys differ from properties (e.g., `DnsEvent.appName` → key `source_package`).
- Derived fields that appear in `toFieldMap()` output but not in the constructor
  must be included (e.g., `DeviceTelemetry.unpatched_cve_id` is computed from
  `unpatchedCves` at runtime).
- Room `@Entity` fields like `DnsEvent.id` and `DnsEvent.timestamp` that are NOT
  in `toFieldMap()` output are NOT in the taxonomy.
- The `status: unwired` annotation tells the Rule Author: "this service has a
  data model but rules targeting it cannot fire — record a `telemetry_gap`
  decision instead of writing a rule."

**Cross-check test:** New `LogsourceTaxonomyCrossCheckTest.kt` in
`app/src/test/java/com/androdr/sigma/` (must be in `com.androdr.sigma` package
for `internal` extension function visibility). The test handles two patterns:

- **Member functions** (9 services): instantiate the model class with test values,
  call `toFieldMap()`, assert field names match the taxonomy.
- **Extension functions** (6 services): import from `com.androdr.sigma`, call the
  extension `toFieldMap()`, assert field names match.

For both patterns: no extra fields in Kotlin that aren't in the taxonomy, no
taxonomy fields that don't exist in Kotlin. Same fail-the-build pattern as
`BundledRulesSchemaCrossCheckTest`.

**`validate-rule.py` update:** The `valid_services` whitelist (line 63) is
updated to match the taxonomy's 15 services (including `network_monitor` — the
validator accepts it because the data model exists; the Rule Author's `status:
unwired` annotation prevents dead rules, not the validator).

### 3. Rule Author — `telemetry_gap` Decision Type and Taxonomy Consumption

Two additions to `update-rules-author.md`:

**Taxonomy reference instruction** (added to Rule Generation Strategy section):

> "Before writing any `detection:` block, read
> `android-sigma-rules/validation/logsource-taxonomy.yml` for the target
> service. Only use field names listed there. Services with `status: unwired`
> have a data model but no rule engine wiring — do NOT write rules for them;
> record a `telemetry_gap` decision instead. If a field you need isn't in the
> taxonomy for an `active` service, also record a `telemetry_gap` decision."

**Prompt engineering note:** Relying on the LLM to self-read a file mid-generation
is fragile. The `/update-rules` orchestrator should pre-read the taxonomy for the
relevant services and inject the field list into the Rule Author's input alongside
the SIRs. The skill instruction above is the fallback; the orchestrator injection
is the primary mechanism. The orchestrator change is a one-line addition to
`/update-rules` (read the taxonomy, append to the Rule Author prompt context).

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

After skill edits land, two re-runs validate the changes:

**Re-run A — feed ingester path:** `/update-rules source stalkerware` (same
threat as Bundle 1c). Stalkerware-indicators is a structured feed, so this
exercises dimensions 1 and 3 but NOT dimension 2 (no single-source unstructured
IOCs will appear).

**Re-run B — threat research path:** `/update-rules research <threat>` using a
web-search-based threat (e.g., a recently reported banking trojan). This
exercises dimension 2 — the researcher must web-search blog posts, producing
single-source IOCs that trigger the `requires_verification` gate.

| Dimension | Exercised by | Expected in 1c | Expected after this sub-plan |
|-----------|-------------|----------------|------------------------------|
| Field accuracy | Re-run A + B | Unchecked — may use out-of-taxonomy fields | Zero out-of-taxonomy fields; any gaps recorded as `telemetry_gap` decisions |
| IOC confidence | Re-run B only | Single-source IOCs flow through silently | Single-source IOCs flagged `requires_verification`; Rule Author records `ioc_confidence` decision |
| Decision manifest | Re-run A + B | No `telemetry_gap` or `ioc_confidence` entries | New decision types present where appropriate |

"Measurably improved" means all three dimensions show the expected behavior in
their respective re-runs. If a re-run shows the same issues as 1c, the skill
edits need revision.

No new rules are required from either re-run. The goal is demonstrating
observable quality improvement in pipeline output.

---

## File Manifest

| File | Change |
|------|--------|
| `.claude/commands/update-rules-research-threat.md` | Add SIR-level `requires_verification` gate, structured vs unstructured source definition |
| `.claude/commands/update-rules-author.md` | Add taxonomy reference instruction, `telemetry_gap` decision type, `ioc_confidence` decision type |
| `.claude/commands/update-rules.md` | Add taxonomy injection — orchestrator pre-reads taxonomy for target services and includes field lists in Rule Author prompt context |
| `third-party/android-sigma-rules/validation/logsource-taxonomy.yml` | **New** — field taxonomy for all 15 logsource services with `status: active/unwired` |
| `third-party/android-sigma-rules/validation/allowed-sources.json` | Fix `amnesty-tech` → `amnesty-investigations` |
| `third-party/android-sigma-rules/validation/validate-rule.py` | Update `valid_services` whitelist to all 15 services; fix `accessibility` → `accessibility_audit`, `appops` → `appops_audit` |
| `third-party/android-sigma-rules/validation/sir-schema.json` | Add optional top-level `requires_verification` boolean (SIR-level, not per-indicator) |
| `third-party/android-sigma-rules/ioc-data/package-names.yml` | Fix `amnesty-tech` → `amnesty-investigations` (4 entries) |
| `third-party/android-sigma-rules/ioc-data/c2-domains.yml` | Fix `amnesty-tech` → `amnesty-investigations` (22 entries) |
| `third-party/android-sigma-rules/ioc-data/cert-hashes.yml` | Fix `amnesty-tech` → `amnesty-investigations` (sources header + 3 entries) |
| `app/src/test/java/com/androdr/sigma/LogsourceTaxonomyCrossCheckTest.kt` | **New** — validates taxonomy matches `toFieldMap()` for all 15 services (member + extension function patterns) |

**Note:** The amnesty rename touches files in the `android-sigma-rules` submodule.
These changes are committed in the submodule first, then the submodule pointer is
bumped in AndroDR — same two-step pattern used in Bundle 1.

## Out of Scope

- No changes to Kotlin telemetry model classes
- No changes to the evaluator, parser, or rule engine
- No new SIGMA rules authored
- No schema-first redesign (future work for public rules repo)
- No changes to feed ingesters or `feed-state.json`
