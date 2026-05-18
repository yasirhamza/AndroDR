# Spec: `installed_app` broker-SDK rule pack

**Issue:** [#168](https://github.com/yasirhamza/AndroDR/issues/168) (parent: data-broker SDK detection).
**Sibling specs:**
- [`2026-05-17-data-broker-sdk-scanner-design.md`](2026-05-17-data-broker-sdk-scanner-design.md) — scanner extension that emits the new fields (shipped PR #183).
- [`2026-05-18-broker-sdk-sir-research-design.md`](2026-05-18-broker-sdk-sir-research-design.md) — SIR research pass (shipped PR #188).

**Scope of this spec:** authoring the **first detection rules** that consume the `embedded_component_class` taxonomy field added in PR #178. 4 SIGMA YAML rules for the four anchored broker SDKs, 4 positive test fixtures, and 2 `telemetry_gap` decision records for the un-anchored SDKs. No code changes in AndroDR repo proper — the work lives in the `android-sigma-rules` submodule plus a submodule-pointer bump.

**Date:** 2026-05-18

---

## Why

PR #188 produced 8 SIR JSONs but no detections fire from a SIR — only a rule can fire. Of the 6 SDK SIRs, four (Outlogic, Venntel, Predicio, Cuebiq) carry concrete `embedded_component_class` anchors that meet the SIGMA `|contains` rule pattern. Mobilewalla and Adsquare have documented gaps (no public Android SDK fingerprint) and produce `telemetry_gap` decisions instead of rules.

This is also the first user of the new `embedded_component_class` field anywhere in the corpus. The test fixtures shipped here become the precedent for how `embedded_*` rules are validated by Gate 4.

## Pack scope

### 4 SIGMA YAML rules

| File | ID | Threat | `embedded_component_class\|contains` values |
|---|---|---|---|
| `androdr_079_data_broker_outlogic.yml` | androdr-079 | Outlogic (X-Mode Social) | `io.xmode.BcnConfig`, `io.xmode.locationsdk` |
| `androdr_080_data_broker_venntel.yml` | androdr-080 | Venntel (Gravy GOLD legacy SDK) | `com.timerazor.gravysdk`, `com.gravy.gravysdk` |
| `androdr_081_data_broker_predicio.yml` | androdr-081 | Predicio (Telescope SDK) | `com.telescope.android`, `io.predic.tracker` |
| `androdr_082_data_broker_cuebiq.yml` | androdr-082 | Cuebiq | `com.cuebiq.cuebiqsdk.model.Collector`, `com.cuebiq.cuebiqsdk.receiver.CoverageReceiver` |

ID range 079–082 is the next contiguous block after androdr-078 (Meiya Pico, currently in staging). All 4 rules land at `third-party/android-sigma-rules/staging/app_scanner/`.

### 4 positive test fixtures

At `third-party/android-sigma-rules/validation/test-fixtures/`:

- `outlogic-positive-app.json`
- `venntel-positive-app.json`
- `predicio-positive-app.json`
- `cuebiq-positive-app.json`

Each is a minimal `AppTelemetry` JSON containing the SDK's class names in `embedded_component_class`. Assertions: own rule fires, the other 3 rules do not fire, the existing `benign-app.json` fires none of the 4.

### 2 `telemetry_gap` decision records

For Mobilewalla and Adsquare. Recorded in the `update-rules-author` skill's standard decision-manifest output (format: `decisions-schema.json`). Each decision quotes the gap reason from the SIR's `threat.description` and recommends future reverse-engineering when evidence appears. No YAML rules ship for these two.

### Explicitly NOT in this pack

- Outlogic's `io.mysdk.*` prefix — dropped per the SIR's own collision note (shared with SignalFrame/WirelessRegistry; would generate false positives).
- The `package_name` indicators from the SIRs. Those are historical "this app was a documented data source at time T," not "this app currently ships the SDK." Adding them would claim, e.g., that Muslim Pro is currently broker-pipelined when the developer removed the SDK in 2020.
- All `domain` indicators from the SIRs. Those feed the future `dns` rule pack — separate spec.
- The 2 aggregator SIRs (Gravy Analytics, Babel Street). Deferred to the DNS pack.
- The combination rule (sensitive permission + broker SDK) from the parent #168 issue. Gated on this pack landing first.
- Promotion of these rules from `staging/app_scanner/` to `app_scanner/`. Follow-up PR after they have either fired on a real device or sat in staging for an agreed cooling period.

## Per-rule design

All 4 rules share this structure (showing Outlogic as exemplar; others differ only in the fields called out in the deltas table below):

```yaml
title: Embedded data-broker SDK — Outlogic (X-Mode Social)
id: androdr-079
status: experimental
description: App embeds the Outlogic (formerly X-Mode Social) location-data
  broker SDK. Outlogic was banned from Play Store in December 2020 and
  settled with the FTC in April 2024 over sale of sensitive location data.
author: AndroDR
date: 2026/05/18
references:
    - https://reports.exodus-privacy.eu.org/en/trackers/354/
    - https://www.ftc.gov/news-events/news/press-releases/2024/04/ftc-finalizes-order-x-mode-successor-outlogic-prohibiting-it-sharing-or-selling-sensitive-location
tags:
    - attack.t1430        # Location Tracking
    - attack.t1437.001    # Application Layer Protocol — Web Protocols
logsource:
    product: androdr
    service: app_scanner
detection:
    selection:
        embedded_component_class|contains:
            - 'io.xmode.BcnConfig'
            - 'io.xmode.locationsdk'
    filter_system_app:
        is_system_app: true
    condition: selection and not filter_system_app
level: medium
category: incident
falsepositives:
    - "App that legitimately embeds the SDK with disclosed user consent; rare given the SDK's regulatory history."
    - "Pre-installed system app shipping the SDK (filtered out by filter_system_app)."
display:
    category: app_risk
    icon: warning
    triggered_title: "Data-broker SDK: Outlogic"
    evidence_type: ioc_match
    summary_template: "Outlogic SDK class detected: {matched_value}"
    guidance: "This app embeds the Outlogic (X-Mode) location-broker SDK, known
      for reselling fine-grained location data to military and federal LE
      customers. Consider uninstalling or denying location permissions."
remediation:
    - "Review whether you need this app; broker SDKs run in the background."
    - "If keeping the app, deny ACCESS_BACKGROUND_LOCATION and ACCESS_FINE_LOCATION."
```

### Deltas for the other 3 rules

Everything else is structurally identical (status, level, category, logsource, filter_system_app, attack tags, display.category, display.icon, evidence_type=`ioc_match`, remediation pattern). The `evidence_type` enum is constrained by `rule-schema.json` to `none / cve_list / ioc_match / permission_cluster`; `ioc_match` is the correct choice — class-name prefixes are IOC values in the same sense as androdr-001's package-name IOCs.

| Field | androdr-080 (Venntel) | androdr-081 (Predicio) | androdr-082 (Cuebiq) |
|---|---|---|---|
| `title` | `Embedded data-broker SDK — Venntel (Gravy GOLD legacy)` | `Embedded data-broker SDK — Predicio (Telescope)` | `Embedded data-broker SDK — Cuebiq` |
| `embedded_component_class\|contains` values | `com.timerazor.gravysdk`, `com.gravy.gravysdk` | `com.telescope.android`, `io.predic.tracker` | `com.cuebiq.cuebiqsdk.model.Collector`, `com.cuebiq.cuebiqsdk.receiver.CoverageReceiver` |
| `references` | TimeRAZOR Javadoc + FTC Gravy/Venntel consent order | Vice Motherboard "Salaat First" article + Exodus tracker #357 | glorifiedgrep _TRACKERS dict + AdExchanger Cuebiq SDK shutdown |
| `description` | App embeds the legacy Gravy GOLD SDK published under TimeRAZOR. Venntel resold this data to ICE/CBP/DEA per FTC complaint (Dec 2024). | App embeds the Predicio Telescope SDK. Predicio was removed from Play Store in February 2021 after Joseph Cox / Vice exposed location-data exfiltration to predic.io. | App embeds the Cuebiq location-data broker SDK. Cuebiq-sourced data was used in the NYT "Privacy Project" (Dec 2019) to re-identify named individuals including a Secret Service agent. |
| `display.triggered_title` | `Data-broker SDK: Venntel` | `Data-broker SDK: Predicio` | `Data-broker SDK: Cuebiq` |
| `display.summary_template` | `Venntel SDK class detected: {matched_value}` | `Predicio SDK class detected: {matched_value}` | `Cuebiq SDK class detected: {matched_value}` |
| `display.guidance` | One sentence on the Venntel pipeline + remediation pattern. | One sentence on the Predicio ban + remediation. | One sentence on the Cuebiq NYT exposé + remediation. |

## Test fixtures

Pattern (Outlogic example):

```json
{
  "fixture_id": "outlogic-positive-app",
  "description": "Positive fixture for androdr-079 — app embedding the Outlogic SDK",
  "app_telemetry": {
    "package_name": "com.example.outlogicembedder",
    "is_system_app": false,
    "embedded_component_class": [
      "io.xmode.BcnConfig",
      "io.xmode.locationsdk.GeoSyncService"
    ],
    "embedded_native_lib": [],
    "permissions": ["android.permission.ACCESS_FINE_LOCATION"]
  },
  "expected_rule_ids": ["androdr-079"],
  "must_not_fire_rule_ids": ["androdr-080", "androdr-081", "androdr-082"]
}
```

If the existing fixture schema (read from `benign-app.json` at implementation time) uses different field names for the assertion block, the plan adapts to match.

Each rule's fixture contains 1–2 class entries matching that rule's `|contains` values. Plus a single `permissions` entry just to make the telemetry plausibly app-shaped (not load-bearing for the rule).

## `telemetry_gap` decisions

Two entries in the author's decision-manifest output (format per `validation/decisions-schema.json`):

```yaml
decisions:
  - rule_id: null
    field: "rule_creation"
    type: "telemetry_gap"
    chosen: "skip"
    alternative: "create installed_app rule with embedded_component_class anchor"
    reasoning: "Mobilewalla SIR (sir-2026-05-18-mobilewalla) explicitly states no public Android package prefix, class name, native library, or telemetry hostname tied to a deployed first-party Mobilewalla on-device SDK. ~95% of data sourced via RTB bidstream per FTC complaint. Recommend revisiting if reverse-engineering of LendBetter/Covariate-integrated APK surfaces concrete anchors."
    missing_field: "concrete_mobilewalla_sdk_anchor"
    source_sir: "sir-2026-05-18-mobilewalla"

  - rule_id: null
    field: "rule_creation"
    type: "telemetry_gap"
    chosen: "skip"
    alternative: "create installed_app rule with embedded_component_class anchor"
    reasoning: "Adsquare SIR (sir-2026-05-18-adsquare) confirms aggregator posture by three independent sources (vendor self-statement to The Markup, own GitHub artifacts being server-side Java, absence from Exodus Privacy tracker DB). No first-party Android SDK exists to fingerprint. Recommend revisiting if a Databroker-Files-implicated German app yields an Adsquare-attributed package name on reverse engineering."
    missing_field: "concrete_adsquare_sdk_anchor"
    source_sir: "sir-2026-05-18-adsquare"
```

The `missing_field` value (`concrete_mobilewalla_sdk_anchor`) is descriptive, not a literal taxonomy field name — the taxonomy field (`embedded_component_class`) is present and supported; the gap is in the SIR's indicator content, not in instrumentation.

## Pipeline + validation flow

1. **Submodule branch** — open `feat/168-installed-app-broker-sdk-pack` in `third-party/android-sigma-rules/`.

2. **Author** via `update-rules-author` skill against the 6 SDK SIRs. Input: the 6 JSONs as an array, `next_id: 79`, the existing rule index, taxonomy fields for `app_scanner` (auto-extracted by the orchestrator). Expected output: 4 rule candidates + 2 `telemetry_gap` decisions.

3. **Write fixtures** alongside the rules. The author skill does not produce fixtures; the plan adds them in the same submodule branch by reading `benign-app.json` to confirm shape and applying the pattern above.

4. **Validate** via `update-rules-validate` (5 gates):
   - Gate 1 — schema/parser. Passes because the new fields are in the taxonomy and `|contains` is in the supported-modifiers list.
   - Gate 2 — rule lint. Duplicate-ID + cross-ref checks.
   - Gate 3 — provenance. Each rule traces to a SIR in PR #188 with concrete `source_urls`.
   - Gate 4 — test harness. Each positive fixture fires its own rule; benign fires none; cross-fixture isolation holds. This is the gate that needs the new fixtures.
   - Gate 5 — LLM self-review via `update-rules-review` skill. Independent reviewer agent.

5. **Two-reviewer cycle** in parallel after the validator passes:
   - Spec-compliance reviewer: candidates match this spec's per-rule deltas, fixtures match the documented pattern, decisions cite SIRs correctly.
   - Harsh-quality reviewer: rule descriptions are anchored on cited references, match-value lists don't include the dropped `io.mysdk.*`, `telemetry_gap` decisions capture the SIRs' gap reasoning.

6. **Commit + push** the submodule branch; open PR in `android-sigma-rules`.

7. **AndroDR-side PR** — bumps submodule pointer to the merged commit. No Kotlin changes. `BundledRulesSchemaCrossCheckTest` passes (taxonomy and `AppTelemetry` are already aligned).

8. **On-device dry-run** — install the new submodule on Z Fold 2 (R3CR300WRRH), run a scan from the Dashboard, confirm zero findings for these 4 rule IDs (the device is not expected to contain broker-SDK-shipping apps). Capture `adb logcat -s AppScanner:D` output as evidence in the AndroDR PR.

## Acceptance criteria

- [ ] 4 SIGMA YAML rules at `third-party/android-sigma-rules/staging/app_scanner/androdr_{079,080,081,082}_data_broker_*.yml`, each `status: experimental`, `level: medium`, `service: app_scanner`, matching only on the class-name prefixes locked in section "Per-rule design" (exemplar YAML for Outlogic; deltas table for the other 3) — and notably NOT on `io.mysdk.*`.
- [ ] 4 positive test fixtures at `third-party/android-sigma-rules/validation/test-fixtures/{outlogic,venntel,predicio,cuebiq}-positive-app.json`, each asserting own-rule-fires + other-3-do-not + benign-fires-none.
- [ ] 2 `telemetry_gap` decisions in the author's manifest output for Mobilewalla and Adsquare, citing their SIR IDs and quoting the gap reason. No YAML rules ship for these two.
- [ ] All 5 validator gates green.
- [ ] Two-reviewer cycle (spec-compliance + harsh-quality, parallel) passes; failures trigger targeted re-author + re-review.
- [ ] Submodule PR merged. AndroDR PR bumping the submodule pointer also merged. `BundledRulesSchemaCrossCheckTest` green.
- [ ] On-device dry-run: zero findings for the 4 new rule IDs on Z Fold 2; `adb logcat` evidence captured in the AndroDR PR description.

## Out of scope

- DNS rule pack consuming the 2 aggregator SIRs plus the 8 SIRs' domain indicators.
- The combination rule from the parent #168 issue.
- Promotion of the 4 rules from `staging/app_scanner/` to `app_scanner/`.
- Bundling the rules into `app/src/main/res/raw/` for the on-device APK.
- Reverse-engineering Mobilewalla or Adsquare APKs to surface concrete anchors.

## Handoff to next session

After this pack ships, the next #168 session is the DNS rule pack — same pattern, different taxonomy field (likely `dns_monitor.queried_hostname`), consuming the 8 SIRs' domain indicators and the 2 aggregator SIRs that were skipped here.
