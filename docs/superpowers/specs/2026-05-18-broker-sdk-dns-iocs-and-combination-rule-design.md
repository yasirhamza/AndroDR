# Spec: broker-SDK DNS IOCs + combination rule

**Issue:** [#168](https://github.com/yasirhamza/AndroDR/issues/168) (parent: data-broker SDK detection — final two deliverables).
**Sibling specs:**
- [`2026-05-17-data-broker-sdk-scanner-design.md`](2026-05-17-data-broker-sdk-scanner-design.md) — scanner extension (PR #183).
- [`2026-05-18-broker-sdk-sir-research-design.md`](2026-05-18-broker-sdk-sir-research-design.md) — SIR research pass (PR #188).
- [`2026-05-18-broker-sdk-installed-app-rule-pack-design.md`](2026-05-18-broker-sdk-installed-app-rule-pack-design.md) — `installed_app` rule pack (PR #189 → #190 → #192).

**Scope of this spec:** the two remaining #168 deliverables — DNS-side broker telemetry detection and the combination rule (broker SDK + sensitive location permission on the same app). Combined into one spec because they share SIR provenance and total surface is small.

**Date:** 2026-05-18

---

## Why

Two pieces of the original #168 vision remain unshipped:

1. **DNS detection** of broker telemetry hostnames. Per-vendor rule files were initially considered (the `androdr-005 Graphite/Paragon` precedent for honest attribution), but the project's actual convention is IOC-database entries consumed by the existing `androdr-003 DNS query to known C2 domain` rule — attribution flows through the entry's `family` and `category` metadata, not a per-vendor rule. The DNS work is therefore data, not new SIGMA rules.

2. **Combination rule** — fires when an installed app BOTH embeds one of the documented broker SDKs (already covered by `androdr-079..082`) AND holds `ACCESS_FINE_LOCATION` or `ACCESS_BACKGROUND_LOCATION`. This is the docu's exact threat model ("weather app + location permission + embedded broker SDK = broker pipeline active") and the highest-signal anchor in #168. Cannot be expressed via IOC database — no single indicator; the rule combines two independent app properties.

After these PRs merge, #168 is closed.

## Deliverables

**A. DNS detection via IOC database** (submodule changes only — no new SIGMA rules):

- Add `"DATA_BROKER_SDK"` to the `category` enum in `validation/ioc-entry-schema.json`.
- Add 18 broker-telemetry domain entries to `ioc-data/c2-domains.yml` under a clearly delimited section header. All use `category: "DATA_BROKER_SDK"`, `severity: "MEDIUM"`, `source: "threat_research"`, and a non-empty `family:` field. The existing `androdr-003` rule picks them up automatically via `domain|ioc_lookup: domain_ioc_db`.

**B. Combination SIGMA rule:**

- New rule `androdr_083_broker_sdk_with_location_permission.yml` in `staging/app_scanner/` (submodule).
- Bundled into `app/src/main/res/raw/sigma_androdr_083_*.yml` (AndroDR) with R.raw registration in `SigmaRuleEngine.kt`'s `BUNDLED_RULE_IDS`.
- Gate-4 fixture `app/src/test/resources/gate4-fixtures/broker-sdk-with-location.yml`.

## IOC inventory

Drawn from the 8 SIRs at `docs/superpowers/research/2026-05-18-broker-sdks/`. The `family` field carries vendor attribution; `category: DATA_BROKER_SDK` carries pipeline-type attribution.

| Family | Domains | SIR source | Count |
|---|---|---|---|
| `Outlogic` | `xmode.io`, `outlogic.io`, `api.myendpoint.io`, `bin5y4muil.execute-api.us-east-1.amazonaws.com`, `api.smartechmetrics.com` | `sir-2026-05-18-outlogic` (Exodus tracker #354 + FTC docs) | 5 |
| `Venntel` | `findgravy.com`, `api.findgravy.com`, `ws.findgravy.com`, `api.foozor.com` | `sir-2026-05-18-venntel` (TimeRAZOR Javadoc + mobiletrackers list) | 4 |
| `Mobilewalla` | `mobilewalla.com` | `sir-2026-05-18-mobilewalla` (FTC complaint + apitracker.io) — apex only; SIR found no subdomain enumeration | 1 |
| `Adsquare` | `adsquare.com`, `help.adsquare.com` | `sir-2026-05-18-adsquare` (vendor self-statement + Netzpolitik) | 2 |
| `Predicio` | `sdk.predic.io`, `predic.io` | `sir-2026-05-18-predicio` (Vice Motherboard + Exodus tracker #357) | 2 |
| `Gravy Analytics` | `gravyanalytics.com`, `unacast.com`, `venntel.com`, `explore.venntel.com` | `sir-2026-05-18-gravy-analytics` (FTC + EFF + 404 Media) | 4 |
| **Total** | | | **18** |

**Skips** (each documented in its SIR):

- **Cuebiq** — SIR documented zero reachable telemetry domains. No entries until future RE surfaces concrete hostnames.
- **Babel Street / LocateX** — SIR explicitly warns its domains (`babelstreet.com` cluster) are analyst-side (LE/IC workstation traffic), not target-side. Including them would create high-FP signals on consumer devices that happen to browse to the vendor's marketing pages. The SIR's own recommendation is to skip target-side detection.

### IOC entry shape

Exemplar:

```yaml
# Data-broker SDK telemetry — AndroDR #168
# Detection model: app embeds a broker SDK (rules androdr-079..082) and
# the SDK transmits to these endpoints. androdr-003 (generic DNS IOC
# rule) surfaces the family attribution via the entry's metadata.

- indicator: "api.myendpoint.io"
  family: "Outlogic"
  category: "DATA_BROKER_SDK"
  severity: "MEDIUM"
  description: "Outlogic (X-Mode Social) location-broker SDK telemetry endpoint. Per Exodus Privacy tracker #354."
  source: "threat_research"
```

All 18 entries follow this exact shape — only `indicator`, `family`, and `description` differ.

### Severity policy

Uniform `MEDIUM` across all 18 entries. Matches the per-SDK SIGMA rule severity locked in PR #192. Privacy harm tier — a step below stalkerware/spyware (`CRITICAL` in the existing `c2-domains.yml`).

### Schema bump

One line added to the category enum in `validation/ioc-entry-schema.json`:

```diff
   "enum": [
     "STALKERWARE",
     "SPYWARE",
     "MALWARE",
     "NATION_STATE_SPYWARE",
     "FORENSIC_TOOL",
-    "MONITORING"
+    "MONITORING",
+    "DATA_BROKER_SDK"
   ]
```

No Kotlin changes required. Confirmed by reading `app/src/main/java/com/androdr/ioc/IocDatabase.kt:62`: the runtime treats `category` as an opaque `String?` — the string flows through to display unchanged. The schema bump is the only enforcement point.

### File-naming nit

`c2-domains.yml` is misnamed for broker telemetry (these aren't command-and-control). The lookup-DB infrastructure routes both through `domain_ioc_db`, so the file is effectively the project's domain-IOC registry. A rename would cascade through `ioc-lookup-definitions.yml`, AndroDR's `ScanOrchestrator`, and `androdr-003`'s lookup name. Too much scope creep for #168. The new section header in `c2-domains.yml` acknowledges the broader scope in a comment.

## Combination rule

### Body (full YAML)

Path: `third-party/android-sigma-rules/staging/app_scanner/androdr_083_broker_sdk_with_location_permission.yml`

```yaml
title: App embeds broker SDK and holds sensitive location permission
id: androdr-083
status: experimental
category: incident
description: >
    Detects an installed app that BOTH embeds one of the documented
    data-broker SDKs (Outlogic, Venntel, Predicio, Cuebiq) AND holds
    ACCESS_FINE_LOCATION. This is the threat model from the DW
    Documentary "Dangerous apps — In the web of data brokers":
    ordinary apps (weather, classifieds, dating, games) embed a
    location-broker SDK and request location permission, enabling the
    broker pipeline to sell precise-movement data to LE and military
    buyers. Higher signal than either anchor alone because the AND
    models the full pipeline.

    Note on permission matching: AndroDR's AppScanner emits the
    `permissions` field as short names (the surveillance-permission
    subset, with `android.permission.` stripped — see AppScanner.kt
    line 275). ACCESS_BACKGROUND_LOCATION is not tracked in that
    subset; matching on ACCESS_FINE_LOCATION suffices because Android
    11+ requires FINE to be granted as a prerequisite for BACKGROUND.
author: AndroDR (AI-generated)
date: 2026/05/18
references:
    - https://reports.exodus-privacy.eu.org/en/trackers/354/
    - https://www.ftc.gov/news-events/news/press-releases/2024/04/ftc-finalizes-order-x-mode-successor-outlogic-prohibiting-it-sharing-or-selling-sensitive-location
tags:
    - attack.t1430
    - attack.t1437.001
logsource:
    product: androdr
    service: app_scanner
detection:
    broker_sdk:
        embedded_component_class|contains:
            - 'io.xmode.BcnConfig'
            - 'io.xmode.locationsdk'
            - 'com.timerazor.gravysdk'
            - 'com.gravy.gravysdk'
            - 'com.telescope.android'
            - 'io.predic.tracker'
            - 'com.cuebiq.cuebiqsdk.model.Collector'
            - 'com.cuebiq.cuebiqsdk.receiver.CoverageReceiver'
    sensitive_location:
        permissions|contains: 'ACCESS_FINE_LOCATION'
    filter_system_app:
        is_system_app: true
    condition: broker_sdk and sensitive_location and not filter_system_app
level: high
display:
    category: app_risk
    icon: warning
    triggered_title: "Active broker pipeline: SDK + location permission"
    evidence_type: ioc_match
    summary_template: "Broker SDK + sensitive location permission on the same app: {matched_value}"
    guidance: "This app embeds a documented location-broker SDK AND holds sensitive location permission — the broker pipeline is active. Either uninstall the app or revoke its location permission. The per-SDK rule for this app will also fire; this rule highlights the higher-signal combination."
falsepositives:
    - "App that legitimately embeds the SDK with disclosed user consent AND has location-essential functionality (rare given regulatory history)."
    - "Pre-installed system app shipping the SDK (filtered out by filter_system_app)."
remediation:
    - "REVOKE location permissions for this app: Settings > Apps > [this app] > Permissions > Location > Don't allow."
    - "Consider uninstalling — broker SDKs run in the background even when the app isn't open."
```

The 8 prefixes in `broker_sdk.embedded_component_class|contains` are the exact union of the match values from `androdr-079..082`. The `io.mysdk.*` exclusion (dropped from `androdr-079` due to SignalFrame/WirelessRegistry collision) is preserved here — same defended-by-the-fixture pattern.

`level: high` is one tier above the per-SDK rules (`medium`) because the combination is a stronger detection: a broker SDK on its own is privacy harm in latent form, but the AND with `ACCESS_*_LOCATION` confirms the pipeline is actively wired. The per-SDK rule will also fire on the same app, so this rule complements rather than replaces the per-SDK findings.

### Gate-4 fixture

Path: `app/src/test/resources/gate4-fixtures/broker-sdk-with-location.yml`

```yaml
# Fixture for androdr-083: broker SDK + sensitive location permission.
# Exercises the AND condition: positive fires only when BOTH clauses hold.
rule_file: sigma_androdr_083_broker_sdk_with_location_permission.yml
service: app_scanner
true_positives:
  - package_name: "com.example.outlogicembedder"
    is_system_app: false
    embedded_component_class:
      - "io.xmode.BcnConfig"
    permissions:
      - "android.permission.ACCESS_BACKGROUND_LOCATION"
      - "android.permission.INTERNET"
  - package_name: "com.example.cuebiqembedder"
    is_system_app: false
    embedded_component_class:
      - "com.cuebiq.cuebiqsdk.model.Collector"
    permissions:
      - "android.permission.ACCESS_FINE_LOCATION"
true_negatives:
  # System-app variant — filter_system_app suppresses
  - package_name: "com.example.outlogicembedder"
    is_system_app: true
    embedded_component_class:
      - "io.xmode.BcnConfig"
    permissions:
      - "android.permission.ACCESS_BACKGROUND_LOCATION"
  # Broker SDK but NO location permission — the AND fails
  - package_name: "com.example.outlogicnoperm"
    is_system_app: false
    embedded_component_class:
      - "io.xmode.BcnConfig"
    permissions:
      - "android.permission.INTERNET"
  # Location permission but NO broker SDK — defends against misread that the rule fires on permission alone
  - package_name: "com.example.benignmapsapp"
    is_system_app: false
    embedded_component_class:
      - "com.maps.legitimate.NavigationService"
    permissions:
      - "android.permission.ACCESS_FINE_LOCATION"
      - "android.permission.ACCESS_BACKGROUND_LOCATION"
  # SignalFrame's io.mysdk.* (intentionally NOT in the broker_sdk match set per androdr-079's exclusion) + location permission
  - package_name: "com.example.signalframeembedder"
    is_system_app: false
    embedded_component_class:
      - "io.mysdk.networkmodule.network.networking.wirelessregistry.WrxConfig"
    permissions:
      - "android.permission.ACCESS_BACKGROUND_LOCATION"
```

The fifth `true_negative` (SignalFrame) is load-bearing — it asserts that the combination rule honors the same `io.mysdk.*` exclusion as `androdr-079`.

## Pipeline + validation flow

1. **Submodule branch** — `feat/168-dns-iocs-and-combination-rule` in `third-party/android-sigma-rules/`.
2. **Schema bump** — add `DATA_BROKER_SDK` to `validation/ioc-entry-schema.json` category enum.
3. **IOC entries** — append 18 entries to `ioc-data/c2-domains.yml` under a section header.
4. **Combination rule** — write `staging/app_scanner/androdr_083_broker_sdk_with_location_permission.yml`.
5. **Submodule validators** (Gates 1–3):
   - `validate-rule.py` on `androdr_083`.
   - `validate-ioc-data.py` on the updated `c2-domains.yml`.
   - `validate-ioc-complementarity.py` (project IOC dedup check).
6. **Submodule PR + admin-merge.**
7. **AndroDR branch** — `feat/168-dns-iocs-and-combination-rule`.
8. **Submodule pointer bump** + copy `androdr_083` YAML into `res/raw/` + add the Gate-4 fixture + register the new rule in `SigmaRuleEngine.kt`'s `BUNDLED_RULE_IDS`. The `BundledRulesManifestCompletenessTest` gate from PR #191 will fail otherwise — that's the whole point of that test.
9. **AndroDR unit tests:**
   - `GateFourFixtureTest`.
   - `BundledRulesManifestCompletenessTest` (the gate from PR #191).
   - `BundledRulesSchemaCrossCheckTest`.
   - `IocDataSchemaCrossCheckTest`.
   - `SigmaRuleParserTest`.
   - Full `./gradlew testDebugUnitTest lintDebug :app:detekt`.
10. **Gate 5 LLM self-review** on `androdr-083` — dispatch an Agent (general-purpose) with the rule body + SIR summary + similar-rule context, applying the 5 criteria from `.claude/commands/update-rules-review.md` (logical correctness, FP risk, severity, completeness, remediation). The skill is subagent-shaped so the criteria are embedded in the prompt rather than invoked via the `Skill` tool.
11. **Two-reviewer cycle** (spec-compliance + harsh-quality, parallel).
12. **AndroDR PR.**
13. **On-device positive verification** on Z Fold 2: build a fixture APK declaring an Outlogic class + holding `ACCESS_FINE_LOCATION` in its manifest, install via `adb`, scan, confirm `androdr-083` fires and `androdr-079` also fires (both should). Uninstall fixture, clean workspace.
14. **Merge both PRs.** Submodule PR admin-merges (light-CI submodule, established pattern across PRs #22 and #23). AndroDR PR waits for CI to go green and merges without `--admin` — GHA is now enforced on this repo as of 2026-05-18.

## Acceptance criteria

- [ ] `validation/ioc-entry-schema.json` has `"DATA_BROKER_SDK"` in the `category` enum.
- [ ] `ioc-data/c2-domains.yml` has 18 broker-telemetry entries under a clear section header. All entries have `category: "DATA_BROKER_SDK"`, `severity: "MEDIUM"`, `source: "threat_research"`, and a non-empty `family:` field (Outlogic / Venntel / Mobilewalla / Adsquare / Predicio / Gravy Analytics).
- [ ] `validate-ioc-data.py`, `validate-rule.py`, `validate-ioc-complementarity.py` all green on the submodule branch.
- [ ] `androdr_083_broker_sdk_with_location_permission.yml` lives in `staging/app_scanner/` with the exemplar body above; `status: experimental`, `level: high`, `category: incident`.
- [ ] Submodule PR merged.
- [ ] AndroDR PR: submodule pointer bumped, `sigma_androdr_083_*.yml` bundled in `res/raw/`, R.raw reference added to `SigmaRuleEngine.kt`'s `BUNDLED_RULE_IDS`, Gate-4 fixture in place.
- [ ] All AndroDR unit tests green, including `BundledRulesManifestCompletenessTest`.
- [ ] Gate 5 LLM review on `androdr-083`: `pass` or `pass_with_notes` with `fp_risk: low`.
- [ ] Two-reviewer cycle: both PASS or ACCEPTABLE.
- [ ] On-device verification: positive fixture (Outlogic class + `ACCESS_FINE_LOCATION`) installed on Z Fold 2 → scan → `androdr-083` fires; fixture uninstalled and workspace clean.
- [ ] Submodule PR squash-merged via admin. AndroDR PR squash-merged after CI is green (no `--admin`).

## Out of scope

- Promoting `androdr-083` from `staging/app_scanner/` to `app_scanner/` (`status: experimental` → `production`). Follow-up PR after observation, matching the precedent set by PR #192 for the broker-SDK pack.
- Cuebiq DNS coverage — no telemetry domains documented in the SIR. Awaits future RE.
- Babel Street domain coverage — analyst-side per the SIR's warning. Intentionally not bundled; revisit if a target-side use case appears.
- Renaming `c2-domains.yml` to reflect its broader role. Cosmetic; separate cleanup PR.

## Handoff after merge

These two PRs combined with the existing #168 commit ladder close the issue:

- `3e284ce` scanner extension (#183)
- `178bec9` SIR research pass (#188)
- `53c53d5` `installed_app` rule pack (#189)
- `957bf64` loader manifest fix (#190)
- `28e9a3b` loader-manifest completeness gate + 6 latent fixes (#191)
- `c7691f4` broker-SDK rules promoted to production (#192)
- **(this spec)** DNS IOCs + combination rule

After merge, the AndroDR PR description includes `Closes #168` so the issue auto-closes.
