# Sub-plan 1a Spec: Validator Sync + Build-time Gate

**Tracking issue:** #105  
**Parent epic:** #104  
**Meta-plan:** `docs/superpowers/plans/2026-04-11-ai-rule-framework-audit-meta-plan.md`  
**Depends on:** nothing (starting point)  
**Unblocks:** #106 (Gate 4 harness + IOC source validation), #107 (staging rerun + end-to-end proof)

---

## Problem

AndroDR rules are modified by two independent write paths:

1. **Dev pipeline** — human PRs edit bundled rules and the Kotlin parser in `AndroDR/`
2. **AI pipeline** — `/update-rules` generates rules validated by `validate-rule.py` + `rule-schema.json` in `android-sigma-rules/`

These two paths enforce different schemas. The Kotlin parser (`SigmaRuleParser.kt:155-169`) requires a top-level `category` field and accepts logsource services like `receiver_audit` and `tombstone_parser`. The Python validator (`validate-rule.py:63`) does not know about `category` and only accepts 5 of the 10+ real services. Neither side checks the other.

When dev PRs add fields or services without updating `rule-schema.json`, the AI pipeline either rejects valid rules (false negative) or accepts invalid ones (false positive). This drift caused all five staging rules to silently carry stale metadata for 9+ days.

The root cause is structural: the two paths share no authoritative schema, and nothing enforces that they agree.

## Solution

Make `android-sigma-rules` the single authoritative source of the rule schema. Bring it into AndroDR's build as a **git submodule** so both repos read the same file. Add a **Kotlin build-time gate** that cross-checks every bundled rule against both the Kotlin parser and the JSON schema. The build fails if they disagree — making it mechanically impossible to drift.

## Design decisions (resolved during brainstorming)

| # | Decision | Resolution | Rationale |
|---|---|---|---|
| D1 | Where does the authoritative schema live? | `android-sigma-rules` (Option D1 — git submodule into AndroDR) | The sigma-rules repo is conceptually upstream; it's a publishable detection-content project (Tier 1, own public repo). AndroDR is a consumer. The two-PR dance for schema changes is the price of structural discipline and prevents drift by construction. |
| D2 | Build-time gate mechanism? | Kotlin parser + JSON schema cross-check using `com.networknt:json-schema-validator:2.0.1` (Option B with library) | Catches drift in both directions: parser rejects what schema accepts → build fails; schema rejects what parser accepts → build fails. No Python dependency in the build. The library is pure JVM, supports JSON Schema draft 2020-12. |
| D3 | Scope: correlation rules included? | No — detection/atom rules only (Option B1) | Correlation rules have a different structure (`correlation.type`, `timespan`, etc.) that would require a new schema definition. Deferred to Bundle 3 (#109) alongside F8 (correlation rule integration tests). Existing `SigmaRuleParser.parseCorrelation()` continues as the only validator for correlation rules. |
| D4 | Submodule path? | `third-party/android-sigma-rules/` | Self-documenting convention for external content; sets a precedent for future external repos. |

---

## Architecture

### Repo layout after sub-plan 1a

```
AndroDR/                                          (main repo)
├── .gitmodules                                   (NEW — registers the submodule)
├── third-party/
│   └── android-sigma-rules/                      (NEW — git submodule, pinned SHA)
│       └── validation/
│           ├── rule-schema.json                  (authoritative schema, edited here)
│           ├── validate-rule.py                  (AI pipeline validator)
│           └── android-permissions.txt
├── app/
│   ├── build.gradle.kts                          (+1 test dependency)
│   ├── src/main/java/com/androdr/sigma/
│   │   └── SigmaRuleParser.kt                   (unchanged)
│   ├── src/main/res/raw/
│   │   └── sigma_androdr_*.yml                   (48 bundled rules, unchanged)
│   └── src/test/java/com/androdr/sigma/
│       ├── AllRulesHaveCategoryTest.kt           (existing, unchanged)
│       ├── AllCorrelationRulesFireTest.kt        (existing, unchanged)
│       └── BundledRulesSchemaCrossCheckTest.kt   (NEW — the build-time gate)
└── .github/workflows/
    └── android-build.yml                         (+1 line: submodule init)

android-sigma-rules/                              (canonical upstream, separate repo)
├── validation/
│   ├── rule-schema.json                          (UPDATED — synced with runtime)
│   ├── validate-rule.py                          (UPDATED — valid_services whitelist)
│   └── ...
└── ...
```

### Data flow: build-time gate

```
./gradlew check
  └── BundledRulesSchemaCrossCheckTest
        │
        ├── loads rule-schema.json from third-party/android-sigma-rules/validation/
        │   (fails with clear error if submodule not initialized)
        │
        ├── iterates app/src/main/res/raw/sigma_androdr_*.yml
        │   (excludes sigma_androdr_corr_*.yml — correlation rules deferred)
        │
        └── for each rule file:
              ├── SigmaRuleParser.parse(yaml) — must succeed
              │   (catches: missing category, invalid enum, bad modifier, etc.)
              │
              └── jsonSchemaValidator.validate(yamlAsJson, schema) — must pass
                  (catches: missing required field, unknown service, wrong type, etc.)
                  
              → if either fails: build fails with structured error + fix hint
```

### Data flow: AI pipeline (unchanged but now reliable)

```
/update-rules
  └── update-rules-validate skill
        └── Gate 1: validate-rule.py
              └── loads same rule-schema.json from android-sigma-rules/validation/
                  (same file, same commit — guaranteed by submodule pin)
```

### Drift-prevention guarantee

Any change to runtime requirements forces a change to `rule-schema.json`, which lives in the submodule. Updating the submodule pointer is itself a git operation visible in the AndroDR PR diff. Reviewers see the Kotlin change and the submodule bump together. The build fails unless they are consistent.

---

## Changes: `android-sigma-rules` repo

A single PR that syncs `rule-schema.json` and `validate-rule.py` with the current AndroDR runtime.

### rule-schema.json changes

**1. Add `category` to required fields:**

Current:
```json
"required": ["title", "id", "status", "description", "logsource", "detection", "level", "tags"]
```

Updated:
```json
"required": ["title", "id", "status", "description", "logsource", "detection", "level", "tags", "category"]
```

**2. Add `category` property definition:**

```json
"category": {
  "type": "string",
  "enum": ["incident", "device_posture"]
}
```

This matches `SigmaRuleParser.kt:162-168` which accepts exactly these two values (case-insensitive, mapped to `RuleCategory.INCIDENT` and `RuleCategory.DEVICE_POSTURE`).

**3. Expand `logsource.service` enum:**

Current (5 services):
```json
"enum": ["app_scanner", "device_auditor", "dns_monitor", "process_monitor", "file_scanner"]
```

Updated (10 services — matching all telemetry model classes with `toFieldMap()`):
```json
"enum": [
  "app_scanner", "device_auditor", "dns_monitor",
  "process_monitor", "file_scanner",
  "receiver_audit", "tombstone_parser",
  "accessibility", "appops", "network_monitor"
]
```

Source of truth for this list: the telemetry model classes that implement `toFieldMap()`:
- `AppTelemetry.kt` → `app_scanner`
- `DeviceTelemetry.kt` → `device_auditor`
- `DnsEvent.kt` → `dns_monitor`
- `ProcessTelemetry.kt` → `process_monitor`
- `FileArtifactTelemetry.kt` → `file_scanner`
- `ReceiverTelemetry.kt` → `receiver_audit`
- (tombstone, accessibility, appops, network) → respective services from bugreport parser modules

**4. Add optional fields that production rules already use:**

```json
"enabled": { "type": "boolean" },
"report_safe_state": { "type": "boolean" }
```

And inside the `display` object:
```json
"guidance": { "type": "string" }
```

These fields are consumed by `SigmaRuleParser.kt:171-172` (`enabled`, `reportSafeState`) and `SigmaRuleParser.kt:269` (`display.guidance`). Making them schema-known prevents the JSON schema validator from rejecting rules that use them (JSON Schema's `additionalProperties` default is permissive, but documenting them is correct practice).

### validate-rule.py changes

**1. Sync `valid_services` whitelist** (line 63):

```python
valid_services = {
    "app_scanner", "device_auditor", "dns_monitor",
    "process_monitor", "file_scanner",
    "receiver_audit", "tombstone_parser",
    "accessibility", "appops", "network_monitor",
}
```

No other changes to `validate-rule.py`. The script's logic is sound; only its data was stale.

### Verification before merging

Run `python validate-rule.py` against:
- All rules in the sigma-rules repo's service directories (must all pass)
- The 5 staging rules (capture which pass and which fail for reference during sub-plan 1c)

---

## Changes: `AndroDR` repo

A single PR that adds the submodule, the test dependency, the cross-check test, and the CI config.

### 1. Git submodule

```bash
git submodule add https://github.com/android-sigma-rules/rules.git third-party/android-sigma-rules
```

Pin to the commit SHA from the merged sigma-rules PR above.

### 2. Test dependency in `app/build.gradle.kts`

```kotlin
testImplementation("com.networknt:json-schema-validator:2.0.1")
```

This library is pure JVM, has no Android-specific dependencies, and supports JSON Schema draft 2020-12 (which `rule-schema.json` declares via `"$schema": "https://json-schema.org/draft/2020-12/schema"`). [Maven Central](https://mvnrepository.com/artifact/com.networknt/json-schema-validator), [GitHub](https://github.com/networknt/json-schema-validator).

### 3. New test: `BundledRulesSchemaCrossCheckTest.kt`

Location: `app/src/test/java/com/androdr/sigma/BundledRulesSchemaCrossCheckTest.kt`

**Structure:**

```kotlin
class BundledRulesSchemaCrossCheckTest {

    // --- Setup ---
    // Locate rule-schema.json from the submodule path
    // (fallback chain similar to AllRulesHaveCategoryTest.rulesDirectory())
    // Fail with a clear error if not found:
    //   "rule-schema.json not found. Run: git submodule update --init"
    
    // Load schema via JsonSchemaFactory (networknt library)
    // Locate res/raw directory (same fallback chain as existing tests)
    
    // --- Helpers ---
    // yamlToJsonNode(yamlString): parse YAML with snakeyaml-engine,
    //   convert the resulting Map to a Jackson JsonNode (networknt 
    //   uses Jackson internally). snakeyaml-engine is already a 
    //   project dependency.
    
    // detectionAndAtomRuleFiles(): same filter as AllRulesHaveCategoryTest
    //   — includes sigma_androdr_*.yml, excludes sigma_androdr_corr_*.yml
    
    // --- Test methods ---
    
    @Test
    fun `every bundled detection rule is accepted by SigmaRuleParser`()
    // Iterate detection/atom files, call SigmaRuleParser.parse(yaml)
    // Collect all failures, report as a single assertion with per-file detail
    
    @Test
    fun `every bundled detection rule passes JSON schema validation`()
    // Iterate detection/atom files, convert to JSON, validate against schema
    // Collect all failures, report with per-file detail + schema error messages
    
    @Test
    fun `schema file is reachable from submodule`()
    // Precondition check — fail fast with developer-friendly error
    // "third-party/android-sigma-rules not found. 
    //  Run: git submodule update --init"
}
```

**Error messages include:**
- Which rule file failed
- Which gate failed (Kotlin parser vs JSON schema)
- Exact validation error
- Fix hint: "If you added a new field or service to SigmaRuleParser, update rule-schema.json in the android-sigma-rules repo and bump the submodule."

### 4. CI workflow update

In `.github/workflows/android-build.yml`, add before the build step:

```yaml
- name: Initialize submodules
  run: git submodule update --init --recursive
```

### 5. Existing tests: no changes

`AllRulesHaveCategoryTest` stays as-is. It overlaps with part of the new cross-check (the category field) but provides a more focused error message for the most common failure mode. The overlap is harmless — two tests catching the same bug is better than zero.

`AllCorrelationRulesFireTest`, `SigmaRuleParserCategoryEnforcementTest`, and all other existing tests are untouched.

---

## Migration sequence

### Step 1: PR against `android-sigma-rules`

**Title:** "Sync rule-schema.json with AndroDR runtime requirements"

Contents:
- Update `rule-schema.json` (add `category` required, expand service enum, add optional fields)
- Update `validate-rule.py` (sync `valid_services` whitelist)
- Run validation against all existing rules + staging rules (capture results)
- Merge

### Step 2: PR against `AndroDR`

**Title:** "Add sigma-rules submodule + build-time schema cross-check gate"  
**Body includes:** `Closes #105`

Contents:
- Add submodule at `third-party/android-sigma-rules/` pinned to Step 1's merge commit
- Add `com.networknt:json-schema-validator:2.0.1` test dependency
- Add `BundledRulesSchemaCrossCheckTest.kt`
- Add `git submodule update --init` to CI workflow
- Run `./gradlew testDebugUnitTest` — all 48 rules must pass both Kotlin parser and JSON schema
- Merge

### Step 3: Verification (during PR review, not shipped)

Two intentional-break experiments to prove the drift loop is closed:

**Test A — "Dev adds a Kotlin field but forgets the schema."**
1. Temporarily add a required field to `SigmaRuleParser.parseDocument()` (e.g., require `foo`)
2. Run `./gradlew testDebugUnitTest` → Kotlin parser fails on every rule missing `foo`
3. Add `foo:` to one bundled rule → parser passes, but JSON schema fails (unknown property)
4. Only fix: update `rule-schema.json`, bump submodule → build green
5. Revert the experiment

**Test B — "Someone loosens the schema without touching the parser."**
1. Temporarily remove `category` from the `required` array in the submodule's `rule-schema.json`
2. Remove `category:` from one bundled rule
3. Run `./gradlew testDebugUnitTest` → Kotlin parser throws `SigmaRuleParseException`, schema passes (it's no longer required)
4. Cross-check test fails on the parser side, surfacing the inconsistency
5. Revert the experiment

### Step 4: Document the developer workflow

Add to CLAUDE.md under a new "Submodule: android-sigma-rules" section:

- After cloning AndroDR, run `git submodule update --init` once
- When adding a new field or logsource service to `SigmaRuleParser.kt`: first update `rule-schema.json` in the sigma-rules repo (open a PR there), merge it, then bump the submodule in AndroDR in the same PR as the Kotlin change
- The build-time cross-check test (`BundledRulesSchemaCrossCheckTest`) will fail if the schema and parser disagree

---

## Scope boundaries

### In scope for sub-plan 1a

- Sync `rule-schema.json` with current runtime (category, services, optional fields)
- Sync `validate-rule.py` whitelist
- Add git submodule to AndroDR
- Add `com.networknt:json-schema-validator:2.0.1` test dependency
- Add `BundledRulesSchemaCrossCheckTest.kt`
- Update CI workflow for submodule init
- Update CLAUDE.md with submodule developer workflow

### Explicitly out of scope

- **Correlation rule schema** — deferred to Bundle 3 (#109). No changes to correlation rule parsing, testing, or validation. `sigma_androdr_corr_*.yml` files are excluded from the cross-check.
- **IOC data validation** — deferred to sub-plan 1b (#106). `merge-ioc-data.py` untouched. IOC `source` field enforcement not in scope.
- **Gate 4 test harness** — deferred to sub-plan 1b (#106).
- **Staging rule re-validation** — deferred to sub-plan 1c (#107). The sigma-rules PR will run validation against staging rules for preview purposes, but no decisions or promotions happen in 1a.
- **Runtime changes** — `SigmaRuleParser.kt` is NOT modified. The parser already enforces everything correctly; only the external schema and the cross-check test are new.
- **`validate-rule.py` logic changes** — only the `valid_services` data constant is updated. No structural changes to the script.

---

## Success criteria

After both PRs merge:

1. `./gradlew testDebugUnitTest` passes with all 48 detection/atom rules validated against both the Kotlin parser and the JSON schema from the submodule
2. CI passes with the submodule initialized automatically
3. `python validate-rule.py <any-bundled-rule.yml>` passes in the sigma-rules repo (using the same schema)
4. It is mechanically impossible to ship a bundled rule that the Kotlin parser accepts but the JSON schema rejects (or vice versa) without a build failure
5. Developer workflow for schema changes is documented in CLAUDE.md
