# Refactor Plan 1: Rule Engine Foundation

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Parent refactor:** Unified telemetry/findings architecture (tracking issue #84). See `docs/superpowers/specs/2026-04-09-unified-telemetry-findings-refactor-design.md` for the full design.

**Plan order:** This is plan 1 of 7. Plans execute strictly in order on branch `claude/unified-telemetry-findings-refactor`. Plan 2 starts after plan 1's final commit.

**Goal:** Establish the rule engine foundation: add a new `RuleCategory` enum (INCIDENT / DEVICE_POSTURE) distinct from the existing `FindingCategory`, require a top-level `category:` field on every bundled rule YAML, extract an explicit `SeverityCapPolicy`, implement correlation-rule category propagation, add a disabled-by-default rule mechanism, and add a build-time test that prevents anyone from shipping a `device_posture` rule that declares a severity above `medium`.

**Architecture:** `RuleCategory` lives on `SigmaRule` and drives policy only (severity cap, correlation propagation). The existing `FindingCategory` enum (DEVICE_POSTURE / APP_RISK / NETWORK) is untouched — it continues to drive UI display and scoring. The two are orthogonal: an APP_RISK finding produced by an `incident`-category rule is perfectly normal. All 38 bundled detection + atom rules get a top-level `category:` field; the 4 correlation rules do NOT (their category is derived). `SigmaRuleEvaluator` applies `SeverityCapPolicy` when constructing findings. `SigmaCorrelationEngine` determines effective category per correlation by inspecting member rule categories.

**Tech Stack:** Kotlin 1.9, JUnit 4, MockK, kotlinx.serialization, Android Room (not touched by this plan), YAML rule files loaded from `res/raw`.

**Acceptance criteria for plan 1 completion:**
- Every bundled rule YAML file declares a top-level `category:` field (INCIDENT or DEVICE_POSTURE) — except correlation rules which derive it.
- `SigmaRuleParser` fails with a clear error if a non-correlation rule is missing `category:`.
- `SeverityCapPolicy` object exists and is applied by `SigmaRuleEvaluator` when building findings.
- `SigmaCorrelationEngine` determines effective rule category from member rules (any INCIDENT member → INCIDENT correlation).
- `SigmaRule` has an `enabled: Boolean` field (default true); engine skips disabled rules.
- Build-time test `AllRulesHaveCategoryTest` enumerates bundled rules and asserts category presence + posture cap compliance.
- `./gradlew testDebugUnitTest` passes.
- `./gradlew lintDebug` passes.
- `./gradlew assembleDebug` succeeds.
- `FindingCategory` enum values are unchanged. UI code is untouched. Consumer code (ScanResult, AppScanViewModel, DeviceAuditViewModel, TimelineAdapter, ScanOrchestrator) is untouched.

---

## File Structure

### Created

- `app/src/main/java/com/androdr/sigma/RuleCategory.kt` — new enum, 2 values (INCIDENT, DEVICE_POSTURE), used by SigmaRule for policy classification.
- `app/src/main/java/com/androdr/sigma/SeverityCapPolicy.kt` — singleton object holding the category → max-level map and the `applyCap(category, declared)` function. Testable in isolation.
- `app/src/test/java/com/androdr/sigma/SeverityCapPolicyTest.kt` — unit tests for the cap policy.
- `app/src/test/java/com/androdr/sigma/AllRulesHaveCategoryTest.kt` — build-time enforcement test. Enumerates every `sigma_androdr_*.yml` in `res/raw`, parses each, and asserts (a) every detection/atom rule declares `category`, (b) every `category: device_posture` rule declares `level` ≤ `medium`.
- `app/src/test/java/com/androdr/sigma/SigmaCorrelationEngineCategoryPropagationTest.kt` — unit tests for correlation propagation logic.
- `app/src/test/java/com/androdr/sigma/SigmaRuleParserCategoryTest.kt` — unit tests for parser category field handling (required, parsed, error on missing).
- `app/src/test/java/com/androdr/sigma/SigmaRuleEngineDisabledRuleTest.kt` — unit tests for disabled-by-default rule mechanism.

### Modified

- `app/src/main/java/com/androdr/sigma/SigmaRule.kt` — add `category: RuleCategory` field (required, no default) and `enabled: Boolean = true` field.
- `app/src/main/java/com/androdr/sigma/SigmaRuleParser.kt` — parse top-level `category:` field from rule YAML, map string → `RuleCategory` enum, fail with clear error if missing. Parse optional `enabled:` field. Correlation rule parser does NOT require category.
- `app/src/main/java/com/androdr/sigma/SigmaRuleEvaluator.kt` — replace inline cap logic at lines 126–128 with `SeverityCapPolicy.applyCap(rule.category, rule.level)`. `buildFinding` uses `rule.category` for cap decisions, but continues to populate `finding.category` (the existing `FindingCategory`) from `display.category` as before (unchanged).
- `app/src/main/java/com/androdr/sigma/SigmaRuleEngine.kt` — skip disabled rules in every `evaluate*` method.
- `app/src/main/java/com/androdr/sigma/SigmaCorrelationEngine.kt` — determine effective `RuleCategory` per correlation from member rule categories; apply cap to correlation finding severity based on effective category.
- `app/src/main/java/com/androdr/sigma/CorrelationRule.kt` — add `effectiveCategory: RuleCategory` field (computed, not parsed from YAML). Parser populates it from member rule lookup.
- All 34 bundled detection rule YAML files in `app/src/main/res/raw/sigma_androdr_0??_*.yml` — add top-level `category:` field. Downgrade any device_posture rule declaring `level: high` or `level: critical` to `level: medium`.
- All 5 atom rule YAML files in `app/src/main/res/raw/sigma_androdr_atom_*.yml` — add top-level `category: incident` field (atom rules are always incident; they detect discrete events).
- Existing test files (`SigmaRuleEngineTest.kt`, `SigmaRuleEvaluatorTest.kt`, `AllCorrelationRulesFireTest.kt`, `SigmaRuleEngineCorrelationTest.kt`) — update test helper `rule()` factories to set `category = RuleCategory.INCIDENT` so existing tests still construct valid `SigmaRule` instances.

### Not touched

- `app/src/main/java/com/androdr/sigma/Evidence.kt` — `FindingCategory` enum unchanged.
- `app/src/main/java/com/androdr/data/model/ScanResult.kt` — scoring logic unchanged.
- `app/src/main/java/com/androdr/ui/**/*ViewModel.kt` — UI code unchanged.
- `app/src/main/java/com/androdr/scanner/ScanOrchestrator.kt` — unchanged.
- `app/src/main/java/com/androdr/data/db/TimelineAdapter.kt` — unchanged.
- Any Room entity or migration — plan 1 does not touch persistence.

---

## Phase A: RuleCategory Enum (Foundation Type)

### Task A1: Create the `RuleCategory` enum

**Files:**
- Create: `app/src/main/java/com/androdr/sigma/RuleCategory.kt`

- [ ] **Step 1: Write the file**

```kotlin
package com.androdr.sigma

/**
 * Policy-level classification of a SIGMA rule. Drives severity cap enforcement
 * and correlation rule category propagation.
 *
 * This is DISTINCT from [FindingCategory] (DEVICE_POSTURE / APP_RISK / NETWORK),
 * which drives UI display and scoring. A rule may be classified as [INCIDENT]
 * (uncapped) while producing findings with [FindingCategory.APP_RISK] (shown on
 * the Apps screen). The two concepts are orthogonal.
 *
 * See `docs/superpowers/specs/2026-04-09-unified-telemetry-findings-refactor-design.md`
 * §6 for the full rationale.
 */
enum class RuleCategory {
    /**
     * Evidence that something happened or is actively happening: an IOC matched,
     * an app with surveillance permissions is installed, a spyware file artifact
     * exists, a known-bad domain was contacted. Attributable to a specific app,
     * event, or actor. Uncapped — may declare any severity.
     */
    INCIDENT,

    /**
     * A condition that enables future compromise but is not itself an incident:
     * bootloader unlocked, no screen lock, ADB enabled, outdated security patch,
     * exploitable CVE present. Not attributable to an active actor.
     *
     * Capped at `medium` severity regardless of declared `level:`. The engine
     * clamps findings from these rules to `min(declared, medium)` at build
     * time via [SeverityCapPolicy].
     */
    DEVICE_POSTURE,
}
```

- [ ] **Step 2: Verify it compiles**

Run: `./gradlew compileDebugKotlin`
Expected: `BUILD SUCCESSFUL`

- [ ] **Step 3: Commit**

```bash
git add app/src/main/java/com/androdr/sigma/RuleCategory.kt
git commit -m "refactor(sigma): add RuleCategory enum for policy classification

Distinct from FindingCategory (UI/scoring): RuleCategory drives severity
cap enforcement and correlation propagation. INCIDENT is uncapped;
DEVICE_POSTURE will be capped at medium by SeverityCapPolicy (added in
a later commit in this plan).

Part of #84."
```

---

## Phase B: Add Required `category` Field to `SigmaRule`

### Task B1: Add `category` field to `SigmaRule` data class

**Files:**
- Modify: `app/src/main/java/com/androdr/sigma/SigmaRule.kt`

- [ ] **Step 1: Read the current file to confirm its shape**

Run: `cat app/src/main/java/com/androdr/sigma/SigmaRule.kt`
Expected: see `SigmaRule` data class with fields `id, title, status, description, product, service, level, tags, detection, falsepositives, remediation, display`.

- [ ] **Step 2: Add the new field**

Replace the `SigmaRule` data class declaration:

```kotlin
data class SigmaRule(
    val id: String,
    val title: String,
    val status: String,
    val description: String,
    val product: String,
    val service: String,
    val level: String,
    val category: RuleCategory,
    val tags: List<String>,
    val detection: SigmaDetection,
    val falsepositives: List<String>,
    val remediation: List<String>,
    val display: SigmaDisplay = SigmaDisplay(),
    val enabled: Boolean = true
)
```

Note: `category` is **required** (no default). `enabled` defaults to `true` (opt-in disable).

- [ ] **Step 3: Try to compile — expect failure**

Run: `./gradlew compileDebugKotlin`
Expected: **FAIL** — every call site that constructs `SigmaRule` will error with "No value passed for parameter 'category'". This is expected; we're about to fix them.

- [ ] **Step 4: Update `SigmaRuleParser` to parse the field and fail on missing**

Open `app/src/main/java/com/androdr/sigma/SigmaRuleParser.kt`. Find `parseDocument()` (around line 134). Locate where `level` is parsed (around line 146):

```kotlin
val level = (doc["level"] as? String)?.lowercase() ?: "medium"
```

Add immediately after:

```kotlin
val categoryString = doc["category"] as? String
    ?: error("Rule ${doc["id"]} is missing required 'category' field. " +
             "Must declare 'category: incident' or 'category: device_posture'. " +
             "See docs/detection-rules-catalog.md for the categorization principle.")

val category = when (categoryString.lowercase()) {
    "incident" -> RuleCategory.INCIDENT
    "device_posture" -> RuleCategory.DEVICE_POSTURE
    else -> error("Rule ${doc["id"]} has invalid category '$categoryString'. " +
                  "Must be 'incident' or 'device_posture'.")
}

val enabled = (doc["enabled"] as? Boolean) ?: true
```

Then find the `SigmaRule(...)` constructor call at the bottom of `parseDocument()` and add `category = category,` and `enabled = enabled,` to the argument list. Keep all other fields unchanged.

- [ ] **Step 5: Try to compile again — expect different failures**

Run: `./gradlew compileDebugKotlin`
Expected: **FAIL** with compilation errors in test files that construct `SigmaRule` directly (e.g. `SigmaRuleEngineTest.kt`, `SigmaRuleEvaluatorTest.kt`). Those test helper `rule()` factories need updating.

- [ ] **Step 6: Update test helper `rule()` factories**

For each test file that constructs `SigmaRule` directly, add `category = RuleCategory.INCIDENT` to the constructor argument list. Files to update:

```bash
grep -rl "SigmaRule(" app/src/test/java/com/androdr/sigma/
```

Expected files (verify the list first):
- `app/src/test/java/com/androdr/sigma/SigmaRuleEngineTest.kt` — `rule()` helper around line 25
- `app/src/test/java/com/androdr/sigma/SigmaRuleEvaluatorTest.kt` — any test builders
- Any other file returned by the grep

In each helper, add `category = RuleCategory.INCIDENT` as a parameter with a default so individual tests don't have to specify it unless they care:

Example for `SigmaRuleEngineTest.kt`:

```kotlin
private fun rule(
    id: String,
    title: String = "Rule $id",
    category: RuleCategory = RuleCategory.INCIDENT,
) = SigmaRule(
    id = id, title = title, status = "production", description = "",
    product = "androdr", service = "app_scanner", level = "high",
    category = category,
    tags = emptyList(),
    detection = SigmaDetection(emptyMap(), "selection"),
    falsepositives = emptyList(), remediation = emptyList()
)
```

- [ ] **Step 7: Try to compile again — expect pass**

Run: `./gradlew compileDebugKotlin`
Expected: **BUILD SUCCESSFUL** for main. Test compilation may still fail because bundled YAML files don't have `category:` yet — that's phase D's job. For now, run the main compile only.

Actually — the bundled YAML loading happens at test time (rule parsing runs on real files), so tests WILL fail at test time, not compile time. We need to defer running `./gradlew testDebugUnitTest` until phase D is done.

- [ ] **Step 8: Commit**

```bash
git add app/src/main/java/com/androdr/sigma/SigmaRule.kt \
        app/src/main/java/com/androdr/sigma/SigmaRuleParser.kt \
        app/src/test/java/com/androdr/sigma/SigmaRuleEngineTest.kt \
        app/src/test/java/com/androdr/sigma/SigmaRuleEvaluatorTest.kt
# Add any other test files that needed updating
git commit -m "refactor(sigma): add required category field to SigmaRule

SigmaRuleParser now requires every rule to declare a top-level
'category:' field with value 'incident' or 'device_posture'. Missing
category produces a clear error pointing at the detection-rules-catalog
for the categorization principle.

Also adds optional 'enabled: Boolean' field (default true) for the
disabled-by-default rule mechanism required by the wakelock rule
(see plan 6).

Test helper factories updated to default category = INCIDENT so
existing tests that don't care about category don't need to specify it.

Bundled rule YAML files still need to be updated with the category
field — that happens in phase D of this plan. Tests will fail to
load bundled rules until then.

Part of #84."
```

---

## Phase C: YAML Rule Category Updates

Phase B broke test-time rule loading because no bundled YAML file declares `category:`. Phase C fixes every bundled rule file.

**Categorization decisions (from spec §6 and the catalog update in commit `bb7d149`):**

- **`device_posture` (11 rules):** 040, 041, 042, 043, 044, 045, 046, 047, 048, 049, 050. All device-level condition checks (ADB, developer options, unknown sources, screen lock, patch level, bootloader, WiFi ADB, CVE exposure).
- **`incident` (23 rules):** everything else in the detection range (001–005, 010–018, 020, 060, 061, 062, 063, 064, 065, 067, 068).
- **`incident` (5 atom rules):** all atom rules (atom_app_launch, atom_device_admin_grant, atom_dns_lookup, atom_package_install, atom_permission_use). Atom rules detect discrete events and are always incidents by definition.
- **Correlation rules (4 files):** do NOT get a top-level `category:` field. Their effective category is derived at evaluation time from member rule categories (see phase F).

### Task C1: Update incident-category detection rules

**Files (23 files to modify):**

- Modify: `app/src/main/res/raw/sigma_androdr_001_package_ioc.yml`
- Modify: `app/src/main/res/raw/sigma_androdr_002_cert_hash_ioc.yml`
- Modify: `app/src/main/res/raw/sigma_androdr_003_domain_ioc.yml`
- Modify: `app/src/main/res/raw/sigma_androdr_004_apk_hash_ioc.yml`
- Modify: `app/src/main/res/raw/sigma_androdr_005_graphite_paragon.yml`
- Modify: `app/src/main/res/raw/sigma_androdr_010_sideloaded_app.yml`
- Modify: `app/src/main/res/raw/sigma_androdr_011_surveillance_permissions.yml`
- Modify: `app/src/main/res/raw/sigma_androdr_012_accessibility_abuse.yml`
- Modify: `app/src/main/res/raw/sigma_androdr_013_device_admin_abuse.yml`
- Modify: `app/src/main/res/raw/sigma_androdr_014_app_impersonation.yml`
- Modify: `app/src/main/res/raw/sigma_androdr_015_firmware_implant.yml`
- Modify: `app/src/main/res/raw/sigma_androdr_016_system_name_disguise.yml`
- Modify: `app/src/main/res/raw/sigma_androdr_017_accessibility_surveillance_combo.yml`
- Modify: `app/src/main/res/raw/sigma_androdr_018_packer_obfuscator.yml` (if exists; check first)
- Modify: `app/src/main/res/raw/sigma_androdr_020_spyware_artifact.yml`
- Modify: `app/src/main/res/raw/sigma_androdr_060_active_accessibility.yml`
- Modify: `app/src/main/res/raw/sigma_androdr_061_sms_receiver.yml`
- Modify: `app/src/main/res/raw/sigma_androdr_062_call_receiver.yml`
- Modify: `app/src/main/res/raw/sigma_androdr_063_appops_microphone.yml`
- Modify: `app/src/main/res/raw/sigma_androdr_064_appops_camera.yml`
- Modify: `app/src/main/res/raw/sigma_androdr_065_appops_install_packages.yml`
- Modify: `app/src/main/res/raw/sigma_androdr_067_notification_listener.yml`
- Modify: `app/src/main/res/raw/sigma_androdr_068_hidden_launcher.yml`

- [ ] **Step 1: For each file, add `category: incident` as a top-level field**

The field should appear immediately after the `level:` field for consistency. Example edit (for sigma_androdr_001_package_ioc.yml):

BEFORE:
```yaml
level: critical
display:
    category: app_risk
```

AFTER:
```yaml
level: critical
category: incident
display:
    category: app_risk
```

Note the distinction: top-level `category: incident` is the rule's **policy classification** (new). `display.category: app_risk` is the rule's **UI/display classification** (unchanged).

Apply this edit to all 23 files listed above.

If `sigma_androdr_018_packer_obfuscator.yml` does not exist, skip it — the catalog listed it but the file may not be shipped yet.

- [ ] **Step 2: Verify all 23 files were edited**

Run: `grep -c "^category: incident" app/src/main/res/raw/sigma_androdr_0{01,02,03,04,05,10,11,12,13,14,15,16,17,18,20,60,61,62,63,64,65,67,68}_*.yml 2>/dev/null | grep -v :0`

Expected: every file returns `:1`. Any file returning `:0` or missing needs re-editing.

- [ ] **Step 3: Commit**

```bash
git add app/src/main/res/raw/sigma_androdr_001_package_ioc.yml \
        app/src/main/res/raw/sigma_androdr_002_cert_hash_ioc.yml \
        app/src/main/res/raw/sigma_androdr_003_domain_ioc.yml \
        app/src/main/res/raw/sigma_androdr_004_apk_hash_ioc.yml \
        app/src/main/res/raw/sigma_androdr_005_graphite_paragon.yml \
        app/src/main/res/raw/sigma_androdr_010_sideloaded_app.yml \
        app/src/main/res/raw/sigma_androdr_011_surveillance_permissions.yml \
        app/src/main/res/raw/sigma_androdr_012_accessibility_abuse.yml \
        app/src/main/res/raw/sigma_androdr_013_device_admin_abuse.yml \
        app/src/main/res/raw/sigma_androdr_014_app_impersonation.yml \
        app/src/main/res/raw/sigma_androdr_015_firmware_implant.yml \
        app/src/main/res/raw/sigma_androdr_016_system_name_disguise.yml \
        app/src/main/res/raw/sigma_androdr_017_accessibility_surveillance_combo.yml \
        app/src/main/res/raw/sigma_androdr_020_spyware_artifact.yml \
        app/src/main/res/raw/sigma_androdr_060_active_accessibility.yml \
        app/src/main/res/raw/sigma_androdr_061_sms_receiver.yml \
        app/src/main/res/raw/sigma_androdr_062_call_receiver.yml \
        app/src/main/res/raw/sigma_androdr_063_appops_microphone.yml \
        app/src/main/res/raw/sigma_androdr_064_appops_camera.yml \
        app/src/main/res/raw/sigma_androdr_065_appops_install_packages.yml \
        app/src/main/res/raw/sigma_androdr_067_notification_listener.yml \
        app/src/main/res/raw/sigma_androdr_068_hidden_launcher.yml
# If 018 exists, add it too.
git commit -m "refactor(rules): add category: incident to all incident-class detection rules

Every rule that detects attributable behavior (IOC match, sideloaded app
with surveillance capabilities, spyware artifact, sensitive receiver
registration, etc.) gets a top-level category: incident declaration.

This is distinct from display.category (which continues to drive the
UI Apps/Device/Network screen routing). Category is the policy field
that controls severity cap enforcement and correlation propagation.

Part of #84."
```

### Task C2: Update device_posture detection rules with category + severity cap

**Files (11 files to modify):**

- Modify: `app/src/main/res/raw/sigma_androdr_040_adb_enabled.yml`
- Modify: `app/src/main/res/raw/sigma_androdr_041_dev_options.yml`
- Modify: `app/src/main/res/raw/sigma_androdr_042_unknown_sources.yml`
- Modify: `app/src/main/res/raw/sigma_androdr_043_no_screen_lock.yml`
- Modify: `app/src/main/res/raw/sigma_androdr_044_stale_patch.yml`
- Modify: `app/src/main/res/raw/sigma_androdr_045_bootloader_unlocked.yml`
- Modify: `app/src/main/res/raw/sigma_androdr_046_wifi_adb.yml`
- Modify: `app/src/main/res/raw/sigma_androdr_047_cve_exploit.yml`
- Modify: `app/src/main/res/raw/sigma_androdr_048_pegasus_cves.yml`
- Modify: `app/src/main/res/raw/sigma_androdr_049_predator_cves.yml`
- Modify: `app/src/main/res/raw/sigma_androdr_050_graphite_cves.yml`

- [ ] **Step 1: For each file, check the current `level:` value**

Run: `grep "^level:" app/src/main/res/raw/sigma_androdr_0{40,41,42,43,44,45,46,47,48,49,50}_*.yml`

Note which files declare `level: high` or `level: critical`. These need downgrading to `level: medium` per the severity cap policy (device_posture caps at medium).

- [ ] **Step 2: For each file, add `category: device_posture` and downgrade `level:` if needed**

Example edit for sigma_androdr_040_adb_enabled.yml, assuming it currently declares `level: high`:

BEFORE:
```yaml
level: high
display:
    category: device_posture
```

AFTER:
```yaml
level: medium
category: device_posture
display:
    category: device_posture
```

For files that already declare `level: medium` (e.g. 041, 043 based on pre-refactor state), only add `category: device_posture` — don't touch level.

For all 11 files, the invariant after the edit is: `level:` is `medium` or lower, and `category: device_posture` is present.

- [ ] **Step 3: Verify every device_posture rule has both fields correct**

Run:
```bash
for f in app/src/main/res/raw/sigma_androdr_0{40,41,42,43,44,45,46,47,48,49,50}_*.yml; do
    cat=$(grep "^category:" "$f")
    lvl=$(grep "^level:" "$f")
    echo "$f: $cat | $lvl"
done
```

Expected: every line shows `category: device_posture` and `level: medium` (or `level: low` or `level: informational`).

- [ ] **Step 4: Commit**

```bash
git add app/src/main/res/raw/sigma_androdr_040_adb_enabled.yml \
        app/src/main/res/raw/sigma_androdr_041_dev_options.yml \
        app/src/main/res/raw/sigma_androdr_042_unknown_sources.yml \
        app/src/main/res/raw/sigma_androdr_043_no_screen_lock.yml \
        app/src/main/res/raw/sigma_androdr_044_stale_patch.yml \
        app/src/main/res/raw/sigma_androdr_045_bootloader_unlocked.yml \
        app/src/main/res/raw/sigma_androdr_046_wifi_adb.yml \
        app/src/main/res/raw/sigma_androdr_047_cve_exploit.yml \
        app/src/main/res/raw/sigma_androdr_048_pegasus_cves.yml \
        app/src/main/res/raw/sigma_androdr_049_predator_cves.yml \
        app/src/main/res/raw/sigma_androdr_050_graphite_cves.yml
git commit -m "refactor(rules): add category: device_posture to all posture-class detection rules

All 11 device posture rules (040-050) declare category: device_posture
and have level clamped to medium. Per spec §6 and the tester's Redmi A5
false-positive that motivated this refactor, posture findings must not
out-shout actual incidents in the UI or report summary.

Rules with level: high or critical were downgraded to medium. Rules
already at medium were left alone.

Part of #84."
```

### Task C3: Update atom rules

**Files (5 files to modify):**

- Modify: `app/src/main/res/raw/sigma_androdr_atom_app_launch.yml`
- Modify: `app/src/main/res/raw/sigma_androdr_atom_device_admin_grant.yml`
- Modify: `app/src/main/res/raw/sigma_androdr_atom_dns_lookup.yml`
- Modify: `app/src/main/res/raw/sigma_androdr_atom_package_install.yml`
- Modify: `app/src/main/res/raw/sigma_androdr_atom_permission_use.yml`

- [ ] **Step 1: Add `category: incident` to each atom rule**

Atom rules detect discrete events. An event happening is always an incident by the categorization principle (§6: "category reflects the nature of the event — something happened vs. a condition exists"). All 5 atom rules get `category: incident`.

Apply the same insertion pattern as task C1: add `category: incident` immediately after `level:`.

- [ ] **Step 2: Verify**

Run: `grep -c "^category: incident" app/src/main/res/raw/sigma_androdr_atom_*.yml | grep -v :0`
Expected: all 5 files return `:1`.

- [ ] **Step 3: Commit**

```bash
git add app/src/main/res/raw/sigma_androdr_atom_*.yml
git commit -m "refactor(rules): add category: incident to all atom rules

Atom rules detect discrete events (package install, permission use,
DNS lookup, app launch, device admin grant) that feed into correlation
rules. Every atom is an incident-class rule by definition.

Part of #84."
```

### Task C4: Verify correlation rules are untouched

- [ ] **Step 1: Confirm correlation rules do NOT have a top-level category field**

Run: `grep "^category:" app/src/main/res/raw/sigma_androdr_corr_*.yml`
Expected: NO output (no matches). Correlation rules derive their category at evaluation time from member rules (implemented in phase F).

- [ ] **Step 2: If any correlation rule does declare a top-level category field, remove it**

The parser (phase E) will reject correlation rules that declare category directly.

No commit needed if no change was made.

---

## Phase D: SeverityCapPolicy Extraction

### Task D1: Create the `SeverityCapPolicy` object

**Files:**
- Create: `app/src/main/java/com/androdr/sigma/SeverityCapPolicy.kt`
- Create: `app/src/test/java/com/androdr/sigma/SeverityCapPolicyTest.kt`

- [ ] **Step 1: Write the test first**

Create `app/src/test/java/com/androdr/sigma/SeverityCapPolicyTest.kt`:

```kotlin
package com.androdr.sigma

import org.junit.Assert.assertEquals
import org.junit.Test

class SeverityCapPolicyTest {

    @Test
    fun `incident category does not cap critical`() {
        assertEquals("critical", SeverityCapPolicy.applyCap(RuleCategory.INCIDENT, "critical"))
    }

    @Test
    fun `incident category does not cap high`() {
        assertEquals("high", SeverityCapPolicy.applyCap(RuleCategory.INCIDENT, "high"))
    }

    @Test
    fun `incident category does not cap medium`() {
        assertEquals("medium", SeverityCapPolicy.applyCap(RuleCategory.INCIDENT, "medium"))
    }

    @Test
    fun `incident category does not cap low`() {
        assertEquals("low", SeverityCapPolicy.applyCap(RuleCategory.INCIDENT, "low"))
    }

    @Test
    fun `device_posture category clamps critical to medium`() {
        assertEquals("medium", SeverityCapPolicy.applyCap(RuleCategory.DEVICE_POSTURE, "critical"))
    }

    @Test
    fun `device_posture category clamps high to medium`() {
        assertEquals("medium", SeverityCapPolicy.applyCap(RuleCategory.DEVICE_POSTURE, "high"))
    }

    @Test
    fun `device_posture category passes medium through unchanged`() {
        assertEquals("medium", SeverityCapPolicy.applyCap(RuleCategory.DEVICE_POSTURE, "medium"))
    }

    @Test
    fun `device_posture category passes low through unchanged`() {
        assertEquals("low", SeverityCapPolicy.applyCap(RuleCategory.DEVICE_POSTURE, "low"))
    }

    @Test
    fun `device_posture category passes informational through unchanged`() {
        assertEquals("informational", SeverityCapPolicy.applyCap(RuleCategory.DEVICE_POSTURE, "informational"))
    }

    @Test
    fun `applyCap is case insensitive on declared level`() {
        assertEquals("medium", SeverityCapPolicy.applyCap(RuleCategory.DEVICE_POSTURE, "CRITICAL"))
        assertEquals("medium", SeverityCapPolicy.applyCap(RuleCategory.DEVICE_POSTURE, "High"))
    }
}
```

- [ ] **Step 2: Run the test — expect compilation failure**

Run: `./gradlew testDebugUnitTest --tests "com.androdr.sigma.SeverityCapPolicyTest"`
Expected: **FAIL** — unresolved reference `SeverityCapPolicy`.

- [ ] **Step 3: Create `SeverityCapPolicy.kt`**

```kotlin
package com.androdr.sigma

/**
 * Enforces the severity cap policy: findings from rules in certain categories
 * have their severity clamped at build time.
 *
 * Current policy (see spec §6):
 * - [RuleCategory.INCIDENT] — uncapped. Any declared severity passes through.
 * - [RuleCategory.DEVICE_POSTURE] — clamped at `medium`. Rules declaring `high`
 *   or `critical` produce findings with `level = medium` instead. Rules declaring
 *   `medium`, `low`, or `informational` are unaffected.
 *
 * Rationale: posture issues represent potential compromise (a condition), not
 * actual compromise (an incident). They must not out-shout real findings in
 * the UI or report summary. See [RuleCategory] docs and the spec at
 * `docs/superpowers/specs/2026-04-09-unified-telemetry-findings-refactor-design.md`
 * §6 for the full argument.
 *
 * Correlation rules that combine posture with an incident leg are promoted
 * via the propagation rule in [SigmaCorrelationEngine], not via this policy.
 */
object SeverityCapPolicy {

    /**
     * Per-category maximum permitted finding severity. Rules whose category
     * is absent from this map are uncapped.
     *
     * Severity ordering (highest to lowest): critical > high > medium > low > informational.
     */
    private val caps: Map<RuleCategory, String> = mapOf(
        RuleCategory.DEVICE_POSTURE to "medium",
    )

    /**
     * Ordered list of severity values used for clamping comparisons.
     * Index 0 is the highest severity. A declared level is clamped to the cap
     * iff its index is lower (i.e. higher severity) than the cap's index.
     */
    private val severityOrder: List<String> = listOf(
        "critical",
        "high",
        "medium",
        "low",
        "informational",
    )

    /**
     * Applies the cap for [category] to [declared] severity. Returns the
     * effective severity after clamping.
     *
     * - If [category] has no cap, returns [declared] unchanged (lowercased).
     * - If [declared] severity is already at or below the cap, returns it unchanged.
     * - If [declared] exceeds the cap, returns the cap value.
     *
     * Input [declared] is case-insensitive; output is always lowercase.
     */
    fun applyCap(category: RuleCategory, declared: String): String {
        val normalizedDeclared = declared.lowercase()
        val cap = caps[category] ?: return normalizedDeclared

        val declaredIdx = severityOrder.indexOf(normalizedDeclared)
        val capIdx = severityOrder.indexOf(cap)

        // Unknown severity values pass through unchanged — the parser should
        // have rejected them earlier.
        if (declaredIdx == -1 || capIdx == -1) return normalizedDeclared

        // Lower index = higher severity. Clamp if declared is higher than cap.
        return if (declaredIdx < capIdx) cap else normalizedDeclared
    }
}
```

- [ ] **Step 4: Run the test — expect pass**

Run: `./gradlew testDebugUnitTest --tests "com.androdr.sigma.SeverityCapPolicyTest"`
Expected: **BUILD SUCCESSFUL**, 10 tests passed.

- [ ] **Step 5: Commit**

```bash
git add app/src/main/java/com/androdr/sigma/SeverityCapPolicy.kt \
        app/src/test/java/com/androdr/sigma/SeverityCapPolicyTest.kt
git commit -m "refactor(sigma): extract SeverityCapPolicy as testable object

Extracts the device_posture → medium cap from inline code in
SigmaRuleEvaluator.kt:126 into a dedicated SeverityCapPolicy object
with full unit test coverage. The policy is a pure function of
(RuleCategory, declared) → effective severity.

Future additions to the cap map (e.g. a hygiene category at low)
happen here in one place.

Part of #84."
```

### Task D2: Apply `SeverityCapPolicy` in `SigmaRuleEvaluator`

**Files:**
- Modify: `app/src/main/java/com/androdr/sigma/SigmaRuleEvaluator.kt`

- [ ] **Step 1: Read the current file around lines 109–146 (the `buildFinding` method)**

Run: `sed -n '100,150p' app/src/main/java/com/androdr/sigma/SigmaRuleEvaluator.kt`
Expected: see the existing inline cap logic around line 126:

```kotlin
val effectiveLevel = if (category == FindingCategory.DEVICE_POSTURE &&
    rule.level.lowercase() in listOf("high", "critical")
) "medium" else rule.level
```

- [ ] **Step 2: Replace the inline cap with `SeverityCapPolicy.applyCap(rule.category, rule.level)`**

Find the line quoted above and replace with:

```kotlin
val effectiveLevel = SeverityCapPolicy.applyCap(rule.category, rule.level)
```

**Important:** the new call uses `rule.category` (the new `RuleCategory` field added in phase B), NOT `category` (which is the local `FindingCategory` variable derived from `display.category`). These are different things. The cap is policy-driven by rule.category, not display-driven by finding category.

Also: delete the `category == FindingCategory.DEVICE_POSTURE` check entirely. The policy handles that logic now.

- [ ] **Step 3: Verify the change**

Run: `grep -n "effectiveLevel" app/src/main/java/com/androdr/sigma/SigmaRuleEvaluator.kt`
Expected: exactly one match, the new `SeverityCapPolicy.applyCap(...)` line. No references to `listOf("high", "critical")`.

- [ ] **Step 4: Run the evaluator tests — expect pass**

Run: `./gradlew testDebugUnitTest --tests "com.androdr.sigma.SigmaRuleEvaluatorTest"`
Expected: **BUILD SUCCESSFUL**. If any test fails with the new policy, it's because the old inline logic had slightly different semantics (e.g. clamping only "high" and "critical" but not other values). Review the failure and adjust the test expectation (not the policy) if the new policy is more correct.

- [ ] **Step 5: Commit**

```bash
git add app/src/main/java/com/androdr/sigma/SigmaRuleEvaluator.kt
git commit -m "refactor(sigma): use SeverityCapPolicy in SigmaRuleEvaluator.buildFinding

Replaces the inline cap logic with SeverityCapPolicy.applyCap(). The cap
decision now reads rule.category (the policy field from phase B), not
finding.category (the display field derived from display.category).

This makes the cap policy testable in isolation and moves one more
piece of detection logic out of hardcoded Kotlin into a declarative
data structure.

Part of #84."
```

---

## Phase E: Build-Time Enforcement Test

### Task E1: Create `AllRulesHaveCategoryTest`

**Files:**
- Create: `app/src/test/java/com/androdr/sigma/AllRulesHaveCategoryTest.kt`

- [ ] **Step 1: Write the test**

```kotlin
package com.androdr.sigma

import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.io.File

/**
 * Build-time enforcement test: every bundled detection and atom rule declares
 * a top-level `category:` field, and every `category: device_posture` rule
 * declares `level:` at `medium` or lower.
 *
 * A rule author trying to ship a `device_posture` rule with `level: high`
 * fails CI here, not at runtime when the engine would silently clamp.
 *
 * Correlation rules (sigma_androdr_corr_*.yml) are exempt — their category
 * is derived at evaluation time from member rule categories, so they MUST
 * NOT declare a top-level category field.
 */
class AllRulesHaveCategoryTest {

    /**
     * Locate the res/raw directory. Mirrors the fallback chain used by
     * AllCorrelationRulesFireTest.loadYaml() so the test works regardless
     * of which directory `./gradlew testDebugUnitTest` is invoked from.
     */
    private fun rulesDirectory(): File {
        val candidates = listOf(
            File("app/src/main/res/raw"),
            File("src/main/res/raw"),
            File("/home/yasir/AndroDR/app/src/main/res/raw"),
        )
        return candidates.firstOrNull { it.isDirectory }
            ?: error(
                "Could not locate res/raw; tried: ${candidates.map { it.absolutePath }}"
            )
    }

    private fun detectionAndAtomRuleFiles(): List<File> =
        rulesDirectory().listFiles { f ->
            f.name.startsWith("sigma_androdr_") &&
                f.name.endsWith(".yml") &&
                !f.name.startsWith("sigma_androdr_corr_")
        }?.toList() ?: emptyList()

    private fun correlationRuleFiles(): List<File> =
        rulesDirectory().listFiles { f ->
            f.name.startsWith("sigma_androdr_corr_") && f.name.endsWith(".yml")
        }?.toList() ?: emptyList()

    /**
     * Extract the top-level `category:` value from a rule YAML.
     * Returns null if no top-level category line exists.
     *
     * "Top-level" means zero leading whitespace — this excludes nested
     * fields like `display.category` which are indented.
     */
    private fun extractTopLevelCategory(file: File): String? =
        file.readText().lines()
            .firstOrNull { line -> line.startsWith("category:") }
            ?.removePrefix("category:")
            ?.trim()

    /**
     * Extract the top-level `level:` value from a rule YAML.
     */
    private fun extractTopLevelLevel(file: File): String? =
        file.readText().lines()
            .firstOrNull { line -> line.startsWith("level:") }
            ?.removePrefix("level:")
            ?.trim()
            ?.lowercase()

    @Test
    fun `every detection and atom rule declares category`() {
        val violations = mutableListOf<String>()
        val ruleFiles = detectionAndAtomRuleFiles()

        assertTrue(
            "Expected at least one detection/atom rule file; found ${ruleFiles.size}. " +
                "Is the test running from the app module root?",
            ruleFiles.isNotEmpty(),
        )

        ruleFiles.forEach { file ->
            val category = extractTopLevelCategory(file)
            when {
                category == null -> violations +=
                    "${file.name}: missing top-level 'category:' field"
                category !in listOf("incident", "device_posture") -> violations +=
                    "${file.name}: category has invalid value '$category' " +
                        "(must be 'incident' or 'device_posture')"
            }
        }

        if (violations.isNotEmpty()) {
            fail(
                "Rule category violations found:\n" +
                    violations.joinToString("\n") { "  - $it" } + "\n\n" +
                    "Every detection and atom rule must declare a top-level " +
                    "category: incident or category: device_posture field. " +
                    "See docs/detection-rules-catalog.md for the categorization principle."
            )
        }
    }

    @Test
    fun `every device_posture rule declares level at medium or below`() {
        val allowedLevels = setOf("medium", "low", "informational")
        val violations = mutableListOf<String>()

        detectionAndAtomRuleFiles().forEach { file ->
            val category = extractTopLevelCategory(file)
            if (category == "device_posture") {
                val level = extractTopLevelLevel(file)
                if (level !in allowedLevels) {
                    violations += "${file.name}: category is device_posture but level is '$level' " +
                        "(must be one of $allowedLevels)"
                }
            }
        }

        if (violations.isNotEmpty()) {
            fail(
                "Device posture severity cap violations:\n" +
                    violations.joinToString("\n") { "  - $it" } + "\n\n" +
                    "Device posture rules are capped at severity 'medium' per the " +
                    "SeverityCapPolicy. Rules declaring 'high' or 'critical' would " +
                    "be silently clamped by the engine — this test catches the " +
                    "mistake at build time instead. If you genuinely need a rule " +
                    "to fire at HIGH or CRITICAL, classify it as category: incident."
            )
        }
    }

    @Test
    fun `correlation rules do not declare top-level category field`() {
        val violations = mutableListOf<String>()

        correlationRuleFiles().forEach { file ->
            if (extractTopLevelCategory(file) != null) {
                violations += "${file.name}: declares top-level 'category:' field but correlation " +
                    "rules must derive category from member rules via propagation"
            }
        }

        if (violations.isNotEmpty()) {
            fail(
                "Correlation rules should not declare category directly:\n" +
                    violations.joinToString("\n") { "  - $it" }
            )
        }
    }
}
```

- [ ] **Step 2: Run the test**

Run: `./gradlew testDebugUnitTest --tests "com.androdr.sigma.AllRulesHaveCategoryTest"`
Expected: **BUILD SUCCESSFUL** if phases B–C left the YAML in a valid state. If any test fails, it means a phase C edit was missed — re-inspect the offending file and add/fix its `category:` declaration.

- [ ] **Step 3: Commit**

```bash
git add app/src/test/java/com/androdr/sigma/AllRulesHaveCategoryTest.kt
git commit -m "test(sigma): build-time enforcement for rule category and posture cap

Three enforcement tests:
1. Every detection/atom rule declares top-level category (incident or
   device_posture). Missing field or invalid value fails CI.
2. Every device_posture rule declares level at medium or lower.
   Rules declaring high/critical fail CI — catches mistakes before
   the engine would silently clamp them.
3. Correlation rules do NOT declare top-level category. Their category
   is derived at evaluation time via propagation.

Part of #84."
```

---

## Phase F: Correlation Category Propagation

### Task F1: Add effective category to `CorrelationRule`

**Files:**
- Modify: `app/src/main/java/com/androdr/sigma/CorrelationRule.kt`

- [ ] **Step 1: Read the current file**

Run: `cat app/src/main/java/com/androdr/sigma/CorrelationRule.kt`
Expected: see the existing `CorrelationRule` data class with fields `id, title, type, referencedRuleIds, timespanMs, groupBy, minEvents, severity, displayLabel, displayCategory`.

- [ ] **Step 2: Add `effectiveCategory` field**

```kotlin
data class CorrelationRule(
    val id: String,
    val title: String,
    val type: CorrelationType,
    val referencedRuleIds: List<String>,
    val timespanMs: Long,
    val groupBy: List<String>,
    val minEvents: Int,
    val severity: String,
    val displayLabel: String,
    val displayCategory: String = "correlation",
    /**
     * Computed at parse time from member rule categories via propagation:
     * if ANY referenced rule is [RuleCategory.INCIDENT], this is INCIDENT;
     * otherwise DEVICE_POSTURE. See spec §6 "Correlation rule propagation".
     *
     * Used for severity cap enforcement: a correlation inheriting INCIDENT
     * is uncapped; one inheriting DEVICE_POSTURE is clamped to medium.
     */
    val effectiveCategory: RuleCategory = RuleCategory.INCIDENT,
)
```

Default to `INCIDENT` so existing tests that construct `CorrelationRule` without specifying it continue to compile.

- [ ] **Step 3: Compile check**

Run: `./gradlew compileDebugKotlin`
Expected: **BUILD SUCCESSFUL**.

- [ ] **Step 4: No commit yet — tied to F2**

### Task F2: Parser computes effective category from member rules

**Files:**
- Modify: `app/src/main/java/com/androdr/sigma/SigmaRuleParser.kt`

- [ ] **Step 1: Find the correlation rule parsing method**

Run: `grep -n "parseCorrelation" app/src/main/java/com/androdr/sigma/SigmaRuleParser.kt`
Expected: a function named `parseCorrelation` somewhere in the file.

- [ ] **Step 2: Understand the parser context**

The parser creates `CorrelationRule` instances from YAML. It currently populates `referencedRuleIds` from the YAML's `correlation.rules` list. To compute `effectiveCategory`, the parser needs access to the list of already-parsed detection/atom rules so it can look up their categories.

Two approaches:

A) Make the parser a two-phase process: first parse all detection/atom rules, then parse correlation rules with access to the category lookup map. This is the cleanest but changes the parser API.

B) Pass in a category lookup function as a parameter to `parseCorrelation`. Caller provides it.

C) Leave `effectiveCategory` defaulted to INCIDENT at parse time, and compute it later at evaluation time in `SigmaCorrelationEngine` when rules are actually applied. The correlation rule data class carries the default until computed.

Go with **C** for this plan — it localizes the propagation logic in the engine and doesn't change the parser API. The data class default of INCIDENT is a safe fallback (uncapped) until the engine computes the real value.

- [ ] **Step 3: Leave the parser unchanged for correlation category**

No changes to `SigmaRuleParser.parseCorrelation()` in this task. The default `effectiveCategory = RuleCategory.INCIDENT` applies.

Proceed to F3 where the engine computes the actual effective category.

### Task F3: `SigmaCorrelationEngine` computes and applies effective category

**Files:**
- Modify: `app/src/main/java/com/androdr/sigma/SigmaCorrelationEngine.kt`
- Create: `app/src/test/java/com/androdr/sigma/SigmaCorrelationEngineCategoryPropagationTest.kt`

- [ ] **Step 1: Write the propagation test first**

```kotlin
package com.androdr.sigma

import com.androdr.data.model.ForensicTimelineEvent
import org.junit.Assert.assertEquals
import org.junit.Test

class SigmaCorrelationEngineCategoryPropagationTest {

    private val engine = SigmaCorrelationEngine()

    private fun makeAtomRule(id: String, category: RuleCategory) = SigmaRule(
        id = id, title = "Atom $id", status = "production", description = "",
        product = "androdr", service = "test", level = "high",
        category = category,
        tags = emptyList(),
        detection = SigmaDetection(emptyMap(), "selection"),
        falsepositives = emptyList(), remediation = emptyList()
    )

    @Test
    fun `correlation with one incident member propagates INCIDENT`() {
        val atoms = mapOf(
            "atom-1" to makeAtomRule("atom-1", RuleCategory.INCIDENT),
            "atom-2" to makeAtomRule("atom-2", RuleCategory.DEVICE_POSTURE),
        )
        val effective = engine.computeEffectiveCategory(
            referencedRuleIds = listOf("atom-1", "atom-2"),
            atomRulesById = atoms,
        )
        assertEquals(RuleCategory.INCIDENT, effective)
    }

    @Test
    fun `correlation with only device_posture members propagates DEVICE_POSTURE`() {
        val atoms = mapOf(
            "atom-1" to makeAtomRule("atom-1", RuleCategory.DEVICE_POSTURE),
            "atom-2" to makeAtomRule("atom-2", RuleCategory.DEVICE_POSTURE),
        )
        val effective = engine.computeEffectiveCategory(
            referencedRuleIds = listOf("atom-1", "atom-2"),
            atomRulesById = atoms,
        )
        assertEquals(RuleCategory.DEVICE_POSTURE, effective)
    }

    @Test
    fun `correlation with only incident members is INCIDENT`() {
        val atoms = mapOf(
            "atom-1" to makeAtomRule("atom-1", RuleCategory.INCIDENT),
            "atom-2" to makeAtomRule("atom-2", RuleCategory.INCIDENT),
        )
        val effective = engine.computeEffectiveCategory(
            referencedRuleIds = listOf("atom-1", "atom-2"),
            atomRulesById = atoms,
        )
        assertEquals(RuleCategory.INCIDENT, effective)
    }

    @Test
    fun `correlation referencing unknown rule defaults safely to INCIDENT`() {
        // If a correlation references a rule ID that doesn't exist in the
        // rule set (misconfiguration or missing load), default to INCIDENT.
        // The unknown rule is ignored, not treated as device_posture.
        val atoms = mapOf(
            "atom-1" to makeAtomRule("atom-1", RuleCategory.DEVICE_POSTURE),
        )
        val effective = engine.computeEffectiveCategory(
            referencedRuleIds = listOf("atom-1", "atom-missing"),
            atomRulesById = atoms,
        )
        // Only atom-1 contributes; it's device_posture, so result is device_posture.
        assertEquals(RuleCategory.DEVICE_POSTURE, effective)
    }

    @Test
    fun `correlation referencing all unknown rules defaults to INCIDENT`() {
        // No known rules → propagation can't determine category → safe default.
        val atoms = mapOf<String, SigmaRule>()
        val effective = engine.computeEffectiveCategory(
            referencedRuleIds = listOf("atom-missing-1", "atom-missing-2"),
            atomRulesById = atoms,
        )
        assertEquals(RuleCategory.INCIDENT, effective)
    }
}
```

- [ ] **Step 2: Run the test — expect compilation failure**

Run: `./gradlew testDebugUnitTest --tests "com.androdr.sigma.SigmaCorrelationEngineCategoryPropagationTest"`
Expected: **FAIL** — unresolved reference `computeEffectiveCategory`.

- [ ] **Step 3: Implement `computeEffectiveCategory` in `SigmaCorrelationEngine`**

Open `app/src/main/java/com/androdr/sigma/SigmaCorrelationEngine.kt`. Add the following method as a public member of the class:

```kotlin
/**
 * Determines the effective rule category for a correlation rule by inspecting
 * its member (referenced) rule categories.
 *
 * Propagation rule (spec §6):
 * - If ANY referenced rule is [RuleCategory.INCIDENT] → result is INCIDENT.
 * - If ALL referenced rules are [RuleCategory.DEVICE_POSTURE] → result is DEVICE_POSTURE.
 * - If NO referenced rules are known (e.g. misconfiguration) → safe default: INCIDENT (uncapped).
 *
 * Unknown rule IDs are skipped — they don't contribute to the decision.
 *
 * This is called at evaluation time to populate [CorrelationRule.effectiveCategory]
 * before the cap policy is applied to the resulting correlation finding.
 *
 * @param referencedRuleIds the rule IDs this correlation references
 * @param atomRulesById lookup table of known atom/detection rules
 */
fun computeEffectiveCategory(
    referencedRuleIds: List<String>,
    atomRulesById: Map<String, SigmaRule>,
): RuleCategory {
    val knownCategories = referencedRuleIds
        .mapNotNull { atomRulesById[it]?.category }

    if (knownCategories.isEmpty()) return RuleCategory.INCIDENT
    return if (knownCategories.any { it == RuleCategory.INCIDENT }) {
        RuleCategory.INCIDENT
    } else {
        RuleCategory.DEVICE_POSTURE
    }
}
```

- [ ] **Step 4: Run the test — expect pass**

Run: `./gradlew testDebugUnitTest --tests "com.androdr.sigma.SigmaCorrelationEngineCategoryPropagationTest"`
Expected: **BUILD SUCCESSFUL**, 5 tests passed.

- [ ] **Step 5: Wire the cap policy into correlation signal emission**

In `SigmaCorrelationEngine.kt`, find the `signal()` method that constructs `ForensicTimelineEvent` for a correlation match. Around line 155 (per the audit report) the line currently reads:

```kotlin
severity = rule.severity,
```

The correlation severity currently comes directly from the rule's declared severity, without any cap. We need to apply the cap based on the correlation's effective category.

Refactor the signal emission to:

1. Accept the `effectiveCategory` as a parameter (or read it from the rule if stored there),
2. Apply `SeverityCapPolicy.applyCap(effectiveCategory, rule.severity)` to get the clamped severity,
3. Use the clamped value in the emitted `ForensicTimelineEvent`.

The exact refactor depends on how `signal()` is called. Inspect the call sites:

```bash
grep -n "signal(" app/src/main/java/com/androdr/sigma/SigmaCorrelationEngine.kt
```

For each call site, compute the effective category via `computeEffectiveCategory()` before calling `signal()`, and pass it in. The `evaluate()` method at the top of the file will need to accept a rules lookup so it can build `atomRulesById`.

Concretely, change `evaluate()` signature from:

```kotlin
fun evaluate(
    rules: List<CorrelationRule>,
    events: List<ForensicTimelineEvent>,
    bindings: Map<Long, Set<String>>
): List<ForensicTimelineEvent>
```

to:

```kotlin
fun evaluate(
    rules: List<CorrelationRule>,
    events: List<ForensicTimelineEvent>,
    bindings: Map<Long, Set<String>>,
    atomRulesById: Map<String, SigmaRule>,
): List<ForensicTimelineEvent>
```

At the top of each correlation evaluation path (for each `rule` in `rules`), compute:

```kotlin
val effectiveCategory = computeEffectiveCategory(rule.referencedRuleIds, atomRulesById)
val effectiveSeverity = SeverityCapPolicy.applyCap(effectiveCategory, rule.severity)
```

Use `effectiveSeverity` where `rule.severity` was previously used in the signal emission.

- [ ] **Step 6: Update call sites of `SigmaCorrelationEngine.evaluate()`**

Run: `grep -rn "correlationEngine.evaluate\|SigmaCorrelationEngine.*evaluate" app/src/main/java/`
Expected: at least one call site in `SigmaRuleEngine.kt` or `ScanOrchestrator.kt`.

For each call site, pass the atom rules lookup. `SigmaRuleEngine` maintains a list of rules; build the map with:

```kotlin
val atomRulesById: Map<String, SigmaRule> = engine.getRules().associateBy { it.id }
```

- [ ] **Step 7: Run all sigma tests**

Run: `./gradlew testDebugUnitTest --tests "com.androdr.sigma.*"`
Expected: **BUILD SUCCESSFUL**. Any test that fails here was written against the pre-cap behavior of correlation severity — review the failure and decide whether the test expectation needs updating (correlation finding severity may now be lower due to the cap, which is correct behavior).

- [ ] **Step 8: Commit**

```bash
git add app/src/main/java/com/androdr/sigma/CorrelationRule.kt \
        app/src/main/java/com/androdr/sigma/SigmaCorrelationEngine.kt \
        app/src/test/java/com/androdr/sigma/SigmaCorrelationEngineCategoryPropagationTest.kt
# Add any call site files that were modified
git commit -m "refactor(sigma): correlation rule category propagation via SeverityCapPolicy

Correlation rules now derive their effective RuleCategory from their
member (referenced) rule categories:
- Any INCIDENT member → INCIDENT (uncapped)
- All DEVICE_POSTURE members → DEVICE_POSTURE (capped at medium)
- No known members → safe default INCIDENT

SigmaCorrelationEngine.evaluate() accepts an atomRulesById lookup and
applies SeverityCapPolicy.applyCap() to correlation findings based on
the computed effective category. A posture+incident correlation
(e.g. bootloader unlocked + known-bad domain contacted) now correctly
promotes to incident and escapes the medium cap.

Part of #84."
```

---

## Phase G: Disabled-by-Default Rule Mechanism

### Task G1: Engine skips disabled rules

**Files:**
- Modify: `app/src/main/java/com/androdr/sigma/SigmaRuleEngine.kt`
- Create: `app/src/test/java/com/androdr/sigma/SigmaRuleEngineDisabledRuleTest.kt`

- [ ] **Step 1: Write the test first**

```kotlin
package com.androdr.sigma

import android.content.Context
import com.androdr.data.model.AppTelemetry
import io.mockk.mockk
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

class SigmaRuleEngineDisabledRuleTest {

    private val mockContext = mockk<Context>(relaxed = true)
    private lateinit var engine: SigmaRuleEngine

    private fun rule(id: String, enabled: Boolean = true) = SigmaRule(
        id = id, title = "Rule $id", status = "production", description = "",
        product = "androdr", service = "app_scanner", level = "high",
        category = RuleCategory.INCIDENT,
        tags = emptyList(),
        detection = SigmaDetection(
            selections = mapOf(
                "selection" to SigmaSelection(
                    fieldMatchers = listOf(
                        SigmaFieldMatcher(
                            fieldName = "is_system_app",
                            modifier = SigmaModifier.EQUALS,
                            values = listOf(false),
                        )
                    )
                )
            ),
            condition = "selection",
        ),
        falsepositives = emptyList(), remediation = emptyList(),
        enabled = enabled,
    )

    private val testTelemetry = AppTelemetry(
        packageName = "com.test.app",
        appName = "Test App",
        certHash = null,
        apkHash = null,
        isSystemApp = false,
        fromTrustedStore = false,
        installer = null,
        isSideloaded = true,
        isKnownOemApp = false,
        permissions = emptyList(),
        surveillancePermissionCount = 0,
        hasAccessibilityService = false,
        hasDeviceAdmin = false,
        knownAppCategory = null,
    )

    @Before
    fun setUp() {
        engine = SigmaRuleEngine(mockContext)
    }

    @Test
    fun `enabled rule produces finding when telemetry matches`() {
        val rules = listOf(rule("rule-enabled", enabled = true))
        setBundledRulesDirectly(rules)

        val findings = engine.evaluateApps(listOf(testTelemetry))

        assertEquals(1, findings.size)
        assertEquals("rule-enabled", findings[0].ruleId)
    }

    @Test
    fun `disabled rule produces no findings even when telemetry matches`() {
        val rules = listOf(rule("rule-disabled", enabled = false))
        setBundledRulesDirectly(rules)

        val findings = engine.evaluateApps(listOf(testTelemetry))

        assertTrue(
            "Expected no findings from disabled rule, got: ${findings.map { it.ruleId }}",
            findings.isEmpty(),
        )
    }

    @Test
    fun `mixed enabled and disabled rules only enabled ones fire`() {
        val rules = listOf(
            rule("rule-on-1", enabled = true),
            rule("rule-off", enabled = false),
            rule("rule-on-2", enabled = true),
        )
        setBundledRulesDirectly(rules)

        val findings = engine.evaluateApps(listOf(testTelemetry))

        assertEquals(2, findings.size)
        val firedIds = findings.map { it.ruleId }.toSet()
        assertEquals(setOf("rule-on-1", "rule-on-2"), firedIds)
    }

    // Reflection helper pattern used in existing SigmaRuleEngineTest
    private fun setBundledRulesDirectly(rules: List<SigmaRule>) {
        val field = SigmaRuleEngine::class.java.getDeclaredField("bundledRules")
        field.isAccessible = true
        field.set(engine, rules)
    }
}
```

- [ ] **Step 2: Run the test — expect failure**

Run: `./gradlew testDebugUnitTest --tests "com.androdr.sigma.SigmaRuleEngineDisabledRuleTest"`
Expected: **FAIL** — either compilation error (if `setBundledRulesDirectly` pattern doesn't match the current engine field name) or test failure (if `enabled = false` rules currently still fire).

If the test fails to compile because of the reflection pattern, adjust it to match the existing pattern in `SigmaRuleEngineTest.kt`. Check:

```bash
grep -A 5 "setBundledRulesDirectly\|bundledRules" app/src/test/java/com/androdr/sigma/SigmaRuleEngineTest.kt
```

Copy the pattern exactly.

- [ ] **Step 3: Update `SigmaRuleEngine` to skip disabled rules**

Open `app/src/main/java/com/androdr/sigma/SigmaRuleEngine.kt`. Find the list of `evaluate*` methods. Each one iterates over the rule set and dispatches to the evaluator. Add a filter `rules.filter { it.enabled }` before the iteration.

One approach: introduce a private method `effectiveRules()` that returns `getRules().filter { it.enabled }`, and change every `evaluate*` to use it instead of iterating directly over `getRules()`:

```kotlin
private fun effectiveRules(): List<SigmaRule> = getRules().filter { it.enabled }
```

Then replace each `getRules()` call in `evaluate*` methods with `effectiveRules()`.

- [ ] **Step 4: Run the test — expect pass**

Run: `./gradlew testDebugUnitTest --tests "com.androdr.sigma.SigmaRuleEngineDisabledRuleTest"`
Expected: **BUILD SUCCESSFUL**, 3 tests passed.

- [ ] **Step 5: Run the full sigma test suite to check for regressions**

Run: `./gradlew testDebugUnitTest --tests "com.androdr.sigma.*"`
Expected: **BUILD SUCCESSFUL**. All tests pass.

- [ ] **Step 6: Commit**

```bash
git add app/src/main/java/com/androdr/sigma/SigmaRuleEngine.kt \
        app/src/test/java/com/androdr/sigma/SigmaRuleEngineDisabledRuleTest.kt
git commit -m "refactor(sigma): engine skips rules with enabled: false

Adds effectiveRules() filter that drops rules declaring enabled: false.
The SigmaRule.enabled field was added in phase B with default true, so
this is an opt-in disable — existing rules are unaffected.

This mechanism is required by the wakelock rule (plan 6) which ships
disabled pending UAT threshold calibration (#87).

Part of #84."
```

---

## Phase H: Final Verification

### Task H1: Run full unit test suite

- [ ] **Step 1: Run every unit test**

Run: `./gradlew testDebugUnitTest`
Expected: **BUILD SUCCESSFUL**. Every test in the repo passes.

If anything fails:
- If failure is in a sigma test, review — it may be legitimately catching a bug in the refactor
- If failure is in a non-sigma test (UI, reporting, data), the refactor shouldn't have touched it. Investigate.
- DO NOT commit until all tests pass.

- [ ] **Step 2: Run lint**

Run: `./gradlew lintDebug`
Expected: **BUILD SUCCESSFUL** with no new warnings.

- [ ] **Step 3: Run full debug assembly**

Run: `./gradlew assembleDebug`
Expected: **BUILD SUCCESSFUL**. APK produced.

- [ ] **Step 4: Run detekt**

Run: `./gradlew detekt`
Expected: **BUILD SUCCESSFUL**.

If new detekt violations are introduced by this plan's code, fix them (don't disable rules) and re-run.

### Task H2: Verify all bundled rules still parse

This is a sanity check: the `AllCorrelationRulesFireTest` (existing test) loads and parses all correlation rules; `AllRulesHaveCategoryTest` (new from phase E) loads and parses all detection/atom rules. If both pass, rule loading is healthy.

- [ ] **Step 1: Run both tests explicitly**

Run:
```bash
./gradlew testDebugUnitTest \
    --tests "com.androdr.sigma.AllRulesHaveCategoryTest" \
    --tests "com.androdr.sigma.AllCorrelationRulesFireTest"
```
Expected: **BUILD SUCCESSFUL**.

### Task H3: Plan 1 completion commit and summary

- [ ] **Step 1: Verify the branch is clean**

Run: `git status`
Expected: `nothing to commit, working tree clean`.

- [ ] **Step 2: Show the commit log for this plan**

Run: `git log --oneline ba947ae..HEAD`

Expected: roughly 10–12 commits for plan 1, each with a clear message and `Part of #84` trailer.

- [ ] **Step 3: Plan 1 is complete. Do NOT open the PR yet.**

The PR opens only after plan 7. Notify the user of plan 1 completion and readiness to write plan 2.

---

## Plan 1 Retrospective Checklist

Before declaring plan 1 complete, verify each of these is true:

- [ ] `RuleCategory` enum exists with INCIDENT and DEVICE_POSTURE values
- [ ] `SigmaRule` has required `category` field and optional `enabled` field
- [ ] `SigmaRuleParser` requires `category` on non-correlation rules, parses `enabled` with default true
- [ ] All 23 incident detection rule YAMLs declare `category: incident`
- [ ] All 11 device_posture detection rule YAMLs declare `category: device_posture` and `level: medium` or lower
- [ ] All 5 atom rule YAMLs declare `category: incident`
- [ ] Correlation rule YAMLs do NOT declare `category` at top level
- [ ] `SeverityCapPolicy` exists with 10 unit tests passing
- [ ] `SigmaRuleEvaluator.buildFinding` uses `SeverityCapPolicy.applyCap(rule.category, rule.level)`
- [ ] `AllRulesHaveCategoryTest` passes and catches missing/invalid category and posture cap violations
- [ ] `SigmaCorrelationEngine.computeEffectiveCategory()` exists with 5 unit tests passing
- [ ] `SigmaCorrelationEngine.evaluate()` accepts `atomRulesById` and applies cap to correlation findings
- [ ] `SigmaRuleEngine.effectiveRules()` filters out disabled rules
- [ ] `SigmaRuleEngineDisabledRuleTest` passes (3 tests)
- [ ] `./gradlew testDebugUnitTest` passes
- [ ] `./gradlew lintDebug` passes
- [ ] `./gradlew assembleDebug` succeeds
- [ ] `./gradlew detekt` passes
- [ ] `FindingCategory`, `ScanResult`, `ScanOrchestrator`, all ViewModels, and `TimelineAdapter` are **untouched** by this plan
- [ ] Branch `claude/unified-telemetry-findings-refactor` has the plan 1 commits in order; the tree is clean

---

**End of plan 1.**
