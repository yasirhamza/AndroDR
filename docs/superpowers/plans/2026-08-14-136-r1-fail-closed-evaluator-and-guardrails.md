# R1: Fail-Closed Evaluator + Pure-Emitter Guardrails — Implementation Plan (rev 2, post plan-gate ceremony)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship R1 of the pure-emitter contract (spec `docs/superpowers/specs/2026-08-14-136-pure-emitter-contract-design.md`): the evaluator skips (never mis-evaluates) rules referencing unresolvable `ioc_lookup` names; skips surface truthfully (report section, not the partial-scan alarm, never as "resolved"); guardrails B1–B5 land dual-gated.

**Architecture:** Workstream A = `SigmaRuleEvaluator` pre-scan + skip; a no-arg `SigmaRuleEngine.unevaluableRules()` (reads the engine's own `@Volatile iocLookups` — single source, no drift) feeds a capability-skip surface: `ScannerFailure` entries with a dedicated `exception` kind that are **excluded** from `isPartialScan` and **rendered** by `ReportFormatter`; skipped ids are excluded from `resolvedFindings` and from `computeAtomBindings`. Workstream B = build gates on the AndroDR side and data-driven lints on the rules-repo side; `judgment-field-allowlist.yml` is the single data source of the frozen judgment set, consumed by `validate-rule.py` (PR gate) AND AndroDR cross-checks (build gate) — the #268 dual-gate doctrine.

**Tech Stack:** Kotlin + JUnit4 (+ mockk for engine tests), Python 3.11 + pytest, snakeyaml.

## Global Constraints

- Env for every gradle/adb command: `export JAVA_HOME=/home/yasir/Applications/android-studio/jbr; export ANDROID_HOME=/home/yasir/Android/Sdk; export PATH="$JAVA_HOME/bin:$ANDROID_HOME/platform-tools:$PATH"`.
- No new dependencies in either repo. Detekt + Android Lint clean.
- **Skip unit = the whole rule**, and an `IOC_LOOKUP` matcher with a missing/blank/non-string lookup name is itself unresolvable (fail-closed) — no matcher-level `false` fallback anywhere.
- Skip-entry format (exact): `ScannerFailure(scanner = "ruleCapability", exception = UNREGISTERED_IOC_LOOKUP, message = "rule <ruleId> not evaluated on this build: unregistered ioc_lookup '<name>'")` where `UNREGISTERED_IOC_LOOKUP = "UnregisteredIocLookup"` (a `const` in `ScanResult.kt`). Capability skips are NOT scanner failures: they must not trip `isPartialScan`.
- Frozen judgment-field data lives in ONE place: `validation/judgment-field-allowlist.yml` top-level keys (expected: `from_trusted_store`, `is_sideloaded`, `is_known_oem_app`). Kotlin/pytest freeze checks assert taxonomy-marked == allowlist keys — never a hardcoded set in test code (Phase 3 must be a data-only edit).
- Every taxonomy field declares `kind: raw_fact | judgment` (spec B4 verbatim — completeness is the contract; an unlabeled field is a CI failure, not a default).
- Severity caps single source `validation/severity-caps.yml` (`caps: { device_posture: medium }`); the Python consumer mirrors `SeverityCapPolicy.kt`'s `severityOrder` list + index-clamp comparison (a second cap entry must work with zero new code). Absent category ⇒ uncapped.
- New Kotlin tests locate the submodule via `TestRuleRepo` (its KDoc mandates it; a private `/home/yasir/AndroDR/...` fallback can silently resolve to the MAIN checkout's different pin — false green).
- Rules-repo changes follow CLAUDE.md safe-ordering (branch → pinned-submodule AndroDR PR → CI green → user-gated rules-main merge → re-point). None of the touched files is in `rules.txt` ⇒ no `rules.sha256` regen.
- **R1→Phase-2 window constraint (must land IN the rules repo, Task 5):** no delivered rule may add a reference to any `ioc_lookup` name until the R1 (fail-closed) rollout is confirmed fleet-uniform — a pre-R1 binary resolves an unknown name to matcher-false and over-fires under negation.
- CONTROLLER does all submodule git; implementers edit submodule files as plain files, uncommitted.
- Final review = full 4-agent ceremony. AndroDR PR targets `main`, body `Refs #136`.
- Commit scopes follow repo history: `feat(sigma)`, `test(sigma)`, `feat(scanner)` — never `arch`.

---

### Task 1: Fail-closed evaluator core

**Files:**
- Modify: `app/src/main/java/com/androdr/sigma/SigmaRuleEvaluator.kt` (evaluate loop L96–129; new fun + const)
- Test (create): `app/src/test/java/com/androdr/sigma/FailClosedLookupTest.kt`

**Interfaces:**
- Consumes: `SigmaRule.detection.selections: Map<String, SigmaSelection>`, `SigmaSelection.fieldMatchers: List<SigmaFieldMatcher>`, `SigmaFieldMatcher(fieldName, modifier, values: List<Any>, allRequired)`; runtime lookup-name extraction `values.firstOrNull()?.toString()` (L281–284 — the pre-scan and this branch must stay changed together).
- Produces: `SigmaRuleEvaluator.unevaluableRules(rules: List<SigmaRule>, iocLookups: Map<String, (Any) -> Boolean>): Map<String, String>` (ruleId → offending name or `MISSING_LOOKUP_NAME`); `internal const val MISSING_LOOKUP_NAME = "(missing lookup name)"`.

- [ ] **Step 1: Write the failing tests** (`FailClosedLookupTest.kt`)

Parse inline YAML with `SigmaRuleParser.parse(yaml: String): SigmaRule?` (the idiom already used at `SigmaRuleEvaluatorTest.kt:591/632`). The first rule is the migrated androdr-010 shape verbatim from the parked Phase-2 branch — the exact over-fire, preserved as a permanent regression. Note: the `unevaluableRules` equality assertions rely on snakeyaml preserving YAML mapping order (it does — LinkedHashMap-backed).

```kotlin
package com.androdr.sigma

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Fail-closed evaluator contract (spec 2026-08-14, Workstream A): a rule
 * referencing an ioc_lookup this binary cannot resolve — unregistered name,
 * or a matcher with no name at all — is SKIPPED whole. The legacy
 * matcher-false fallback inverts negated gates (the #136 Phase-2 over-fire).
 */
class FailClosedLookupTest {

    private val migratedSideloadRule = """
        id: androdr-010
        title: Sideloaded Application
        status: stable
        level: medium
        category: incident
        logsource: { product: androdr, service: app_scanner }
        detection:
          selection:
            is_system_app: false
          store_installed:
            installer|ioc_lookup: trusted_installer_db
          filter_known_good:
            package_name|ioc_lookup: known_good_app_db
          condition: selection and not store_installed and not filter_known_good
    """.trimIndent()

    private val filterLookupRule = """
        id: androdr-777
        title: Filter Lookup Rule
        status: stable
        level: medium
        category: incident
        logsource: { product: androdr, service: app_scanner }
        detection:
          selection:
            has_device_admin: true
          filter_trusted:
            installer|ioc_lookup: trusted_installer_db
          condition: selection and not filter_trusted
    """.trimIndent()

    private val namelessLookupRule = """
        id: androdr-779
        title: Nameless Lookup Rule
        status: stable
        level: medium
        category: incident
        logsource: { product: androdr, service: app_scanner }
        detection:
          selection:
            has_device_admin: true
          store_installed:
            installer|ioc_lookup:
          condition: selection and not store_installed
    """.trimIndent()

    private val noLookupRule = """
        id: androdr-778
        title: No Lookup Rule
        status: stable
        level: medium
        category: incident
        logsource: { product: androdr, service: app_scanner }
        detection:
          selection:
            has_device_admin: true
          condition: selection
    """.trimIndent()

    private fun parse(yaml: String): SigmaRule =
        requireNotNull(SigmaRuleParser.parse(yaml)) { "test rule failed to parse" }

    private val sideloadedRecord = mapOf<String, Any?>(
        "package_name" to "com.evil.app", "is_system_app" to false,
        "installer" to null, "has_device_admin" to true
    )

    private val allRegistered = mapOf<String, (Any) -> Boolean>(
        "trusted_installer_db" to { v -> v == "com.android.vending" },
        "known_good_app_db" to { _ -> false }
    )

    @Test
    fun `unregistered lookup in negated selection - rule skipped, no over-fire`() {
        val findings = SigmaRuleEvaluator.evaluate(
            listOf(parse(migratedSideloadRule)), listOf(sideloadedRecord),
            "app_scanner", iocLookups = emptyMap()
        )
        assertTrue(
            "Rule with unregistered lookup must be skipped whole, got: $findings",
            findings.none { it.ruleId == "androdr-010" }
        )
    }

    @Test
    fun `unregistered lookup in filter - rule skipped, exemption never defeated`() {
        val findings = SigmaRuleEvaluator.evaluate(
            listOf(parse(filterLookupRule)), listOf(sideloadedRecord),
            "app_scanner", iocLookups = emptyMap()
        )
        assertTrue(findings.none { it.ruleId == "androdr-777" })
    }

    @Test
    fun `lookup matcher with NO name is unresolvable even when all names registered`() {
        // Fail-closed on the nameless spelling `installer|ioc_lookup:` — the
        // parser yields values = emptyList(); the legacy branch resolved it to
        // false, inverting the negated gate (the fail-OPEN hole).
        val findings = SigmaRuleEvaluator.evaluate(
            listOf(parse(namelessLookupRule)), listOf(sideloadedRecord),
            "app_scanner", iocLookups = allRegistered
        )
        assertTrue(findings.none { it.ruleId == "androdr-779" })
        assertEquals(
            mapOf("androdr-779" to SigmaRuleEvaluator.MISSING_LOOKUP_NAME),
            SigmaRuleEvaluator.unevaluableRules(listOf(parse(namelessLookupRule)), allRegistered)
        )
    }

    @Test
    fun `registered lookups - behavior identical to today`() {
        val sideloaded = SigmaRuleEvaluator.evaluate(
            listOf(parse(migratedSideloadRule)), listOf(sideloadedRecord),
            "app_scanner", iocLookups = allRegistered
        )
        assertTrue(sideloaded.any { it.ruleId == "androdr-010" && it.triggered })

        val storeRecord = sideloadedRecord + mapOf("installer" to "com.android.vending")
        val exempt = SigmaRuleEvaluator.evaluate(
            listOf(parse(migratedSideloadRule)), listOf(storeRecord),
            "app_scanner", iocLookups = allRegistered
        )
        assertTrue(exempt.none { it.ruleId == "androdr-010" && it.triggered })
    }

    @Test
    fun `mixed rule list - only the lookup rule is skipped`() {
        val findings = SigmaRuleEvaluator.evaluate(
            listOf(parse(migratedSideloadRule), parse(noLookupRule)),
            listOf(sideloadedRecord), "app_scanner", iocLookups = emptyMap()
        )
        assertTrue(findings.none { it.ruleId == "androdr-010" })
        assertTrue(findings.any { it.ruleId == "androdr-778" && it.triggered })
    }

    @Test
    fun `unevaluableRules maps ruleId to first missing name`() {
        val rules = listOf(parse(migratedSideloadRule), parse(noLookupRule))
        assertEquals(
            mapOf("androdr-010" to "trusted_installer_db"),
            SigmaRuleEvaluator.unevaluableRules(rules, emptyMap())
        )
        assertTrue(SigmaRuleEvaluator.unevaluableRules(rules, allRegistered).isEmpty())
    }
}
```

- [ ] **Step 2: Verify failure** — `./gradlew testDebugUnitTest --tests 'com.androdr.sigma.FailClosedLookupTest'` → FAIL (`unevaluableRules`/`MISSING_LOOKUP_NAME` unresolved; skip tests fail because today the 010-shape rule over-fires).

- [ ] **Step 3: Implement in `SigmaRuleEvaluator`**

```kotlin
/** Sentinel for an IOC_LOOKUP matcher that names no lookup at all. */
internal const val MISSING_LOOKUP_NAME = "(missing lookup name)"   // inside object SigmaRuleEvaluator

/**
 * Rules this binary cannot faithfully evaluate: any detection matcher is an
 * ioc_lookup whose name is unregistered — or missing/blank entirely.
 * Returns ruleId → offending name (or [MISSING_LOOKUP_NAME]). evaluate()
 * SKIPS these rules whole (fail-closed): the legacy matcher-false fallback
 * inverts negated gates (#136 Phase-2 over-fire) and silently defeats
 * filter exemptions. Must stay in lockstep with the IOC_LOOKUP branch below.
 */
fun unevaluableRules(
    rules: List<SigmaRule>,
    iocLookups: Map<String, (Any) -> Boolean>
): Map<String, String> {
    val result = mutableMapOf<String, String>()
    for (rule in rules) {
        val offending = rule.detection.selections.values.asSequence()
            .flatMap { it.fieldMatchers.asSequence() }
            .filter { it.modifier == SigmaModifier.IOC_LOOKUP }
            .map { m ->
                m.values.firstOrNull()?.toString()?.takeIf { it.isNotBlank() }
                    ?: MISSING_LOOKUP_NAME
            }
            .firstOrNull { it == MISSING_LOOKUP_NAME || it !in iocLookups }
        if (offending != null) result[rule.id] = offending
    }
    return result
}
```

In `evaluate()` (L103):
```kotlin
val matchingRules = rules.filter { it.service == service }
val skipped = unevaluableRules(matchingRules, iocLookups).keys
val evaluableRules = if (skipped.isEmpty()) matchingRules
else matchingRules.filter { it.id !in skipped }
```
and iterate `evaluableRules`. No cache (registry can change between scans; cost trivial — deliberate deviation from the spec's "cached" wording, note in the commit body). Leave L281–284 untouched.

Parser note (verify empirically via the `namelessLookupRule` test): the parser maps a null `installer|ioc_lookup:` value to `values = emptyList()` (`SigmaRuleParser.kt:231`), and this pre-scan flags that matcher via `MISSING_LOOKUP_NAME`. Confirm the parser actually emits an `IOC_LOOKUP` matcher with empty values (not that it drops the matcher entirely); if it drops it, the `androdr-779` assertion will fail and the empty-`store_installed`-selection path must instead be confirmed fail-safe (a separate pre-existing dead-selection concern already gated at PR time by `validate-rule.py`).

- [ ] **Step 4: Verify pass** — new tests + `--tests 'com.androdr.sigma.SigmaRuleEvaluatorTest'`. If an existing test asserted matcher-false for unregistered lookups, update it to expect skip and flag it in the report.

- [ ] **Step 5: Full suite + commit**
```bash
./gradlew testDebugUnitTest detekt
git add app/src/main/java/com/androdr/sigma/SigmaRuleEvaluator.kt app/src/test/java/com/androdr/sigma/FailClosedLookupTest.kt
git commit -m "feat(sigma): fail-closed evaluator — skip rules with unresolvable ioc_lookup (#136 R1)"
```

### Task 2: Skip observability — engine API, both scan paths, report section

**Files:**
- Modify: `app/src/main/java/com/androdr/sigma/SigmaRuleEngine.kt` (no-arg delegate near the `evaluate*` family)
- Modify: `app/src/main/java/com/androdr/data/model/ScanResult.kt` (const + `isPartialScan`)
- Modify: `app/src/main/java/com/androdr/scanner/ScanOrchestrator.kt` (`runFullScanInner` after `scannerErrors` decl ~L232; `analyzeBugReport`'s own list ~L451; shared private helper)
- Modify: `app/src/main/java/com/androdr/reporting/ReportFormatter.kt` (new section)
- Modify: `app/src/main/java/com/androdr/ui/dashboard/DashboardScreen.kt` (L600 banner-body count)
- Test: extend `FailClosedLookupTest.kt` (engine) + `app/src/test/java/com/androdr/reporting/`'s existing ReportFormatter test file (locate it; extend)

**Interfaces:**
- Consumes: Task 1's `unevaluableRules`; `ScannerFailure(scanner, exception, message)` (`ScanResult.kt:26`); the engine's private `@Volatile iocLookups` set by `setIocLookups` and `effectiveRules()`.
- Produces: `SigmaRuleEngine.unevaluableRules(): Map<String, String>` (NO-ARG — reads the engine's own lookup field so "what evaluate skipped" and "what we report" share one input by construction); `const val UNREGISTERED_IOC_LOOKUP = "UnregisteredIocLookup"` in `ScanResult.kt`.

- [ ] **Step 1: Failing engine test** (append to `FailClosedLookupTest.kt`; mirror `SigmaRuleEngineTest.kt:12-31` construction — `SigmaRuleEngine(mockk<Context>(relaxed = true))`, rules injected via `setRemoteRules` (merges over never-loaded bundled rules) or the `setBundledRulesDirectly` reflection helper):

```kotlin
@Test
fun `engine reports unevaluable rules over its effective set via its own lookups`() {
    val engine = SigmaRuleEngine(io.mockk.mockk(relaxed = true))
    engine.setRemoteRules(listOf(parse(migratedSideloadRule), parse(noLookupRule)))
    engine.setIocLookups(emptyMap())
    assertEquals(mapOf("androdr-010" to "trusted_installer_db"), engine.unevaluableRules())
    engine.setIocLookups(allRegistered)
    assertTrue(engine.unevaluableRules().isEmpty())
}
```

- [ ] **Step 2: Verify failure**, then implement:

`SigmaRuleEngine`:
```kotlin
/**
 * Rules the CURRENT binary cannot evaluate (unresolvable ioc_lookup),
 * over the full effective rule set, judged against the same iocLookups
 * field evaluate() uses — single source, no observability drift.
 */
fun unevaluableRules(): Map<String, String> =
    SigmaRuleEvaluator.unevaluableRules(effectiveRules(), iocLookups)
```

`ScanResult.kt` — add beside `ScannerFailure`:
```kotlin
/** ScannerFailure.exception value marking a capability skip, not a crash. */
const val UNREGISTERED_IOC_LOOKUP = "UnregisteredIocLookup"
```
and change `isPartialScan` to exclude capability skips (a skip is accepted under-detection, not a failed scanner — it must not raise the red partial-scan banner):
```kotlin
val isPartialScan: Boolean
    get() = scannerErrors.any { it.exception != UNREGISTERED_IOC_LOOKUP }
```

`ScanOrchestrator` — one private helper, called from BOTH `runFullScanInner` (after the `scannerErrors` declaration, before persisting the result) and `analyzeBugReport` (into its own errors list):
```kotlin
/** Records one capability-skip entry per rule this binary cannot evaluate. */
private fun recordRuleCapabilitySkips(errors: MutableList<ScannerFailure>) {
    sigmaRuleEngine.unevaluableRules().forEach { (ruleId, lookupName) ->
        errors.add(
            ScannerFailure(
                scanner = "ruleCapability",
                exception = UNREGISTERED_IOC_LOOKUP,
                message = "rule $ruleId not evaluated on this build: unregistered ioc_lookup '$lookupName'"
            )
        )
    }
}
```
(The message is a capability statement — deliberately service-agnostic, so it is true even for rules of services a given scan didn't run.)

`DashboardScreen.kt` — the partial-scan banner is visibility-gated on `isPartialScan` (L148, now correct), but its body renders `scan.scannerErrors.size` (L600), which still counts skip entries. Make the count consistent with the predicate:
```kotlin
scan.scannerErrors.count { it.exception != UNREGISTERED_IOC_LOOKUP }
```
so a banner shown for a real failure never inflates its count with accepted capability skips.

`ReportFormatter` — render the skips as their own section (distinct from scanner failures; today NOTHING in `reporting/` reads `scannerErrors` — this section makes the spec's diagnosability claim true). Locate the section list and append after the findings sections:
```kotlin
val capabilitySkips = scan.scannerErrors.filter { it.exception == UNREGISTERED_IOC_LOOKUP }
if (capabilitySkips.isNotEmpty()) {
    appendLine()
    appendLine("RULES NOT EVALUATED ON THIS BUILD (missing capability — update the app):")
    capabilitySkips.forEach { appendLine("  - ${it.message}") }
}
```
Adapt to the formatter's actual builder idiom (read the file; keep the section header text).

- [ ] **Step 3: ReportFormatter + isPartialScan tests** — extend the existing ReportFormatter test file: a `ScanResult` with one capability-skip entry renders the section and `isPartialScan == false`; with one real scanner failure `isPartialScan == true`.

- [ ] **Step 4: Full suite + commit**
```bash
./gradlew testDebugUnitTest detekt
git add app/src/main/java/com/androdr/sigma/SigmaRuleEngine.kt app/src/main/java/com/androdr/data/model/ScanResult.kt app/src/main/java/com/androdr/scanner/ScanOrchestrator.kt app/src/main/java/com/androdr/reporting/ReportFormatter.kt app/src/test/java
git commit -m "feat(scanner): surface rule capability skips — report section, not partial-scan alarm (#136 R1)"
```

### Task 3: Skip correctness in consumers — resolvedFindings + atom bindings

**Files:**
- Modify: `app/src/main/java/com/androdr/scanner/ScanOrchestrator.kt` (`resolvedFindings` diff, ~L584-591)
- Modify: `app/src/main/java/com/androdr/sigma/SigmaRuleEngine.kt` (`computeAtomBindings`, L116-142)
- Test: extend `FailClosedLookupTest.kt` + the orchestrator/diff test file if one exists (locate; else engine-level)

**Interfaces:** consumes Task 2's `unevaluableRules()` and `UNREGISTERED_IOC_LOOKUP`.

- [ ] **Step 1: Failing tests**

1. **Resolved-suppression:** a rule id that TRIGGERED in the previous scan and is SKIPPED (not merely un-triggered) in the current scan must NOT appear in `resolvedFindings` — a skipped CRITICAL rendering as "resolved" is affirmative false reassurance, worse than a miss. The real target is `computeDiff(newer, older)` at `ScanOrchestrator.kt:574-585` (`resolvedFindings = older.findings.filter { it.triggered && it.ruleId !in newerTriggeredIds }`). Pass the skipped-id set in as a **structured** argument (a new `computeDiff` param, sourced from `sigmaRuleEngine.unevaluableRules().keys` at the call site) and subtract it — do NOT parse rule ids back out of `ScannerFailure.message` strings (fragile; `ScannerFailure` has no structured ruleId field). `computeDiff` is already a public function → test it directly.

   > **AMENDED 2026-08-14 (final-review wave, user ruling).** Shipped differently:
   > `ScannerFailure` DID gain a structured `ruleId` field (no Room migration — the
   > column is kotlinx-serialized JSON TEXT), and `computeDiff(newer, older)` derives
   > the skip set from `newer`'s own persisted capability-skip entries instead of
   > taking a parameter defaulted from the live engine. The "no message parsing"
   > constraint above still holds; the "no structured ruleId field" premise no longer
   > does. Rationale: an ambient default made the diff impure — a cold-start History
   > diff (before any scan ran in the process) read the wrong skip set. See the spec's
   > residual (d).
2. **Atom-binding exclusion:** an atom rule whose id is in `unevaluableRules()` must produce no bindings from `computeAtomBindings` (engine-level test: atom rule with an `ioc_lookup` matcher + empty lookups → correlation receives no binding for it).
3. **Corpus lint:** no bundled `timeline/` atom rule may contain an `IOC_LOOKUP` matcher (add to `FailClosedLookupTest` as a bundled-corpus scan using the existing rule-loading idiom from `BundledRulesSchemaCrossCheckTest`) — keeps the binding path structurally lookup-free until it, too, pre-scans.

- [ ] **Step 2: Implement**

- `resolvedFindings`: compute the skipped id set once (`sigmaRuleEngine.unevaluableRules().keys`) and subtract it from the resolved diff.
- `computeAtomBindings`: filter the atom rule set through the same skipped id set before binding.

- [ ] **Step 3: Full suite + commit**
```bash
./gradlew testDebugUnitTest detekt
git add app/src/main/java/com/androdr/scanner/ScanOrchestrator.kt app/src/main/java/com/androdr/sigma/SigmaRuleEngine.kt app/src/test/java
git commit -m "fix(scanner): skipped rules never read as resolved; atom bindings respect fail-closed (#136 R1)"
```

### Task 4: Build gates B1 + B2 (AndroDR-only)

**Files:**
- Test (create): `app/src/test/java/com/androdr/sigma/PureEmitterContractTest.kt`

- [ ] **Step 1: Write both gates** (they pass immediately; Step 2 RED-proofs them)

```kotlin
package com.androdr.sigma

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * Pure-emitter contract build gates (#136 checks 1+2, spec B1/B2).
 * Source-scanning, matching the repo's cross-check-test convention.
 */
class PureEmitterContractTest {

    private fun mainSourceRoot(): File = listOf(
        File("app/src/main/java"),
        File("../app/src/main/java"),
        File("/home/yasir/AndroDR/app/src/main/java"),
    ).firstOrNull { it.isDirectory } ?: error("main source root not found")

    // B1: Finding may only be constructed — or severity-mutated via copy —
    // in the evaluator. The data class itself is declared there (pinned:
    // moving the declaration means revisiting this gate, not allowlisting).
    private val findingConstructionAllowlist = setOf(
        "com/androdr/sigma/SigmaRuleEvaluator.kt",
    )
    private val constructionPattern = Regex("""(?<![\w.])Finding\(""")
    private val severityCopyPattern = Regex("""\.copy\([^)]*\blevel\s*=""")

    @Test
    fun `Finding is constructed and severity-mutated only inside the evaluator`() {
        val offenders = mainSourceRoot().walkTopDown()
            .filter { it.isFile && it.extension == "kt" }
            .filter { f -> findingConstructionAllowlist.none { f.path.replace('\\', '/').endsWith(it) } }
            .filter { f ->
                f.readLines().any { line ->
                    val code = line.substringBefore("//")
                    constructionPattern.containsMatchIn(code) ||
                        severityCopyPattern.containsMatchIn(code)
                }
            }
            .map { it.path }.toList()
        assertTrue(
            "Finding construction / level-copy outside the evaluator (findings are " +
                "derived only by the rule engines — #84/#136): $offenders",
            offenders.isEmpty()
        )
    }

    // B2: the telemetry emitter surface = every type with a toFieldMap().
    // Enumerated set asserted for equality so a NEW emitter fails loudly and
    // gets classified here, and severity-like fields are checked both as
    // property declarations and as emitted field-map keys.
    private val expectedEmitterFiles = setOf(
        // Verified real set via `grep -rl "fun toFieldMap" app/src/main/java`
        // (2026-08-14). Re-verify at implementation time; do not trust blindly.
        "AccessibilityTelemetry.kt", "AppOpsTelemetry.kt", "AppTelemetry.kt",
        "DeviceTelemetry.kt", "DnsEvent.kt", "FileArtifactTelemetry.kt",
        "NetworkTelemetry.kt", "ProcessTelemetry.kt", "ReceiverTelemetry.kt",
        // extension emitters
        "TelemetryFieldMaps.kt",
    )
    private val forbiddenProperty = Regex("""\b(val|var)\s+(severity|level|priority)\b""")
    private val forbiddenKey = Regex(""""(severity|level|priority)"\s+to\b""")

    @Test
    fun `telemetry emitters declare no severity - as property or field-map key`() {
        val root = mainSourceRoot()
        val actual = root.walkTopDown()
            .filter { it.isFile && it.extension == "kt" }
            .filter { it.readText().contains("fun toFieldMap") }
            .map { it.name }.toSet()
        assertEquals(
            "Emitter set changed — classify the new/removed toFieldMap type here " +
                "AND in logsource-taxonomy.yml (every emitted field needs a kind)",
            expectedEmitterFiles, actual
        )
        val offenders = root.walkTopDown()
            .filter { it.isFile && it.name in expectedEmitterFiles }
            .filter { f ->
                f.readLines().any { line ->
                    val code = line.substringBefore("//")
                    forbiddenProperty.containsMatchIn(code) || forbiddenKey.containsMatchIn(code)
                }
            }
            .map { it.name }.toList()
        assertTrue(
            "Telemetry emitters must stay severity-free (findings own severity — #84/#136): $offenders",
            offenders.isEmpty()
        )
    }
}
```
First run `grep -rl "fun toFieldMap" app/src/main/java` and correct `expectedEmitterFiles` to the real set (the list above is the verified 2026-08-14 set — re-verify, don't trust). If a file in the set legitimately declares `val level` for a non-severity meaning, flag it in the report rather than silently narrowing the regex.

Note — `severityCopyPattern`'s case-sensitivity is load-bearing: the one near-match in main sources, `CveRepository.kt:279` `.copy(fixedInPatchLevel = …)`, is NOT matched because `\blevel` is lowercase-and-word-boundary-anchored ("PatchLevel" has neither). Do NOT add `RegexOption.IGNORE_CASE` — it would false-positive there.

- [ ] **Step 2: RED-proof by mutation** (each, then revert):
1. A bare `Finding(ruleId = …)` construction in `ReportFormatter.kt` → B1 FAILS.
2. A `someFinding.copy(level = "low")` in `ScanOrchestrator.kt` → B1 FAILS.
3. `val severity: String = ""` in `DnsEvent.kt` (deliberately NOT AppTelemetry — proves the non-`*Telemetry.kt` coverage) → B2 FAILS.
4. `"severity" to "high"` inside a `toFieldMap` in `TelemetryFieldMaps.kt` → B2 FAILS.

- [ ] **Step 3: Commit**
```bash
git add app/src/test/java/com/androdr/sigma/PureEmitterContractTest.kt
git commit -m "test(sigma): Finding-construction + emitter-severity build gates (#136 R1)"
```

### Task 5: Rules-repo lints — caps, taxonomy kinds, judgment allowlist, #275

**Files (inside `third-party/android-sigma-rules/`, plain-file edits, committed by CONTROLLER on branch `feat/136-r1-lints`):**
- Create: `validation/severity-caps.yml`, `validation/judgment-field-allowlist.yml`
- Modify: `validation/logsource-taxonomy.yml` (EVERY field gains `kind`), `validation/validate-rule.py`, `validation/ioc-lookup-definitions.yml` (header constraint note)
- Test: extend `validation/test_validate_rule_lints.py`

**Interfaces (consumed by Task 6):** caps shape `caps: {device_posture: medium}`; taxonomy field entries all carry `kind`; allowlist shape below (top-level keys = THE frozen judgment set; `delivered`/`staging` id lists).

- [ ] **Step 1: Data files**

`validation/severity-caps.yml`:
```yaml
# Per-category maximum finding severity — SINGLE SOURCE (#136 R1, spec B3).
# Keys are RULE categories (incident|device_posture — the vocabulary of
# rule `category:`, NOT display categories like app_risk). Consumers:
# validate-rule.py (PR gate, severityOrder index-clamp) + AndroDR
# SeverityCapsCrossCheckTest (build gate vs SeverityCapPolicy).
# Categories absent here are uncapped.
caps:
  device_posture: medium
```

Taxonomy: add `kind: raw_fact` to every field entry, except `kind: judgment` on exactly `app_scanner`'s `from_trusted_store`, `is_sideloaded`, `is_known_oem_app` (mechanical sweep, ~105 entries; completeness IS the contract — an unlabeled field must fail CI, so "absent = raw_fact" defaults are forbidden).

`validation/judgment-field-allowlist.yml` — top-level keys are the authoritative frozen judgment set; ids split by directory so a staging twin can never shield its delivered sibling. GENERATE the lists (run per directory from the submodule root), then paste; the illustrative ids below are from a prior sweep (from_trusted_store delivered: 010,011,012,013,014,016,017,068,069,089; is_known_oem_app spans 010–017,068,069 incl. 015; is_sideloaded: 067,077,087,088,089 + staging 091 etc.) — trust only the generation output:
```bash
for d in app_scanner staging/app_scanner; do echo "== $d"; for f in from_trusted_store is_sideloaded is_known_oem_app; do
  echo " $f:"; grep -l "^\s*${f}[:|]" $d/*.yml 2>/dev/null \
    | xargs -I{} python3 -c "import yaml;print('  -',yaml.safe_load(open('{}'))['id'])" | sort -u
done; done
```
```yaml
# Rules permitted to reference judgment-kind fields during the strangler-fig
# parallel run (#136 R1, spec B5). The TOP-LEVEL KEYS are the authoritative
# frozen judgment-field set (taxonomy kind:judgment must equal them — both
# validators assert it). Entries may only be REMOVED (Phase 2 empties
# from_trusted_store.delivered; Phase 3 deletes whole keys). delivered vs
# staging are separate lists: a staging twin never authorizes its delivered id.
allowed:
  from_trusted_store:
    delivered: [<generated>]
    staging: [<generated>]
  is_sideloaded:
    delivered: [<generated>]
    staging: [<generated>]
  is_known_oem_app:
    delivered: [<generated>]
    staging: [<generated>]
```

`validation/ioc-lookup-definitions.yml` — append to the header comment:
```yaml
# CAPABILITY CONSTRAINT (#136 R1): a DELIVERED rule may only reference a
# lookup name after every fielded binary either registers it or fail-closed
# skips (app >= R1). Pre-R1 binaries resolve unknown names to matcher-false
# and OVER-FIRE under negation. Until R1 rollout is confirmed fleet-uniform,
# adding a new ioc_lookup reference to any delivered rule is forbidden.
```

- [ ] **Step 2: Failing pytest cases** (extend `test_validate_rule_lints.py` with its existing helpers; `APP_BASE = yaml.safe_load((REPO / "app_scanner" / "androdr_010_sideloaded_app.yml").read_text())` + `make_app_rule` mirroring `make_corr_rule`):

```python
# ---------- #275: ioc_lookup registration ----------
def test_unregistered_ioc_lookup_rejected(tmp_path):
    rule = make_app_rule(id="androdr-300")
    rule["detection"] = {"selection": {"package_name|ioc_lookup": "no_such_db"}, "condition": "selection"}
    result = run_validator_on(tmp_path, rule)
    assert result.returncode == 1
    assert "no_such_db" in result.stderr and "ioc-lookup-definitions" in result.stderr

def test_registered_ioc_lookup_accepted(tmp_path):
    rule = make_app_rule(id="androdr-301")
    rule["detection"] = {"selection": {"package_name|ioc_lookup": "known_good_app_db"}, "condition": "selection"}
    assert run_validator_on(tmp_path, rule).returncode == 0

def test_nameless_ioc_lookup_rejected(tmp_path):
    rule = make_app_rule(id="androdr-304")
    rule["detection"] = {"selection": {"installer|ioc_lookup": None}, "condition": "selection"}
    assert run_validator_on(tmp_path, rule).returncode == 1

# ---------- B5: judgment-field deprecation (delivered vs staging) ----------
def test_new_rule_using_judgment_field_rejected(tmp_path):
    rule = make_app_rule(id="androdr-302")
    rule["detection"] = {"selection": {"from_trusted_store": False}, "condition": "selection"}
    result = run_validator_on(tmp_path, rule)
    assert result.returncode == 1
    assert "judgment" in result.stderr and "from_trusted_store" in result.stderr

def test_allowlisted_delivered_rule_accepted(tmp_path):
    assert run_validator_on(tmp_path, copy.deepcopy(APP_BASE)).returncode == 0

def test_modifier_spelled_judgment_field_rejected(tmp_path):
    rule = make_app_rule(id="androdr-305")
    rule["detection"] = {"selection": {"is_sideloaded|equals": True}, "condition": "selection"}
    assert run_validator_on(tmp_path, rule).returncode == 1

# ---------- B4: complete kinds + data-driven freeze ----------
def test_every_taxonomy_field_declares_kind():
    tax = yaml.safe_load((THIS_DIR / "logsource-taxonomy.yml").read_text())
    missing = [f"{svc}/{fname}"
               for svc, sdef in tax["services"].items()
               for fname, fdef in sdef["fields"].items()
               if not isinstance(fdef, dict) or fdef.get("kind") not in ("raw_fact", "judgment")]
    assert missing == []

def test_judgment_set_equals_allowlist_keys():
    tax = yaml.safe_load((THIS_DIR / "logsource-taxonomy.yml").read_text())
    marked = {fname for sdef in tax["services"].values()
              for fname, fdef in sdef["fields"].items()
              if isinstance(fdef, dict) and fdef.get("kind") == "judgment"}
    allowed = set(yaml.safe_load((THIS_DIR / "judgment-field-allowlist.yml").read_text())["allowed"])
    assert marked == allowed  # the allowlist keys ARE the frozen set (data, not code)

# ---------- B3: caps single-source with rank comparison ----------
def test_severity_cap_sourced_from_yaml(tmp_path):
    caps = yaml.safe_load((THIS_DIR / "severity-caps.yml").read_text())["caps"]
    assert caps == {"device_posture": "medium"}
    assert run_validator_on(tmp_path, make_rule(id="androdr-303", level="critical")).returncode == 1
    assert run_validator_on(tmp_path, make_rule(id="androdr-306", level="medium")).returncode == 0
```
Run `python3 -m pytest validation/test_validate_rule_lints.py -v` → new cases FAIL; the existing regression sweep over the whole corpus must stay green throughout.

- [ ] **Step 3: Implement in `validate-rule.py`**

Loaders — follow `load_taxonomy`'s idiom exactly: narrow `except (OSError, yaml.YAMLError)` for the parse, separate structural validation with its own `sys.exit(FATAL…)` messages (do NOT wrap key access in a broad `except Exception`). Severity comparison — mirror the Kotlin policy so a future cap entry works with zero code:
```python
# Mirrors SeverityCapPolicy.kt severityOrder — the two must stay in lockstep.
SEVERITY_ORDER = ["critical", "high", "medium", "low", "informational"]

def cap_violated(declared: str, cap: str) -> bool:
    if declared not in SEVERITY_ORDER or cap not in SEVERITY_ORDER:
        return True  # unknown severities fail closed
    return SEVERITY_ORDER.index(declared) < SEVERITY_ORDER.index(cap)
```
Replace the hardcoded `category == "device_posture" and level in ("high","critical")` check (~L344-350) with a loop over `load_severity_caps(...)` using `cap_violated` (keep the existing error-message voice). In `main()` after `load_taxonomy`: FATAL if any field lacks `kind` ∈ {raw_fact, judgment}; FATAL if the judgment-marked set != `load_judgment_allowlist(...)` keys. In the per-field loop (after the field-membership check; `key_str`/`base_field`/`sel_value` in scope; `rule_id = rule.get("id")`; `in_staging` selects which id list applies):
```python
if "ioc_lookup" in key_str.split("|")[1:]:
    lookup_name = sel_value[field_key]
    if not isinstance(lookup_name, str) or not lookup_name.strip() \
            or lookup_name not in ioc_lookup_names:
        errors.append(
            f"ioc_lookup '{lookup_name}' is not registered in "
            f"validation/ioc-lookup-definitions.yml (registered: "
            f"{', '.join(sorted(ioc_lookup_names))}) — an R1+ binary skips the "
            f"whole rule; a pre-R1 binary OVER-FIRES under negation"
        )

field_def = taxonomy.get(service, {}).get("fields", {}).get(base_field)
if isinstance(field_def, dict) and field_def.get("kind") == "judgment":
    scope = "staging" if in_staging else "delivered"
    if rule_id not in judgment_allowlist.get(base_field, {}).get(scope, set()):
        errors.append(
            f"detection references judgment-kind field '{base_field}' — the "
            f"emitter contract (#136) forbids new uses ({scope} allowlist); "
            f"compute the judgment in the rule (e.g. installer|ioc_lookup) instead"
        )
```
Thread the loaded structures through `validate_rule(...)` params from `main()` (same pattern as `taxonomy`).

- [ ] **Step 4: Verify** — full pytest green INCLUDING the corpus sweep (a missing allowlist id ⇒ regenerate the data file, never weaken the lint).

- [ ] **Step 5: Hand off to controller** (files uncommitted; exact list in the report). Controller commits on `feat/136-r1-lints`, pushes.

### Task 6: AndroDR dual-gate cross-checks + submodule pin

**Files:**
- Test (create): `app/src/test/java/com/androdr/sigma/SeverityCapsCrossCheckTest.kt`, `app/src/test/java/com/androdr/sigma/TaxonomyJudgmentCrossCheckTest.kt`
- Modify: `app/src/test/java/com/androdr/sigma/DetectionFieldCrossCheckTest.kt` (the AndroDR-side B5 consumer) and, if needed, `TestRuleRepo.kt` (shared loaders)
- (Controller) submodule pin to the `feat/136-r1-lints` commit

**Interfaces:**
- Consumes: Task 5's three data files via **`TestRuleRepo.submoduleRoot()`** (mandated shared locator — no private path lists; its null ⇒ assume-skip convention applies); `SeverityCapPolicy.applyCap(RuleCategory, String): String`; `RuleCategory` = exactly {INCIDENT, DEVICE_POSTURE}.

- [ ] **Step 1: `SeverityCapsCrossCheckTest`** — snakeyaml `LoadSettings.builder().setAllowDuplicateKeys(false)` (the ioc-lookup-definitions sibling idiom — a duplicate `device_posture:` key must not silently overwrite the cap); for each YAML cap: `RuleCategory.valueOf(key.uppercase())` (an unknown key must FAIL with a readable message naming the two category vocabularies), assert `applyCap(cat, "critical") == cap`; for every `RuleCategory.entries` not in the YAML: `applyCap(cat, "critical") == "critical"`.

- [ ] **Step 2: `TaxonomyJudgmentCrossCheckTest`** — via `TestRuleRepo`: (a) every taxonomy field of every service declares `kind` ∈ {raw_fact, judgment}; (b) the judgment-marked field-name set EQUALS the `judgment-field-allowlist.yml` top-level key set (the frozen set is DATA — Phase 3 deletes a key + its marks in one rules-repo edit, and this test still passes).

- [ ] **Step 3: Extend `DetectionFieldCrossCheckTest`** (B5's AndroDR consumer — per its own KDoc, "neither guard can silently become the only one"): for every DELIVERED rule it already walks (res/raw + `rules.txt` files), any detection base-field whose taxonomy `kind` is `judgment` requires the rule id ∈ the allowlist's `delivered` list for that field. Follow the test's existing traversal + failure-message style.

- [ ] **Step 4: Controller pins the submodule; verify**
```
./gradlew testDebugUnitTest --tests 'com.androdr.sigma.SeverityCapsCrossCheckTest' --tests 'com.androdr.sigma.TaxonomyJudgmentCrossCheckTest' --tests 'com.androdr.sigma.DetectionFieldCrossCheckTest' --tests 'com.androdr.sigma.LogsourceTaxonomyCrossCheckTest'
```
(The taxonomy cross-checks read `fields.keys` only — `kind` cannot break them; verified during plan review.)

- [ ] **Step 5: Full suite + commit**
```bash
./gradlew testDebugUnitTest lintDebug detekt
git add app/src/test/java/com/androdr/sigma third-party/android-sigma-rules
git commit -m "test(sigma): severity-caps + judgment-field dual gates; pin submodule to lints branch (#136 R1)"
```

### Task 7: Ceremony, PR, gated go-live, release (controller-run)

- [ ] **Step 1:** Full gate green on the branch.
- [ ] **Step 2:** Full 4-agent ceremony on the PR diff. Security lens re-attacks: any evaluate/binding path still matcher-false on a missing lookup? nameless-lookup spelling? skip visible as resolved anywhere else (timeline, dashboard counts)? lint bypass via staging/id-reuse/modifier spellings? One fix wave + scoped re-review.
- [ ] **Step 3:** Push; open AndroDR PR → `main`, body `Refs #136` (fail-closed semantics, dual gates, submodule-on-branch note).
- [ ] **Step 4:** CI green (submodule-check red-by-design). **Verify the rules repo's main branch protection requires the `validate` check** (`gh api repos/android-sigma-rules/rules/branches/main/protection` — the lint gate is detective-only on push; PR-time enforcement is the real control). ⛔ **PAUSE — user confirms go-live.**
- [ ] **Step 5:** Merge rules branch → rules main (merge commit); re-point submodule to the main commit; CI fully green; merge the AndroDR PR.
- [ ] **Step 6:** File the pre-existing feed-fragility issue found during plan review: a remote rule throwing `SigmaRuleParseException` aborts the whole fetch loop (`SigmaRuleFeed.kt:81`), silently dropping every later rule in `rules.txt` — same "one feed edit changes fleet coverage" class. Comment on #136: R1 shipped (all three proposed checks + fail-closed evaluator + B4/B5); propose closing #136 with Phase 2/3 tracked in a new issue — user decides. Record the Phase-2 preconditions in that comment: (a) R1 fleet-uniform, (b) the `OemPrefixResolver` empty-data door (empty parsed feed ⇒ `trusted_installer_db` returns false for everything ⇒ post-migration over-fire; close by not registering a lookup whose backing set is empty — Phase-2 scope), (c) the no-new-lookup-references constraint holds until (a).
- [ ] **Step 7:** ⛔ **User-gated:** cut the R1 release via the existing release flow — **the first PUBLIC-testing release** (Play approved open testing 2026-08-14). Versioning (user decision 2026-08-14): **stay `0.9.0.$versionCode` through open testing** — NO versionName change in this release; `1.0` debuts at the production promotion. Shipping R1 in the first public build makes every public install lookup-capable from day one — the Phase-2 capability gap then only ever applies to closed-testing stragglers. At the gate, also present release polish: public-audience release notes and a Play-listing readiness check.

## Self-review + plan-gate reconciliation notes

- Rev 2 incorporates the 4-agent plan-gate findings: Task 2 rebuilt on the real APIs (no-arg engine fun; `sigmaRuleEngine`; mockk Context; `setRemoteRules`); nameless-lookup fail-closed (security F1); resolved-suppression + atom-binding exclusion as new Task 3 (security F2, architect F5); observability redesign — `UNREGISTERED_IOC_LOOKUP` kind excluded from `isPartialScan` + ReportFormatter section, no Room schema change (architect F1, security F3); B2 rebuilt on the `toFieldMap` surface with equality-asserted emitter set (security F5); B4 all-fields `kind` per spec (security F4); frozen set = allowlist keys, delivered/staging split, `DetectionFieldCrossCheckTest` as the AndroDR B5 consumer (architect F2/F6/F8); `severityOrder` ported (correctness F4); `TestRuleRepo` mandated (architect F9); B1 allowlist = evaluator only + `.copy(level=` clause (quality/security); naming/idiom minors applied; R1→Phase-2 constraint written into the rules repo (security F10); OemPrefixResolver empty-data door recorded as a Phase-2 precondition (architect F7).
- Spec deltas this plan implements are reflected in the spec file (same commit): observability wording, B1 site, error-table rows, Phase-2 preconditions.

**Round-2 gate (2026-08-14, inline — the subagent lenses hit the session token limit; controller verified against source):** round-1 fixes verified good against the code — no-arg `SigmaRuleEngine.unevaluableRules()` viable (`@Volatile private var iocLookups` field + `private fun effectiveRules()` = `getRules().filter { enabled }`, callable in-class); `setRemoteRules`/`setIocLookups` exist; parser maps null `ioc_lookup:` → `values=emptyList()` (sentinel path valid); B2 key-regex safe (no emitter emits a level/severity/priority key); B1 `.copy(level=)` has one case-safe near-miss only. New round-2 fixes folded in: (a) `DashboardScreen.kt:600` banner count must also exclude `UNREGISTERED_IOC_LOOKUP` (the `isPartialScan` change left the count inconsistent) — Important; (b) `expectedEmitterFiles` was missing `ReceiverTelemetry.kt` — Minor; (c) `resolvedFindings` must receive a structured skipped-id set, not parse `ScannerFailure` messages — Minor; (d) parser nameless-matcher behavior verified empirically by the test — Minor; (e) B1 case-sensitivity documented as load-bearing — Minor. No new Critical/Important architectural findings; the design converged at rev 2. Other absence-of-finding consumers (`FindingCard`, `DeviceAuditScreen` passed/total) read `.triggered` on findings that exist, so a skip is simply absent — safe, and moot on a current build (all 6 lookups registered; skips only occur post-Phase-2 on pre-R1 binaries).
