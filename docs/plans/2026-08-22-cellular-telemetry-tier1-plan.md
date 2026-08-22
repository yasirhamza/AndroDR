# Tier 1 Cellular Telemetry Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give AndroDR a `cellular_monitor` Tier 1 radio-telemetry source that flags candidate IMSI-catcher / fake-base-station / downgrade conditions from public Android telephony APIs only, delivered from an isolated worktree branch that never merges to `main`.

**Architecture:** A `TelephonyCallback` registered inside the existing `DnsVpnService` foreground context feeds a `RadioStateStore` (last snapshot + 5-minute rolling window). Each change event produces a `CellularSnapshot` carrying raw radio facts plus objective derived measurements, which `SigmaRuleEngine.evaluateCellular()` passes to the rule evaluator under the service string `cellular_monitor`. All judgment lives in five SIGMA YAML rules; the emitter never decides what is suspicious.

**Tech Stack:** Kotlin, Android `TelephonyManager` / `TelephonyCallback` / `CellInfoLte`, Hilt, JUnit4, Gradle, SIGMA YAML, git worktrees, GitHub Actions.

**Spec:** [`docs/plans/2026-08-22-cellular-telemetry-tier1-spec.md`](2026-08-22-cellular-telemetry-tier1-spec.md) — read it alongside this plan.

## Global Constraints

- **Never merge this branch to `main`.** It is research tooling with one user.
- **Never push the taxonomy or rule changes to `android-sigma-rules` `main`.** They live on an unmerged rules-repo branch only.
- **Emitters emit all facts verbatim.** The emitter may compute objective measurements ("changed", "N times in T minutes"); only rules decide what is suspicious.
- **Detection logic is rule-driven YAML, never hardcoded Kotlin.**
- **Rule `category:` must be `incident` or `device_posture`** — those are the only schema enum values. Cellular rules use `incident`.
- **Rule `level:` ceiling for v1 is `medium`.** Self-imposed (spec §8), not the `device_posture` cap.
- **Rule `status:` must be one of** `experimental`, `test`, `production`. New cellular rules use `experimental`.
- **Rule schema required fields:** `title`, `id`, `status`, `logsource`, `detection`, `level`, `category`.
- **Run all verification from inside the worktree path.** Running from the main checkout silently verifies the wrong tree.
- **`submodule-check` and `ci-success` are permanently red on this branch, by design** (spec §9a). `build-and-test` is the real gate.
- **`instrumented` is `continue-on-error` and exempt from `ci-success`** — read its result explicitly; never infer it from overall run status.

## Two Atomicity Rules (violating either breaks CI in the same commit)

These are the highest-risk part of this plan. Both are all-or-nothing within a single commit.

**A. Taxonomy ↔ model parity.** `LogsourceTaxonomyCrossCheckTest` asserts `untested = taxonomy.keys - actual.keys` is empty *and* `assertEquals(actual.size, taxonomy.size)`. Therefore the taxonomy service entry, the Kotlin `toFieldMap()`, **and** the test's own hardcoded service map must all land **in the same commit**. Adding any one alone fails the build.

**B. Rule packaging.** `BundledMirrorParityTest` asserts every `res/raw/sigma_*.yml` has a byte-equal mirror counterpart **and** a `rules.txt` entry. `BundledRulesManifestCompletenessTest` asserts every `res/raw/*.yml` is registered in `SigmaRuleEngine`'s `R.raw` list. Therefore each rule addition must, in one commit: add the bundled YAML, register it in `BUNDLED_RULE_IDS`, copy it byte-identically to the mirror, append to `rules.txt`, and regenerate `rules.sha256`.

## File Structure

| File | Responsibility |
|---|---|
| `app/src/main/java/com/androdr/data/model/CellularSnapshot.kt` | **Create.** Data class + `toFieldMap()`. The emitter contract. |
| `app/src/main/java/com/androdr/cellular/RadioStateStore.kt` | **Create.** Holds last snapshot + 5-min window; computes objective derived measurements. No judgment. |
| `app/src/main/java/com/androdr/cellular/CellularMonitor.kt` | **Create.** Registers `TelephonyCallback`, maps `CellInfo` → `CellularSnapshot`, invokes the engine. |
| `app/src/main/java/com/androdr/sigma/SigmaRuleEngine.kt` | **Modify.** Add `evaluateCellular()` + register five `R.raw` rule ids. |
| `app/src/main/java/com/androdr/network/DnsVpnService.kt` | **Modify.** Start/stop `CellularMonitor` alongside the VPN lifecycle. |
| `app/src/main/AndroidManifest.xml` | **Modify.** Declare `ACCESS_FINE_LOCATION` + `READ_PHONE_STATE` (branch only). |
| `app/src/main/res/raw/sigma_androdr_1{00..04}_*.yml` | **Create.** The five rules. |
| `app/src/test/java/com/androdr/sigma/LogsourceTaxonomyCrossCheckTest.kt` | **Modify.** Register `cellular_monitor` in the hardcoded map. |
| `app/src/test/java/com/androdr/cellular/*Test.kt` | **Create.** Unit tests for store + snapshot + rule firing. |
| `third-party/android-sigma-rules/validation/logsource-taxonomy.yml` | **Modify (rules branch).** Add `cellular_monitor` service. |
| `third-party/android-sigma-rules/cellular_monitor/*.yml` | **Create (rules branch).** Byte-identical mirrors. |
| `third-party/android-sigma-rules/rules.txt`, `rules.sha256` | **Modify (rules branch).** Delivery list + manifest. |

---

### Task 0: Worktree, branches, and the CI vehicle

**Files:**
- Create: worktree at `.claude/worktrees/cellular-tier1/`
- Create: branch `research/cellular-tier1` (AndroDR), branch `research/cellular-monitor` (rules repo)

**Interfaces:**
- Consumes: nothing.
- Produces: an isolated worktree path used by every later task; a draft PR that runs CI on every push.

- [ ] **Step 1: Create the worktree and branch**

```bash
cd /home/yasir/AndroDR
git worktree add -b research/cellular-tier1 .claude/worktrees/cellular-tier1 main
cd .claude/worktrees/cellular-tier1
git submodule update --init
```

- [ ] **Step 2: Create the rules-repo branch inside the worktree's submodule**

```bash
cd /home/yasir/AndroDR/.claude/worktrees/cellular-tier1/third-party/android-sigma-rules
git checkout -b research/cellular-monitor
git push -u origin research/cellular-monitor
```

- [ ] **Step 3: Verify the baseline is green before adding anything**

```bash
cd /home/yasir/AndroDR/.claude/worktrees/cellular-tier1
./gradlew testDebugUnitTest
```
Expected: PASS. If this fails, stop — the baseline is broken and nothing later is interpretable.

- [ ] **Step 4: Push the branch and open the draft PR (CI vehicle)**

```bash
cd /home/yasir/AndroDR/.claude/worktrees/cellular-tier1
git commit --allow-empty -m "chore: open research branch for Tier 1 cellular telemetry"
git push -u origin research/cellular-tier1
gh pr create --draft --base main --head research/cellular-tier1 \
  --title "DO NOT MERGE — research branch, CI vehicle only" \
  --body "Research branch for Tier 1 cellular telemetry (spec: docs/plans/2026-08-22-cellular-telemetry-tier1-spec.md).

**This PR exists only to run CI. It must never be merged.**

\`submodule-check\` and therefore \`ci-success\` are **permanently red by design**: the submodule pins an unmerged rules-repo branch, so \`git merge-base --is-ancestor\` can never pass. That also makes this PR mechanically unmergeable (branch protection requires \`ci-success\`, \`enforce_admins: true\`).

Read \`build-and-test\` as the real gate. \`instrumented\` is \`continue-on-error\` — read its result explicitly."
```

- [ ] **Step 5: Confirm CI ran**

```bash
gh pr checks --watch
```

Expected at Task 0: everything green, including `submodule-check` and `ci-success`. **They are green here and only go red from Task 2**, when the submodule pointer first moves to the unmerged rules branch. Do not expect red yet.

`build-and-test`, `lint-and-detekt` and `instrumented` are all **skipped** at this step, because the empty commit changes no files and the `changes` path filter therefore sets `code=false`.

**Do NOT use "`instrumented` appears in the job list" as the check that the CI vehicle works.** Verified empirically 2026-08-22: a skipped job is still *listed*, so `instrumented` is PRESENT under `workflow_dispatch` too. Presence cannot distinguish a `pull_request` run from a dispatch, and treating it as proof gives a false pass.

**The CI vehicle is confirmed working only at Task 2 Step 6**, the first commit carrying Kotlin. There, `instrumented` must show a real conclusion (`success`/`failure`), not `skipped`:

```bash
gh run view <run-id> --json jobs --jq '.jobs[] | select(.name=="instrumented") | .conclusion'
```

If that still prints `skipped` on a commit that changed `.kt` files, the draft-PR mechanism is not delivering on-device coverage — stop and re-examine §9a before continuing.

---

### Task 1: Spike — measure what an unprivileged app actually sees

**This task gates H1 and H6. Its output is an answer, not code.** Everything built here is throwaway and must not be carried into later tasks.

**Files:**
- Create: throwaway scratch code (deleted at end of task)

**Interfaces:**
- Consumes: nothing.
- Produces: three measured values that set defaults in Tasks 5, 7 and 8 — field richness, callback frequency, neighbour visibility.

- [ ] **Step 1: Add permissions temporarily to the manifest**

In `app/src/main/AndroidManifest.xml`, above `<application>`:

```xml
<uses-permission android:name="android.permission.ACCESS_FINE_LOCATION" />
<uses-permission android:name="android.permission.READ_PHONE_STATE" />
```

- [ ] **Step 2: Write a throwaway logger**

Create `app/src/main/java/com/androdr/cellular/SpikeLogger.kt`:

```kotlin
package com.androdr.cellular

import android.content.Context
import android.telephony.CellInfoLte
import android.telephony.TelephonyManager
import android.util.Log

object SpikeLogger {
    fun dumpOnce(context: Context) {
        val tm = context.getSystemService(TelephonyManager::class.java)
        @Suppress("MissingPermission")
        val all = tm.allCellInfo
        Log.i("SPIKE", "cellInfo count=${all.size}")
        all.filterIsInstance<CellInfoLte>().forEach { info ->
            val id = info.cellIdentity
            Log.i(
                "SPIKE",
                "registered=${info.isRegistered} ci=${id.ci} pci=${id.pci} tac=${id.tac} " +
                    "earfcn=${id.earfcn} bandwidth=${id.bandwidth} mcc=${id.mccString} " +
                    "mnc=${id.mncString} long=${id.operatorAlphaLong} short=${id.operatorAlphaShort} " +
                    "rsrp=${info.cellSignalStrength.rsrp}"
            )
        }
    }
}
```

- [ ] **Step 3: Call it from the app and read the log**

Invoke `SpikeLogger.dumpOnce(context)` from any existing screen's init, install with `./gradlew installDebug`, grant location, then:

```bash
adb logcat -s SPIKE
```

- [ ] **Step 4: Record the three measurements**

Write findings into the spec's §10 as measured values:
1. **Field richness** — is any field `2147483647` (`Integer.MAX_VALUE`)? List which.
2. **Neighbour visibility** — is `count` > 1, i.e. are non-registered neighbours returned?
3. **Callback frequency** — repeat while moving between cells; note seconds between distinct `ci` values.

- [ ] **Step 5: Decide and record the gates**

- If **field richness fails** (sentinels present): H2 and H4 may be unviable — record which rules survive.
- If **neighbour visibility fails** (`count == 1`): H4 is dead; drop it from Task 7.
- If **callbacks are sparse**: the §4 hybrid backstop is required; add it in Task 5.

- [ ] **Step 6: Delete all spike code and revert the manifest**

```bash
cd /home/yasir/AndroDR/.claude/worktrees/cellular-tier1
rm app/src/main/java/com/androdr/cellular/SpikeLogger.kt
git checkout app/src/main/AndroidManifest.xml
git status --short
```
Expected: clean tree. The spike leaves no code behind.

---

### Task 2: `CellularSnapshot` + taxonomy + cross-check registration

**Atomicity rule A applies — all three parts land in ONE commit.**

Sentinel handling is a deliberate refinement of spec §5: Android reports unavailable integers as `Integer.MAX_VALUE`, so those fields are nullable and normalized to `null`. This is consistent with spec §10 spike item 1, which anticipates other devices blanking fields.

**Files:**
- Create: `app/src/main/java/com/androdr/data/model/CellularSnapshot.kt`
- Create: `app/src/test/java/com/androdr/cellular/CellularSnapshotTest.kt`
- Modify: `third-party/android-sigma-rules/validation/logsource-taxonomy.yml`
- Modify: `app/src/test/java/com/androdr/sigma/LogsourceTaxonomyCrossCheckTest.kt`

**Interfaces:**
- Consumes: `TelemetrySource` (existing enum, `LIVE_SCAN` / `BUGREPORT_IMPORT`).
- Produces: `CellularSnapshot(...)` with `fun toFieldMap(): Map<String, Any?>` emitting exactly the 24 keys listed below. Tasks 3–8 depend on these exact key names.

- [ ] **Step 1: Write the failing test**

Create `app/src/test/java/com/androdr/cellular/CellularSnapshotTest.kt`:

```kotlin
package com.androdr.cellular

import com.androdr.data.model.CellularSnapshot
import com.androdr.data.model.TelemetrySource
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class CellularSnapshotTest {

    private fun sample() = CellularSnapshot(
        mcc = "427", mnc = "01", tac = 4100, ci = 12345L, pci = 77,
        earfcn = 1650, bands = listOf(3), bandwidthKhz = 20000, rat = "LTE",
        operatorAlphaLong = "Ooredoo", operatorAlphaShort = "Ooredoo",
        additionalPlmns = emptyList(), neighborCount = 4, servingRsrp = -95,
        isRegistered = true, capturedAt = 1000L, source = TelemetrySource.LIVE_SCAN,
        previousTac = 4099, previousRat = "LTE", tacChanged = true, ratChanged = false,
        tacChangesLast5m = 2, servingMinusMaxNeighborRsrpDb = 12,
        locationMovedMLast5m = 40,
    )

    @Test
    fun `toFieldMap emits every taxonomy key`() {
        val f = sample().toFieldMap()
        assertEquals("427", f["mcc"])
        assertEquals(4100, f["tac"])
        assertEquals(20000, f["bandwidth_khz"])
        assertEquals("LTE", f["rat"])
        assertEquals("Ooredoo", f["operator_alpha_long"])
        assertEquals(4, f["neighbor_count"])
        assertEquals(true, f["is_registered"])
        assertEquals("LIVE_SCAN", f["source"])
        assertEquals(4099, f["previous_tac"])
        assertEquals(true, f["tac_changed"])
        assertEquals(2, f["tac_changes_last_5m"])
        assertEquals(12, f["serving_minus_max_neighbor_rsrp_db"])
        assertEquals(40, f["location_moved_m_last_5m"])
        assertEquals(24, f.size)
    }

    @Test
    fun `null measurements survive into the field map`() {
        val f = sample().copy(locationMovedMLast5m = null, servingRsrp = null).toFieldMap()
        assertNull(f["location_moved_m_last_5m"])
        assertNull(f["serving_rsrp"])
    }
}
```

- [ ] **Step 2: Run it to verify it fails**

```bash
cd /home/yasir/AndroDR/.claude/worktrees/cellular-tier1
./gradlew testDebugUnitTest --tests '*CellularSnapshotTest*'
```
Expected: FAIL — `Unresolved reference: CellularSnapshot`.

- [ ] **Step 3: Create the model**

Create `app/src/main/java/com/androdr/data/model/CellularSnapshot.kt`:

```kotlin
package com.androdr.data.model

/**
 * Tier 1 radio telemetry. Emits ALL radio facts verbatim plus objective
 * derived measurements; it never decides what is suspicious — that is the
 * rules' job (spec §5).
 *
 * Integer fields are nullable because Android reports unavailable values as
 * Integer.MAX_VALUE; [CellularMonitor] normalizes those to null.
 */
data class CellularSnapshot(
    val mcc: String?,
    val mnc: String?,
    val tac: Int?,
    val ci: Long?,
    val pci: Int?,
    val earfcn: Int?,
    val bands: List<Int>,
    val bandwidthKhz: Int?,
    val rat: String,
    val operatorAlphaLong: String?,
    val operatorAlphaShort: String?,
    val additionalPlmns: List<String>,
    val neighborCount: Int,
    val servingRsrp: Int?,
    val isRegistered: Boolean,
    val capturedAt: Long,
    val source: TelemetrySource,
    val previousTac: Int?,
    val previousRat: String?,
    val tacChanged: Boolean,
    val ratChanged: Boolean,
    val tacChangesLast5m: Int,
    val servingMinusMaxNeighborRsrpDb: Int?,
    val locationMovedMLast5m: Int?,
) {
    fun toFieldMap(): Map<String, Any?> = mapOf(
        "mcc" to mcc,
        "mnc" to mnc,
        "tac" to tac,
        "ci" to ci,
        "pci" to pci,
        "earfcn" to earfcn,
        "bands" to bands,
        "bandwidth_khz" to bandwidthKhz,
        "rat" to rat,
        "operator_alpha_long" to operatorAlphaLong,
        "operator_alpha_short" to operatorAlphaShort,
        "additional_plmns" to additionalPlmns,
        "neighbor_count" to neighborCount,
        "serving_rsrp" to servingRsrp,
        "is_registered" to isRegistered,
        "captured_at" to capturedAt,
        "source" to source.name,
        "previous_tac" to previousTac,
        "previous_rat" to previousRat,
        "tac_changed" to tacChanged,
        "rat_changed" to ratChanged,
        "tac_changes_last_5m" to tacChangesLast5m,
        "serving_minus_max_neighbor_rsrp_db" to servingMinusMaxNeighborRsrpDb,
        "location_moved_m_last_5m" to locationMovedMLast5m,
    )
}
```

- [ ] **Step 4: Add the taxonomy service (rules-repo branch)**

In `third-party/android-sigma-rules/validation/logsource-taxonomy.yml`, add after the `tombstone_parser` block:

```yaml
  cellular_monitor:
    model_class: CellularSnapshot
    field_map: member
    status: active
    fields:
      mcc: { kind: raw_fact, type: string, nullable: true, description: "Mobile country code" }
      mnc: { kind: raw_fact, type: string, nullable: true, description: "Mobile network code" }
      tac: { kind: raw_fact, type: int, nullable: true, description: "Tracking area code; null when the platform reports Integer.MAX_VALUE" }
      ci: { kind: raw_fact, type: long, nullable: true, description: "Cell identity" }
      pci: { kind: raw_fact, type: int, nullable: true, description: "Physical cell ID" }
      earfcn: { kind: raw_fact, type: int, nullable: true, description: "Frequency channel number; emitted for future band-plan rules, unused in v1" }
      bands: { kind: raw_fact, type: list, description: "Reported band numbers" }
      bandwidth_khz: { kind: raw_fact, type: int, nullable: true, description: "Channel bandwidth in kHz" }
      rat: { kind: raw_fact, type: string, description: "Radio access technology (LTE, NR, UMTS, GSM, UNKNOWN)" }
      operator_alpha_long: { kind: raw_fact, type: string, nullable: true, description: "Network-reported long operator name. ATTACKER-CONTROLLED: a fake base station chooses this freely — never treat as trust" }
      operator_alpha_short: { kind: raw_fact, type: string, nullable: true, description: "Network-reported short operator name. ATTACKER-CONTROLLED" }
      additional_plmns: { kind: raw_fact, type: list, description: "Additional PLMN identifiers advertised by the cell" }
      neighbor_count: { kind: raw_fact, type: int, description: "Number of neighbour cells in the same report" }
      serving_rsrp: { kind: raw_fact, type: int, nullable: true, description: "Serving cell RSRP in dBm" }
      is_registered: { kind: raw_fact, type: boolean, description: "Device is registered on this cell" }
      captured_at: { kind: raw_fact, type: long, description: "When this snapshot was captured (epoch ms)" }
      source: { kind: raw_fact, type: string, description: "TelemetrySource enum name" }
      previous_tac: { kind: raw_fact, type: int, nullable: true, description: "TAC of the prior snapshot; null on first observation" }
      previous_rat: { kind: raw_fact, type: string, nullable: true, description: "RAT of the prior snapshot; null on first observation" }
      tac_changed: { kind: raw_fact, type: boolean, description: "TAC differs from the prior snapshot" }
      rat_changed: { kind: raw_fact, type: boolean, description: "RAT differs from the prior snapshot" }
      tac_changes_last_5m: { kind: raw_fact, type: int, description: "Objective count of TAC changes in the rolling 5-minute window" }
      serving_minus_max_neighbor_rsrp_db: { kind: raw_fact, type: int, nullable: true, description: "Serving RSRP minus strongest neighbour RSRP; null when no neighbours reported" }
      location_moved_m_last_5m: { kind: raw_fact, type: int, nullable: true, description: "Coarse network-provider displacement in metres over 5 minutes; null when unavailable" }
```

- [ ] **Step 5: Register the service in the cross-check test**

In `app/src/test/java/com/androdr/sigma/LogsourceTaxonomyCrossCheckTest.kt`, add the import and a map entry inside `memberFunctionFieldMaps()`:

```kotlin
import com.androdr.data.model.CellularSnapshot
```

```kotlin
        "cellular_monitor" to CellularSnapshot(
            mcc = null, mnc = null, tac = null, ci = null, pci = null,
            earfcn = null, bands = emptyList(), bandwidthKhz = null, rat = "UNKNOWN",
            operatorAlphaLong = null, operatorAlphaShort = null,
            additionalPlmns = emptyList(), neighborCount = 0, servingRsrp = null,
            isRegistered = false, capturedAt = 0L, source = TelemetrySource.LIVE_SCAN,
            previousTac = null, previousRat = null, tacChanged = false, ratChanged = false,
            tacChangesLast5m = 0, servingMinusMaxNeighborRsrpDb = null,
            locationMovedMLast5m = null,
        ).toFieldMap().keys,
```

- [ ] **Step 6: Run the cross-checks**

```bash
cd /home/yasir/AndroDR/.claude/worktrees/cellular-tier1
./gradlew testDebugUnitTest --tests '*CellularSnapshotTest*' --tests '*LogsourceTaxonomyCrossCheckTest*'
```
Expected: PASS both. If `taxonomy service count matches expected` fails, one of Steps 4/5 was missed — atomicity rule A.

- [ ] **Step 7: Commit both repos**

```bash
cd /home/yasir/AndroDR/.claude/worktrees/cellular-tier1/third-party/android-sigma-rules
git add validation/logsource-taxonomy.yml
git commit -m "feat: add cellular_monitor logsource service"
git push origin research/cellular-monitor

cd /home/yasir/AndroDR/.claude/worktrees/cellular-tier1
git add app/src/main/java/com/androdr/data/model/CellularSnapshot.kt \
        app/src/test/java/com/androdr/cellular/CellularSnapshotTest.kt \
        app/src/test/java/com/androdr/sigma/LogsourceTaxonomyCrossCheckTest.kt \
        third-party/android-sigma-rules
git commit -m "feat(cellular): add CellularSnapshot emitter contract + taxonomy"
git push origin research/cellular-tier1
```

---

### Task 3: Wire `evaluateCellular()` — proving it is not another `network_monitor`

**Files:**
- Modify: `app/src/main/java/com/androdr/sigma/SigmaRuleEngine.kt`
- Create: `app/src/test/java/com/androdr/cellular/CellularEvaluationTest.kt`

**Interfaces:**
- Consumes: `CellularSnapshot.toFieldMap()` from Task 2.
- Produces: `fun evaluateCellular(telemetry: List<CellularSnapshot>): List<Finding>` — Task 6 calls this.

- [ ] **Step 1: Write the failing test**

Create `app/src/test/java/com/androdr/cellular/CellularEvaluationTest.kt`:

```kotlin
package com.androdr.cellular

import com.androdr.sigma.SigmaRuleEvaluator
import com.androdr.sigma.SigmaRuleParser
import org.junit.Assert.assertTrue
import org.junit.Test

class CellularEvaluationTest {

    private val narrowBandwidthRule = """
        title: Implausibly narrow cell bandwidth
        id: androdr-101
        status: experimental
        description: Test
        category: incident
        logsource:
            product: androdr
            service: cellular_monitor
        detection:
            selection:
                is_registered: true
                bandwidth_khz:
                    - 1400
                    - 3000
            condition: selection
        level: low
    """.trimIndent()

    @Test
    fun `cellular_monitor rule fires on narrow bandwidth`() {
        val rule = SigmaRuleParser.parse(narrowBandwidthRule)!!
        val narrow = mapOf<String, Any?>("is_registered" to true, "bandwidth_khz" to 1400)
        val wide = mapOf<String, Any?>("is_registered" to true, "bandwidth_khz" to 20000)

        val hit = SigmaRuleEvaluator.evaluate(
            listOf(rule), listOf(narrow), "cellular_monitor", emptyMap(), emptyMap()
        )
        assertTrue("Should fire on 1.4 MHz", hit.any { it.triggered })

        val miss = SigmaRuleEvaluator.evaluate(
            listOf(rule), listOf(wide), "cellular_monitor", emptyMap(), emptyMap()
        )
        assertTrue("Should not fire on 20 MHz", miss.none { it.triggered })
    }
}
```

- [ ] **Step 2: Run it to verify it fails or passes for the wrong reason**

```bash
./gradlew testDebugUnitTest --tests '*CellularEvaluationTest*'
```
Note: this exercises the evaluator directly and may already pass — that is expected. It proves the service string works; Step 3 adds the engine entry point that production code needs.

- [ ] **Step 3: Add `evaluateCellular` to the engine**

In `app/src/main/java/com/androdr/sigma/SigmaRuleEngine.kt`, add the import `com.androdr.data.model.CellularSnapshot` and, next to `evaluateDns`:

```kotlin
    fun evaluateCellular(telemetry: List<CellularSnapshot>): List<Finding> {
        val records = telemetry.map { it.toFieldMap() }
        return SigmaRuleEvaluator.evaluate(
            effectiveRules(), records, "cellular_monitor", iocLookups, evidenceProviders
        )
    }
```

- [ ] **Step 4: Run the full suite**

```bash
./gradlew testDebugUnitTest
```
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add app/src/main/java/com/androdr/sigma/SigmaRuleEngine.kt \
        app/src/test/java/com/androdr/cellular/CellularEvaluationTest.kt
git commit -m "feat(cellular): wire evaluateCellular into SigmaRuleEngine"
git push origin research/cellular-tier1
```

---

### Task 4: `RadioStateStore` — objective derived measurements

**Files:**
- Create: `app/src/main/java/com/androdr/cellular/RadioStateStore.kt`
- Create: `app/src/test/java/com/androdr/cellular/RadioStateStoreTest.kt`

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces: `class RadioStateStore(private val windowMillis: Long = 300_000L)` with `fun record(tac: Int?, rat: String, atMillis: Long): Derived` and `data class Derived(val previousTac: Int?, val previousRat: String?, val tacChanged: Boolean, val ratChanged: Boolean, val tacChangesLast5m: Int)`. Task 6 uses both.

- [ ] **Step 1: Write the failing test**

Create `app/src/test/java/com/androdr/cellular/RadioStateStoreTest.kt`:

```kotlin
package com.androdr.cellular

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class RadioStateStoreTest {

    @Test
    fun `first observation has no previous values`() {
        val d = RadioStateStore().record(tac = 100, rat = "LTE", atMillis = 0L)
        assertNull(d.previousTac)
        assertNull(d.previousRat)
        assertFalse(d.tacChanged)
        assertEquals(0, d.tacChangesLast5m)
    }

    @Test
    fun `tac change is reported and counted`() {
        val store = RadioStateStore()
        store.record(100, "LTE", 0L)
        val d = store.record(101, "LTE", 1_000L)
        assertEquals(100, d.previousTac)
        assertTrue(d.tacChanged)
        assertEquals(1, d.tacChangesLast5m)
    }

    @Test
    fun `changes outside the window are dropped`() {
        val store = RadioStateStore(windowMillis = 300_000L)
        store.record(100, "LTE", 0L)
        store.record(101, "LTE", 1_000L)
        val d = store.record(102, "LTE", 400_000L)
        assertEquals(1, d.tacChangesLast5m)
    }

    @Test
    fun `rat downgrade is reported`() {
        val store = RadioStateStore()
        store.record(100, "LTE", 0L)
        val d = store.record(100, "GSM", 1_000L)
        assertEquals("LTE", d.previousRat)
        assertTrue(d.ratChanged)
        assertFalse(d.tacChanged)
    }
}
```

- [ ] **Step 2: Run to verify it fails**

```bash
./gradlew testDebugUnitTest --tests '*RadioStateStoreTest*'
```
Expected: FAIL — `Unresolved reference: RadioStateStore`.

- [ ] **Step 3: Implement**

Create `app/src/main/java/com/androdr/cellular/RadioStateStore.kt`:

```kotlin
package com.androdr.cellular

/**
 * Holds the previous radio observation and a rolling window of TAC-change
 * timestamps. Computes OBJECTIVE measurements only — "the value changed",
 * "it changed N times in T ms". It never decides what is suspicious; that
 * belongs to the rules (spec §5).
 */
class RadioStateStore(private val windowMillis: Long = DEFAULT_WINDOW_MILLIS) {

    data class Derived(
        val previousTac: Int?,
        val previousRat: String?,
        val tacChanged: Boolean,
        val ratChanged: Boolean,
        val tacChangesLast5m: Int,
    )

    private var lastTac: Int? = null
    private var lastRat: String? = null
    private var seenFirst = false
    private val tacChangeTimes = ArrayDeque<Long>()

    @Synchronized
    fun record(tac: Int?, rat: String, atMillis: Long): Derived {
        val prevTac = lastTac
        val prevRat = lastRat
        val tacChanged = seenFirst && tac != prevTac
        val ratChanged = seenFirst && rat != prevRat

        if (tacChanged) tacChangeTimes.addLast(atMillis)
        while (tacChangeTimes.isNotEmpty() && atMillis - tacChangeTimes.first() > windowMillis) {
            tacChangeTimes.removeFirst()
        }

        lastTac = tac
        lastRat = rat
        seenFirst = true

        return Derived(prevTac, prevRat, tacChanged, ratChanged, tacChangeTimes.size)
    }

    private companion object {
        const val DEFAULT_WINDOW_MILLIS = 300_000L
    }
}
```

- [ ] **Step 4: Run to verify it passes**

```bash
./gradlew testDebugUnitTest --tests '*RadioStateStoreTest*'
```
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add app/src/main/java/com/androdr/cellular/RadioStateStore.kt \
        app/src/test/java/com/androdr/cellular/RadioStateStoreTest.kt
git commit -m "feat(cellular): add RadioStateStore derived measurements"
git push origin research/cellular-tier1
```

---

### Task 5: Rules H2 + H4 (snapshot-only) — first end-to-end delivery

**Atomicity rule B applies — bundled YAML, `BUNDLED_RULE_IDS`, mirror, `rules.txt`, and `rules.sha256` land in ONE commit.**

**Skip H4 entirely if Task 1 Step 5 found `neighbor_count == 1` always.**

**Files:**
- Create: `app/src/main/res/raw/sigma_androdr_101_cell_narrow_bandwidth.yml`
- Create: `app/src/main/res/raw/sigma_androdr_102_cell_isolated.yml`
- Modify: `app/src/main/java/com/androdr/sigma/SigmaRuleEngine.kt` (`BUNDLED_RULE_IDS`)
- Create (rules branch): `third-party/android-sigma-rules/cellular_monitor/androdr_101_*.yml`, `..._102_*.yml`
- Modify (rules branch): `rules.txt`, `rules.sha256`

**Interfaces:**
- Consumes: the `cellular_monitor` service and field names from Task 2.
- Produces: two loadable bundled rules. No Kotlin interface.

- [ ] **Step 1: Write the H2 rule**

Create `app/src/main/res/raw/sigma_androdr_101_cell_narrow_bandwidth.yml`:

```yaml
title: Implausibly narrow cell bandwidth
id: androdr-101
status: experimental
description: >-
    The registered cell reports a 1.4 or 3 MHz channel. Software-defined fake
    base stations commonly transmit narrow; production macro cells normally run
    10, 15 or 20 MHz. Suggestive, not conclusive — narrow carriers do exist in
    legitimate deployments.
author: AndroDR
date: 2026/08/22
category: incident
logsource:
    product: androdr
    service: cellular_monitor
detection:
    selection:
        is_registered: true
        bandwidth_khz:
            - 1400
            - 3000
    condition: selection
level: low
tags:
    - attack.t1430
falsepositives:
    - Legitimate narrowband or rural LTE deployments
    - IoT/NB-IoT carriers
remediation:
    - "Note where and when this appeared. On its own it is weak evidence; corroborate with other cellular findings before acting."
```

- [ ] **Step 2: Write the H4 rule**

Create `app/src/main/res/raw/sigma_androdr_102_cell_isolated.yml`:

```yaml
title: Serving cell reports no neighbours
id: androdr-102
status: experimental
description: >-
    The device is registered to a cell that advertises no neighbour cells. Real
    macro cells almost always have neighbours; an isolated cell is characteristic
    of a standalone fake base station. Also occurs legitimately in rural areas and
    indoor small cells.
author: AndroDR
date: 2026/08/22
category: incident
logsource:
    product: androdr
    service: cellular_monitor
detection:
    selection:
        is_registered: true
        neighbor_count: 0
    condition: selection
level: low
tags:
    - attack.t1430
falsepositives:
    - Rural or isolated coverage
    - Indoor small cells and femtocells
remediation:
    - "Note where and when this appeared. Corroborate with other cellular findings before acting."
```

- [ ] **Step 3: Register both in the loader manifest**

In `SigmaRuleEngine.kt`, append to `BUNDLED_RULE_IDS`:

```kotlin
            R.raw.sigma_androdr_101_cell_narrow_bandwidth,
            R.raw.sigma_androdr_102_cell_isolated,
```

- [ ] **Step 4: Mirror byte-identically and register for delivery**

```bash
cd /home/yasir/AndroDR/.claude/worktrees/cellular-tier1
M=third-party/android-sigma-rules
mkdir -p $M/cellular_monitor
cp app/src/main/res/raw/sigma_androdr_101_cell_narrow_bandwidth.yml \
   $M/cellular_monitor/androdr_101_cell_narrow_bandwidth.yml
cp app/src/main/res/raw/sigma_androdr_102_cell_isolated.yml \
   $M/cellular_monitor/androdr_102_cell_isolated.yml
printf 'cellular_monitor/androdr_101_cell_narrow_bandwidth.yml\n' >> $M/rules.txt
printf 'cellular_monitor/androdr_102_cell_isolated.yml\n' >> $M/rules.txt
```

- [ ] **Step 5: Regenerate the manifest**

```bash
cd /home/yasir/AndroDR/.claude/worktrees/cellular-tier1/third-party/android-sigma-rules
while read -r f; do printf '%s  %s\n' "$(sha256sum "$f" | cut -d' ' -f1)" "$f"; done \
    < rules.txt > rules.sha256
```

- [ ] **Step 6: Run every gate this touches**

```bash
cd /home/yasir/AndroDR/.claude/worktrees/cellular-tier1
./gradlew testDebugUnitTest
```
Expected: PASS, specifically `BundledMirrorParityTest`, `BundledRulesManifestCompletenessTest`, `RuleManifestIntegrityTest`, `AllRulesHaveCategoryTest`, `DetectionFieldCrossCheckTest`, `BundledRulesSchemaCrossCheckTest`.

Common failures: `"missing from rules.txt (OTA-unreachable)"` → Step 4 skipped; `"differs from mirror"` → the copies are not byte-identical, re-run `cp`.

- [ ] **Step 7: Validate on the rules-repo side**

```bash
gh workflow run validate.yml --ref research/cellular-monitor --repo yasirhamza/android-sigma-rules
```

- [ ] **Step 8: Commit both repos**

```bash
cd /home/yasir/AndroDR/.claude/worktrees/cellular-tier1/third-party/android-sigma-rules
git add cellular_monitor rules.txt rules.sha256
git commit -m "feat: mirror cellular_monitor rules androdr-101/102"
git push origin research/cellular-monitor

cd /home/yasir/AndroDR/.claude/worktrees/cellular-tier1
git add app/src/main/res/raw app/src/main/java/com/androdr/sigma/SigmaRuleEngine.kt third-party/android-sigma-rules
git commit -m "feat(cellular): add snapshot rules androdr-101/102"
git push origin research/cellular-tier1
```

---

### Task 6: `CellularMonitor` — callback, mapping, permissions, service hook

**Files:**
- Create: `app/src/main/java/com/androdr/cellular/CellularMonitor.kt`
- Modify: `app/src/main/AndroidManifest.xml`
- Modify: `app/src/main/java/com/androdr/network/DnsVpnService.kt`

**Interfaces:**
- Consumes: `CellularSnapshot` (Task 2), `SigmaRuleEngine.evaluateCellular` (Task 3), `RadioStateStore.record` (Task 4).
- Produces: `class CellularMonitor` with `fun start()` and `fun stop()`.

- [ ] **Step 1: Declare permissions**

In `app/src/main/AndroidManifest.xml`, above `<application>`:

```xml
<!-- Research branch only — never merged to main (spec §3). -->
<uses-permission android:name="android.permission.ACCESS_FINE_LOCATION" />
<uses-permission android:name="android.permission.READ_PHONE_STATE" />
```

- [ ] **Step 2: Implement the monitor**

Create `app/src/main/java/com/androdr/cellular/CellularMonitor.kt`:

```kotlin
package com.androdr.cellular

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.telephony.CellInfo
import android.telephony.CellInfoGsm
import android.telephony.CellInfoLte
import android.telephony.CellInfoNr
import android.telephony.CellInfoWcdma
import android.telephony.TelephonyCallback
import android.telephony.TelephonyManager
import android.util.Log
import androidx.core.content.ContextCompat
import com.androdr.data.model.CellularSnapshot
import com.androdr.data.model.TelemetrySource
import com.androdr.sigma.SigmaRuleEngine

/**
 * Tier 1 radio telemetry (spec §4). Registers a TelephonyCallback inside the
 * DnsVpnService foreground context so cell/RAT transitions arrive as events
 * rather than polls. No-ops unless both permissions are granted.
 */
class CellularMonitor(
    private val context: Context,
    private val engine: SigmaRuleEngine,
    private val store: RadioStateStore = RadioStateStore(),
) {
    private var callback: TelephonyCallback? = null

    private fun hasPermissions(): Boolean =
        ContextCompat.checkSelfPermission(context, Manifest.permission.ACCESS_FINE_LOCATION) ==
            PackageManager.PERMISSION_GRANTED &&
            ContextCompat.checkSelfPermission(context, Manifest.permission.READ_PHONE_STATE) ==
            PackageManager.PERMISSION_GRANTED

    fun start() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) {
            Log.i(TAG, "TelephonyCallback needs API 31+; monitor inert")
            return
        }
        if (!hasPermissions()) {
            Log.i(TAG, "Cellular permissions not granted; monitor inert")
            return
        }
        val tm = context.getSystemService(TelephonyManager::class.java) ?: return
        val cb = object : TelephonyCallback(), TelephonyCallback.CellInfoListener {
            override fun onCellInfoChanged(cellInfo: MutableList<CellInfo>) {
                handle(cellInfo)
            }
        }
        callback = cb
        tm.registerTelephonyCallback(context.mainExecutor, cb)
        Log.i(TAG, "Cellular monitor started")
    }

    fun stop() {
        val cb = callback ?: return
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            context.getSystemService(TelephonyManager::class.java)?.unregisterTelephonyCallback(cb)
        }
        callback = null
    }

    internal fun handle(cellInfo: List<CellInfo>) {
        val serving = cellInfo.firstOrNull { it.isRegistered } ?: return
        val snapshot = toSnapshot(serving, cellInfo, System.currentTimeMillis())
        val findings = engine.evaluateCellular(listOf(snapshot))
        findings.filter { it.triggered }.forEach { Log.w(TAG, "Cellular finding: ${it.ruleId}") }
    }

    private fun sentinel(value: Int): Int? = if (value == Int.MAX_VALUE) null else value

    internal fun toSnapshot(serving: CellInfo, all: List<CellInfo>, now: Long): CellularSnapshot {
        val rat = when (serving) {
            is CellInfoNr -> "NR"
            is CellInfoLte -> "LTE"
            is CellInfoWcdma -> "UMTS"
            is CellInfoGsm -> "GSM"
            else -> "UNKNOWN"
        }
        val lte = serving as? CellInfoLte
        val id = lte?.cellIdentity
        val tac = id?.tac?.let { sentinel(it) }
        val derived = store.record(tac, rat, now)
        val servingRsrp = lte?.cellSignalStrength?.rsrp?.let { sentinel(it) }
        val neighbours = all.filter { !it.isRegistered }
        val maxNeighborRsrp = neighbours.filterIsInstance<CellInfoLte>()
            .mapNotNull { sentinel(it.cellSignalStrength.rsrp) }
            .maxOrNull()

        return CellularSnapshot(
            mcc = id?.mccString,
            mnc = id?.mncString,
            tac = tac,
            ci = id?.ci?.let { sentinel(it) }?.toLong(),
            pci = id?.pci?.let { sentinel(it) },
            earfcn = id?.earfcn?.let { sentinel(it) },
            bands = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R)
                id?.bands?.toList().orEmpty() else emptyList(),
            bandwidthKhz = id?.bandwidth?.let { sentinel(it) },
            rat = rat,
            operatorAlphaLong = id?.operatorAlphaLong?.toString(),
            operatorAlphaShort = id?.operatorAlphaShort?.toString(),
            additionalPlmns = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R)
                id?.additionalPlmns?.toList().orEmpty() else emptyList(),
            neighborCount = neighbours.size,
            servingRsrp = servingRsrp,
            isRegistered = true,
            capturedAt = now,
            source = TelemetrySource.LIVE_SCAN,
            previousTac = derived.previousTac,
            previousRat = derived.previousRat,
            tacChanged = derived.tacChanged,
            ratChanged = derived.ratChanged,
            tacChangesLast5m = derived.tacChangesLast5m,
            servingMinusMaxNeighborRsrpDb =
                if (servingRsrp != null && maxNeighborRsrp != null) servingRsrp - maxNeighborRsrp else null,
            locationMovedMLast5m = null,
        )
    }

    private companion object {
        const val TAG = "CellularMonitor"
    }
}
```

Note `locationMovedMLast5m` is `null` in v1. H1 (Task 7) handles absence explicitly, per spec §5.

- [ ] **Step 3: Hook into the VPN lifecycle**

In `app/src/main/java/com/androdr/network/DnsVpnService.kt`, add a field and calls:

```kotlin
    @Suppress("LateinitUsage") @Inject lateinit var sigmaRuleEngine: SigmaRuleEngine
    private var cellularMonitor: CellularMonitor? = null
```

At the end of `startVpn()`:

```kotlin
        cellularMonitor = CellularMonitor(applicationContext, sigmaRuleEngine).also { it.start() }
```

At the start of `stopVpn()`:

```kotlin
        cellularMonitor?.stop()
        cellularMonitor = null
```

- [ ] **Step 4: Build and lint**

```bash
cd /home/yasir/AndroDR/.claude/worktrees/cellular-tier1
./gradlew assembleDebug lintDebug testDebugUnitTest
```
Expected: PASS. If lint flags `MissingPermission`, confirm `hasPermissions()` guards the call path.

- [ ] **Step 5: Commit**

```bash
git add app/src/main/java/com/androdr/cellular/CellularMonitor.kt \
        app/src/main/AndroidManifest.xml \
        app/src/main/java/com/androdr/network/DnsVpnService.kt
git commit -m "feat(cellular): add CellularMonitor and hook into DnsVpnService"
git push origin research/cellular-tier1
```

---

### Task 7: Rules H6 + H1 (stateful) — the strongest heuristics

**Atomicity rule B applies.** Use the Task 1 measurement to set the H1 threshold; the value below is the starting point from spec §6.

**Files:**
- Create: `app/src/main/res/raw/sigma_androdr_103_cell_rat_downgrade.yml`
- Create: `app/src/main/res/raw/sigma_androdr_104_cell_tac_churn.yml`
- Modify: `SigmaRuleEngine.kt`, mirror, `rules.txt`, `rules.sha256`

**Interfaces:**
- Consumes: `previous_rat`, `tac_changes_last_5m`, `location_moved_m_last_5m` from Task 2.
- Produces: two loadable rules.

- [ ] **Step 1: Write the H6 rule**

Create `app/src/main/res/raw/sigma_androdr_103_cell_rat_downgrade.yml`:

```yaml
title: Cellular downgrade from LTE/NR to 2G/3G
id: androdr-103
status: experimental
description: >-
    The device moved from LTE or NR to GSM or UMTS. Forcing a downgrade to 2G,
    which lacks mutual authentication, is the classic IMSI-catcher manoeuvre.
    Legitimate downgrades happen at the edge of coverage.
author: AndroDR
date: 2026/08/22
category: incident
logsource:
    product: androdr
    service: cellular_monitor
detection:
    selection:
        previous_rat:
            - LTE
            - NR
        rat:
            - GSM
            - UMTS
    condition: selection
level: medium
tags:
    - attack.t1430
falsepositives:
    - Genuine loss of LTE/NR coverage
    - Rural roaming
remediation:
    - "Enable Advanced Protection (Android 16+) or your device's '2G off' setting, which removes this attack surface entirely."
    - "If this repeats in a fixed location with good coverage, treat it as suspicious."
```

- [ ] **Step 2: Write the H1 rule**

Create `app/src/main/res/raw/sigma_androdr_104_cell_tac_churn.yml`:

```yaml
title: Tracking area churn without movement
id: androdr-104
status: experimental
description: >-
    Three or more tracking-area changes within five minutes. A fake cell changes
    tracking area to force a Tracking Area Update, and that update is the
    mechanism by which the IMSI or TMSI is harvested. The strongest Tier 1
    signal. Fires regardless of whether displacement data is available.
author: AndroDR
date: 2026/08/22
category: incident
logsource:
    product: androdr
    service: cellular_monitor
detection:
    selection:
        is_registered: true
        tac_changes_last_5m|gte: 3
    condition: selection
level: medium
tags:
    - attack.t1430
falsepositives:
    - Travelling at speed across tracking-area boundaries
    - Dense urban areas with overlapping operators
remediation:
    - "Note the location and time. Repeated churn while stationary is the strongest Tier 1 indicator of a fake base station."
```

**Note:** `location_moved_m_last_5m` is not referenced, because Task 6 always emits it as `null` in v1 and `DetectionFieldCrossCheckTest` plus the fleet-safety discipline make a negated filter on an always-null field a hazard. The movement clause from spec §6 is deferred until the field carries real data.

- [ ] **Step 3: Register, mirror, deliver, regenerate**

```bash
cd /home/yasir/AndroDR/.claude/worktrees/cellular-tier1
M=third-party/android-sigma-rules
cp app/src/main/res/raw/sigma_androdr_103_cell_rat_downgrade.yml $M/cellular_monitor/androdr_103_cell_rat_downgrade.yml
cp app/src/main/res/raw/sigma_androdr_104_cell_tac_churn.yml     $M/cellular_monitor/androdr_104_cell_tac_churn.yml
printf 'cellular_monitor/androdr_103_cell_rat_downgrade.yml\n' >> $M/rules.txt
printf 'cellular_monitor/androdr_104_cell_tac_churn.yml\n'     >> $M/rules.txt
cd $M && while read -r f; do printf '%s  %s\n' "$(sha256sum "$f" | cut -d' ' -f1)" "$f"; done < rules.txt > rules.sha256
```

Also append to `BUNDLED_RULE_IDS` in `SigmaRuleEngine.kt`:

```kotlin
            R.raw.sigma_androdr_103_cell_rat_downgrade,
            R.raw.sigma_androdr_104_cell_tac_churn,
```

- [ ] **Step 4: Verify `gte` is a supported modifier**

```bash
cd /home/yasir/AndroDR/.claude/worktrees/cellular-tier1
grep -n "gte\|gt\b\|lte\|numeric" app/src/main/java/com/androdr/sigma/SigmaRuleEvaluator.kt | head
```
If `gte` is **not** supported, replace the H1 selection with an explicit enumeration and record the change:

```yaml
        tac_changes_last_5m:
            - 3
            - 4
            - 5
            - 6
```

- [ ] **Step 5: Run all gates**

```bash
./gradlew testDebugUnitTest
```
Expected: PASS.

- [ ] **Step 6: Commit both repos**

```bash
cd /home/yasir/AndroDR/.claude/worktrees/cellular-tier1/third-party/android-sigma-rules
git add cellular_monitor rules.txt rules.sha256
git commit -m "feat: mirror cellular_monitor rules androdr-103/104"
git push origin research/cellular-monitor
cd /home/yasir/AndroDR/.claude/worktrees/cellular-tier1
git add app/src/main/res/raw app/src/main/java/com/androdr/sigma/SigmaRuleEngine.kt third-party/android-sigma-rules
git commit -m "feat(cellular): add stateful rules androdr-103/104"
git push origin research/cellular-tier1
```

---

### Task 8: Rule H7 — operator-name mismatch, per travelled operator

**Atomicity rule B applies.** One rule per operator, so no reference dataset is needed and no judgment leaks into the emitter (spec §6).

**Files:**
- Create: `app/src/main/res/raw/sigma_androdr_105_cell_operator_mismatch_qa.yml`
- Modify: `SigmaRuleEngine.kt`, mirror, `rules.txt`, `rules.sha256`

**Interfaces:**
- Consumes: `mcc`, `mnc`, `operator_alpha_long` from Task 2.
- Produces: one loadable rule.

- [ ] **Step 1: Confirm the real MCC/MNC and operator string**

```bash
adb shell dumpsys telephony.registry | grep -iE "mOperatorAlphaLong|mMcc|mMnc" | head
```
Use the **observed** values; do not assume. Qatar is MCC 427 (Ooredoo `01`, Vodafone `02`), but the exact `operatorAlphaLong` string must be copied verbatim from the device.

- [ ] **Step 2: Write the rule**

Create `app/src/main/res/raw/sigma_androdr_105_cell_operator_mismatch_qa.yml`, substituting the observed name:

```yaml
title: Operator name inconsistent with PLMN (Qatar)
id: androdr-105
status: experimental
description: >-
    The cell advertises Qatar MCC 427 with Ooredoo's MNC but broadcasts a
    different operator name. The name is attacker-controlled and freely chosen,
    so a mismatch against the PLMN that actually identifies the operator is a
    cheap inconsistency check.
author: AndroDR
date: 2026/08/22
category: incident
logsource:
    product: androdr
    service: cellular_monitor
detection:
    selection:
        mcc: '427'
        mnc: '01'
    filter_expected:
        operator_alpha_long: 'Ooredoo'
    condition: selection and not filter_expected
level: low
tags:
    - attack.t1430
falsepositives:
    - MVNOs reusing the host network PLMN
    - Roaming partners presenting their own branding
remediation:
    - "Confirm the operator name shown in Settings matches your carrier."
```

- [ ] **Step 3: Register, mirror, deliver, regenerate**

```bash
cd /home/yasir/AndroDR/.claude/worktrees/cellular-tier1
M=third-party/android-sigma-rules
cp app/src/main/res/raw/sigma_androdr_105_cell_operator_mismatch_qa.yml \
   $M/cellular_monitor/androdr_105_cell_operator_mismatch_qa.yml
printf 'cellular_monitor/androdr_105_cell_operator_mismatch_qa.yml\n' >> $M/rules.txt
cd $M && while read -r f; do printf '%s  %s\n' "$(sha256sum "$f" | cut -d' ' -f1)" "$f"; done < rules.txt > rules.sha256
```

Append to `BUNDLED_RULE_IDS`:

```kotlin
            R.raw.sigma_androdr_105_cell_operator_mismatch_qa,
```

- [ ] **Step 4: Run all gates**

```bash
./gradlew testDebugUnitTest lintDebug
```
Expected: PASS.

- [ ] **Step 5: Commit both repos**

```bash
cd /home/yasir/AndroDR/.claude/worktrees/cellular-tier1/third-party/android-sigma-rules
git add cellular_monitor rules.txt rules.sha256
git commit -m "feat: mirror cellular_monitor rule androdr-105"
git push origin research/cellular-monitor
cd /home/yasir/AndroDR/.claude/worktrees/cellular-tier1
git add app/src/main/res/raw app/src/main/java/com/androdr/sigma/SigmaRuleEngine.kt third-party/android-sigma-rules
git commit -m "feat(cellular): add operator-mismatch rule androdr-105"
git push origin research/cellular-tier1
```

---

### Task 9: Field-readiness check

**Files:**
- Modify: `docs/plans/2026-08-22-cellular-telemetry-tier1-spec.md` (record measured values)

**Interfaces:**
- Consumes: everything above.
- Produces: a deployable research build and a recorded baseline.

- [ ] **Step 1: Full local verification from the worktree**

```bash
cd /home/yasir/AndroDR/.claude/worktrees/cellular-tier1
./gradlew testDebugUnitTest lintDebug assembleDebug
```
Expected: PASS. Confirm the shell prompt path is the worktree, not `/home/yasir/AndroDR`.

- [ ] **Step 2: Confirm CI state matches the documented expectation**

```bash
gh pr checks
```
Expected: `build-and-test` green, `lint-and-detekt` green, `submodule-check` **red (expected)**, `ci-success` **red (expected)**. Read `instrumented` explicitly — it is `continue-on-error` and will not fail the run.

- [ ] **Step 3: Install and confirm the monitor arms**

```bash
./gradlew installDebug
adb logcat -s CellularMonitor
```
Expected: `Cellular monitor started` after granting location and starting the VPN. If it logs `monitor inert`, the permission was not granted.

- [ ] **Step 4: Record a stationary baseline**

Leave it running stationary for 30 minutes. Record how many findings fire with no attack present — this is the false-positive floor, and the number that Task 7's threshold must be tuned against.

- [ ] **Step 5: Write measured values into the spec**

Replace the "starting points to be tuned" language in spec §6 with the observed values, and fill in §10 with the Task 1 measurements. Commit to the research branch.

```bash
git add docs/plans/2026-08-22-cellular-telemetry-tier1-spec.md
git commit -m "docs(cellular): record measured field baseline"
git push origin research/cellular-tier1
```

---

## Self-Review

**Spec coverage.** §1 goal → Tasks 2–8. §2 evidence → Task 1 verifies it app-side. §3 worktree → Task 0. §4 architecture → Tasks 4 and 6. §5 emitter contract → Task 2 (all 24 fields). §6 five rules → Tasks 5, 7, 8. §7 wiring → Task 3. §8 permissions/severity → Task 6 Step 1, and every rule is `level: low`/`medium`. §9 taxonomy/mirror → Tasks 2, 5, 7, 8 under atomicity rules A and B. §9a CI → Task 0 Steps 4–5, Task 9 Step 2. §10 spike → Task 1. §11 is recorded-not-scoped, correctly absent. §12 open questions: rebase cadence and emulator limits stay open by design.

**Known deviations from the spec, both deliberate and flagged in place:**
1. Integer fields are **nullable** and `Integer.MAX_VALUE` is normalized to `null` (Task 2). The spec's §5 table did not mark them nullable; this is more correct and consistent with §10 spike item 1.
2. **H1 drops the `location_moved_m_last_5m` clause** (Task 7 Step 2), because v1 always emits that field as `null`. Spec §6 wanted `< 100 OR absent`; with the field always absent the clause is inert, and referencing an always-null field in a negated filter is a hazard. Deferred until the field carries data.

**Placeholder scan.** No TBD/TODO. Every code step carries real code. Task 1 is explicitly a measurement task whose outputs feed named later steps.

**Type consistency.** `CellularSnapshot` constructor parameters are identical in Tasks 2, 6 and the cross-check registration. `RadioStateStore.record(tac, rat, atMillis)` returns `Derived`, consumed with matching property names in Task 6. Field-map keys in Task 2 match every rule's `detection:` keys in Tasks 5, 7, 8.

**Unverified assumption flagged for the executor.** Task 7 Step 4 explicitly checks whether the `|gte` modifier exists before relying on it, and gives the fallback. This is the one place the plan could not confirm support from the existing rule corpus.
