# Fix #267 via Phased Pure-Emitter Migration of Installer Trust — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. **Only Phase 1 is task-level in this document** — Phases 1b/2/3 are a tracked roadmap and get their own plans when picked up.

**Goal:** Stop `from_trusted_store` from being forgeable via an attacker-chosen installer package name (#267), and do it as the first step of a phased migration toward the pure-emitter contract (#136) — introduce the rule-consumable trust path while keeping the legacy computed booleans running in parallel, then retire the booleans once the new path is stable.

**Architecture:** Trust currently leaks through `OemPrefixResolver.isTrustedInstaller`, which trusts any installer whose package name *starts with* an OEM prefix — and `com.google.`/`com.android.`/`android.` are unconditional, so `com.google.play.svcupdate` forges store trust on every device. Phase 1 removes that inference: trust becomes exact membership in the curated `trusted_installers` list, and the same resolution is exposed to rules as a device-aware `trusted_installer_db` `ioc_lookup`. The three legacy judgment booleans (`from_trusted_store`, `is_sideloaded`, `is_known_oem_app`) keep being emitted, now computed from the non-forgeable membership, so nothing downstream breaks. Later phases move the OEM stores into device-conditional data (1b), migrate rules onto the lookup (2), and delete the booleans (3).

**Tech Stack:** Kotlin, JUnit4 + MockK (JVM unit tests), Android SDK 34 / JDK 21, Gradle. On-device verification against the attached Samsung Fold 2 (`SM_F916B`, package `com.androdr.debug`).

## Global Constraints

- **JDK 21** for every gradle/adb command. Export first:
  `export JAVA_HOME=/home/yasir/Applications/android-studio/jbr`
  `export ANDROID_HOME=/home/yasir/Android/Sdk`
  `export PATH="$JAVA_HOME/bin:$ANDROID_HOME/platform-tools:$ANDROID_HOME/emulator:$PATH"`
- **No new dependencies**; builds fully offline.
- **Detekt / Android Lint stay clean** (`lintDebug`, warnings-as-errors in release). No unused parameters left behind, no `@Suppress` to paper one over.
- **Phase 1 is AndroDR-Kotlin-only:** no `res/raw` YAML change, no taxonomy change, no submodule bump, no rules-repo PR — therefore **no safe-ordering protocol and no `rules.sha256` regen**. (This is exactly why the device-conditional data restructure is deferred to Phase 1b, which *does* need all of that.)
- **All changes via a PR targeting `main`** from `fix/267-trusted-installer-forgeable`; never push to `main` directly. CI `build` must pass. PR body includes `Closes #267`.
- **Commit trailers** on every commit:
  `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`
  `Claude-Session: https://claude.ai/code/session_01JD52ChA3BtfEYtVi2Uz61H`

## Review scope (proportionality)

Phase 1 is small and self-contained but security-sensitive (it changes the trust anchor feeding 10 rules). Skip the full 4-agent ceremony; run a **code-security** review and a **correctness** review of the diff, plus the on-device baseline/proof in Tasks 1 and 7 as the authoritative gate. Planning-time device sweep already established the false-positive surface (Fold 2: all third-party apps Play- or adb-installed, none prefix-trusted).

## What Phase 1 deliberately does NOT close

The **exact-name cross-device** forgery: naming an installer `com.sec.android.app.samsungapps` on a non-Samsung device still confers trust, because Phase 1's list is flat/unconditional. Closing that needs the device-conditional data restructure in **Phase 1b** (deferred for the 12h-fetch deployment reason below). Phase 1 closes the *prefix* forgery — the literal subject of #267's title. File the exact-name residual as a new issue when Phase 1 merges; do **not** leave #267 half-closed silently.

---

# Phase 1 — De-forge + stand up the pure-emitter path (this PR)

## File structure

- **Modify** `app/src/main/java/com/androdr/ioc/OemPrefixResolver.kt` — remove the `isOemPrefix` disjunct from `isTrustedInstaller`; drop the now-unused `device` parameter from that method; rewrite its KDoc.
- **Modify** `app/src/main/java/com/androdr/scanner/AppScanner.kt:245-246` — update the single call site.
- **Modify** `app/src/main/java/com/androdr/scanner/ScanOrchestrator.kt:164-179` — register the `trusted_installer_db` lookup in the `setIocLookups` map (device-aware closure, captures the existing `localDevice`).
- **Test** `app/src/test/java/com/androdr/ioc/OemPrefixResolverTest.kt` — flip prefix-installer-trust to distrust; add #267 prefix-forgery regressions.
- **Test** `app/src/test/java/com/androdr/scanner/AppScannerTelemetryTest.kt` — end-to-end: forged OEM-prefixed installer stays sideloaded.
- **Test** `app/src/test/java/com/androdr/sigma/SigmaRuleEvaluatorTest.kt` — prove a rule using `installer|ioc_lookup: trusted_installer_db` evaluates correctly (the Phase 2 migration target works today).
- **Modify** `app/src/test/java/com/androdr/sigma/FixtureClassificationCrossCheckTest.kt:36-39` — refresh the #267 "forgeable" KDoc note.

## Task 1: On-device baseline — prove the prefix forgery is live on the Fold 2

Captures the *before* state using the currently-installed (pre-fix) app. `adb install -i <installer>` sets the installer package name, reproducing the exact attack with no interactive tap. Verification only; deliverable is the recorded classification.

**Files:** none. Fixture: `test-adversary/fixtures/mercenary/surveillance-permissions.apk`.

- [ ] **Step 1: Confirm device + pre-fix app present**

```bash
export JAVA_HOME=/home/yasir/Applications/android-studio/jbr
export ANDROID_HOME=/home/yasir/Android/Sdk
export PATH="$JAVA_HOME/bin:$ANDROID_HOME/platform-tools:$ANDROID_HOME/emulator:$PATH"
adb devices -l                                        # expect SM_F916B ... device
adb shell pm list packages | grep com.androdr.debug   # else: ./gradlew installDebug (installs current, pre-fix code)
```

- [ ] **Step 2: Install the fixture with a forged OEM-prefixed installer**

```bash
adb install -r -i com.google.play.svcupdate \
  /home/yasir/AndroDR/test-adversary/fixtures/mercenary/surveillance-permissions.apk
adb shell dumpsys package com.androdr.test.surveillance 2>/dev/null | grep -i installerPackageName
```
Expected: `installerPackageName=com.google.play.svcupdate`. (If the fixture's applicationId differs, read it from `adb shell pm list packages -3 | grep -i surveil`.)

- [ ] **Step 3: Scan and read the on-device classification (pull all 3 DB files — WAL matters)**

Launch the app, tap **Run Scan** (or `adb shell am start -n com.androdr.debug/com.androdr.MainActivity`), then:

```bash
SCR=/tmp/claude-1000/-home-yasir-AndroDR/4eca4b99-5697-4eee-95e7-5bbde5d4b215/scratchpad
for ext in "" "-wal" "-shm"; do
  adb exec-out run-as com.androdr.debug cat \
    "/data/data/com.androdr.debug/databases/androdr.db$ext" > "$SCR/androdr.db$ext"
done
sqlite3 "$SCR/androdr.db" \
  "SELECT findings FROM ScanResult ORDER BY timestamp DESC LIMIT 1;" | python3 -m json.tool | grep -iE "ruleId|packageName|surveil"
```
Expected (pre-fix bug): the surveillance fixture does **NOT** trigger the sideload-gated rules — the forged installer set `from_trusted_store = true` → `is_sideloaded = false`. Record verbatim in `$SCR/267-baseline.txt` for the PR body.

## Task 2: De-forge `isTrustedInstaller` (TDD)

**Interfaces:**
- Produces: `OemPrefixResolver.isTrustedInstaller(installer: String): Boolean` — true iff `installer` is an exact member of the parsed `trusted_installers` set. The `device: DeviceIdentity` parameter is **removed** (Phase 1 trust is device-independent; Phase 1b re-introduces device-conditionality via data, not via this signature).
- Consumes: `AppScanner.collectTelemetry` passes the non-null `installerPackage`.

- [ ] **Step 1: Rewrite the resolver tests to pin the new contract**

In `OemPrefixResolverTest.kt`, replace the three installer tests (`bundled installers are trusted`, `OEM-prefix installers are trusted on matching device`, `unknown installers are not trusted`) with (note the dropped `device` arg):

```kotlin
    @Test
    fun `bundled store installers are trusted`() {
        assertTrue(resolver.isTrustedInstaller("com.android.vending"))
        assertTrue(resolver.isTrustedInstaller("com.sec.android.app.samsungapps"))
        assertTrue(resolver.isTrustedInstaller("com.xiaomi.market"))
        assertTrue(resolver.isTrustedInstaller("com.huawei.appmarket"))
    }

    @Test
    fun `OEM-prefixed non-store installers are NOT trusted (#267)`() {
        // Pre-#267 these passed via the isOemPrefix disjunct. An installer name is
        // attacker-influenced, so prefix-based trust was forgeable; trust now rests
        // only on the explicit trusted_installers store list.
        assertFalse(resolver.isTrustedInstaller("com.samsung.android.app.omcagent"))
        assertFalse(resolver.isTrustedInstaller("com.tmobile.pr.adapt"))
    }

    @Test
    fun `forged store-looking installer names are not trusted (#267)`() {
        assertFalse(resolver.isTrustedInstaller("com.google.play.svcupdate"))
        assertFalse(resolver.isTrustedInstaller("com.android.fakestore"))
        assertFalse(resolver.isTrustedInstaller("android.evil.installer"))
        // The system installer UI used for user-driven sideloads must NOT read as a
        // store (matches the timeline path's [SIDELOADED] labeling).
        assertFalse(resolver.isTrustedInstaller("com.google.android.packageinstaller"))
        assertFalse(resolver.isTrustedInstaller("com.android.packageinstaller"))
    }

    @Test
    fun `unknown installers are not trusted`() {
        assertFalse(resolver.isTrustedInstaller("com.unknown.installer"))
    }
```

- [ ] **Step 2: Run — expect failure**

```bash
./gradlew :app:testDebugUnitTest --tests "com.androdr.ioc.OemPrefixResolverTest"
```
Expected: FAIL (signature mismatch + the forged-name assertions fail against the current prefix logic).

- [ ] **Step 3: Apply the fix in `OemPrefixResolver.kt`** — replace lines 72-81 (KDoc + method):

```kotlin
    /**
     * Returns true iff [installer] is an explicitly trusted app-store package
     * name (exact membership in the parsed `trusted_installers` list).
     *
     * Trust is deliberately NOT inferred from OEM package prefixes. An installer
     * package name is attacker-influenced — a dropper sets its own
     * `installingPackageName`, and the system installer UI surfaces via the
     * `initiatingPackageName` fallback in AppScanner — so a prefix like
     * `com.google.` could be forged (`com.google.play.svcupdate`) to fake store
     * trust. Genuine stores are all enumerated in `trusted_installers`. See #267.
     *
     * Phase 1b (#136) will make membership device-conditional (an OEM store is
     * trusted only on its own ecosystem) by moving the OEM stores into the
     * per-vendor conditional blocks; that is a data change, not a signature change.
     */
    fun isTrustedInstaller(installer: String): Boolean =
        installer in data.get().trustedInstallers
```

- [ ] **Step 4: Update the call site in `AppScanner.kt:245-246`**

```kotlin
        val fromTrustedStore = installerPackage != null &&
            oemPrefixResolver.isTrustedInstaller(installerPackage)
```

- [ ] **Step 5: Run — expect pass**

```bash
./gradlew :app:testDebugUnitTest --tests "com.androdr.ioc.OemPrefixResolverTest"
```
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add app/src/main/java/com/androdr/ioc/OemPrefixResolver.kt \
        app/src/main/java/com/androdr/scanner/AppScanner.kt \
        app/src/test/java/com/androdr/ioc/OemPrefixResolverTest.kt
git commit -m "fix(ioc): from_trusted_store rests only on explicit store list (#267)

Remove the isOemPrefix disjunct from isTrustedInstaller so an
attacker-chosen installer name (com.google.play.svcupdate) can no longer
forge store trust. Drop the now-unused device parameter."
```

## Task 3: End-to-end regression in `AppScanner`

**Files:** `app/src/test/java/com/androdr/scanner/AppScannerTelemetryTest.kt`

- [ ] **Step 1: Add the regression** (after the existing sideloaded/Play tests, ~line 152):

```kotlin
    @Test
    fun `non-system app with forged OEM-prefixed installer is sideloaded, not trusted (#267)`() = runTest {
        val pkg = buildPackageInfo(
            pkgName = "com.evil.stage2",
            installerPkg = "com.google.play.svcupdate"  // OEM-prefix-shaped, not a real store
        )
        installPackages(pkg)

        val result = scanner.collectTelemetry()

        assertEquals(1, result.size)
        val telemetry = result[0]
        assertFalse("forged installer must not confer store trust", telemetry.fromTrustedStore)
        assertTrue("app must remain sideloaded", telemetry.isSideloaded)
    }
```

- [ ] **Step 2: Run + confirm it guards the fix**

```bash
./gradlew :app:testDebugUnitTest --tests "com.androdr.scanner.AppScannerTelemetryTest"
```
Expected: PASS. Sanity: `git stash` the Task 2 change → rerun → FAIL → `git stash pop`.

- [ ] **Step 3: Commit**

```bash
git add app/src/test/java/com/androdr/scanner/AppScannerTelemetryTest.kt
git commit -m "test(scanner): forged OEM-prefixed installer stays sideloaded (#267)"
```

## Task 4: Stand up the pure-emitter path — `trusted_installer_db` lookup

Introduces the rule-consumable trust path that Phase 2 rules will adopt, running in parallel with the legacy `from_trusted_store` boolean. The closure is device-aware from day one (captures the existing `localDevice`) so Phase 1b fills in device-conditional data with **no** lookup/rule signature change. Backed by the same `isTrustedInstaller` membership, so the two surfaces can never disagree.

**Interfaces:**
- Consumes: `OemPrefixResolver.isTrustedInstaller(installer: String)` from Task 2.
- Produces: an `ioc_lookup` named `trusted_installer_db` in the engine's lookup map; a rule matcher `installer|ioc_lookup: trusted_installer_db` returns true iff the installer is a trusted store.

- [ ] **Step 1: Register the lookup in `ScanOrchestrator.initRuleEngine`**

In the `setIocLookups(mapOf(...))` block (after the `known_good_app_db` entry, ~line 178), add:

```kotlin
            // Pure-emitter trust path (#267 / #136). Rules migrate off the computed
            // `from_trusted_store` boolean onto this lookup in Phase 2; both are backed
            // by the same resolver so they cannot diverge. `localDevice` is captured for
            // Phase 1b, when membership becomes device-conditional (data-only change).
            "trusted_installer_db" to { v ->
                val installer = v?.toString()
                installer != null && oemPrefixResolver.isTrustedInstaller(installer)
            }
```
(The `localDevice` capture becomes load-bearing in 1b; in Phase 1 the resolver ignores it. Keep the comment so the unused-capture is intentional, not accidental.)

- [ ] **Step 2: Write a rule-evaluator test for the new lookup**

In `SigmaRuleEvaluatorTest.kt`, follow the file's existing pattern for building an engine with custom `ioc_lookups` and an inline rule. Add:

```kotlin
    @Test
    fun `trusted_installer_db lookup matches only enumerated stores (#267 pure-emitter path)`() {
        // Inline rule keyed on the new lookup — the Phase 2 migration target.
        val ruleYaml = """
            title: test trusted installer lookup
            id: test-trusted-installer
            logsource: { product: android, service: app_scanner }
            detection:
              store: { installer|ioc_lookup: trusted_installer_db }
              condition: store
            level: informational
        """.trimIndent()
        // Wire the same lookup the orchestrator registers.
        val engine = buildEngineWithLookups(
            ruleYaml,
            mapOf("trusted_installer_db" to { v: Any? ->
                v?.toString() in setOf("com.android.vending", "com.sec.android.app.samsungapps")
            })
        )
        assertTrue(engine.matches(fieldMapOf("installer" to "com.android.vending")))
        assertFalse(engine.matches(fieldMapOf("installer" to "com.google.play.svcupdate")))
        assertFalse(engine.matches(fieldMapOf("installer" to null)))
    }
```
(Adapt `buildEngineWithLookups` / `fieldMapOf` / `engine.matches` to the actual helpers in the test file — read the surrounding tests first; do not invent APIs. The point asserted is fixed: the lookup matches enumerated stores and rejects forged names and null.)

- [ ] **Step 3: Run both the new test and the orchestrator/engine suite**

```bash
./gradlew :app:testDebugUnitTest --tests "com.androdr.sigma.SigmaRuleEvaluatorTest"
```
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add app/src/main/java/com/androdr/scanner/ScanOrchestrator.kt \
        app/src/test/java/com/androdr/sigma/SigmaRuleEvaluatorTest.kt
git commit -m "feat(rules): add device-aware trusted_installer_db lookup (parallel path, #267/#136)"
```

## Task 5: Refresh the #267 doc note

**Files:** `app/src/test/java/com/androdr/sigma/FixtureClassificationCrossCheckTest.kt:36-39`

- [ ] **Step 1: Replace the paragraph** that calls `isTrustedInstaller` "forgeable, #267" with:

```kotlin
 * `from_trusted_store` / `is_sideloaded` remain OUT OF SCOPE here: they depend on
 * installer/system inputs the fixtures don't carry (6 fixture files / 33 records set
 * them verbatim). #267 (Phase 1) hardened `isTrustedInstaller` to exact store-list
 * membership — no longer forgeable by prefix — but this cross-check still cannot
 * compute those fields from package name alone. Extending it needs fixture-carried
 * installer inputs; see the #136 pure-emitter migration.
```

- [ ] **Step 2: Verify + commit**

```bash
./gradlew :app:testDebugUnitTest --tests "com.androdr.sigma.FixtureClassificationCrossCheckTest"
git add app/src/test/java/com/androdr/sigma/FixtureClassificationCrossCheckTest.kt
git commit -m "docs(test): note #267 Phase 1 resolves the prefix-forgeable caveat"
```

## Task 6: Full unit suite + lint

- [ ] **Step 1: Full debug unit suite**

```bash
export JAVA_HOME=/home/yasir/Applications/android-studio/jbr
export ANDROID_HOME=/home/yasir/Android/Sdk
export PATH="$JAVA_HOME/bin:$ANDROID_HOME/platform-tools:$ANDROID_HOME/emulator:$PATH"
./gradlew testDebugUnitTest
```
Expected: BUILD SUCCESSFUL, zero failures. (Grep confirmed only `OemPrefixResolverTest` called the old two-arg `isTrustedInstaller`.)

- [ ] **Step 2: Lint**

```bash
./gradlew lintDebug
```
Expected: no new warnings/errors — in particular no "unused parameter" (the `device` arg was removed, not suppressed).

## Task 7: On-device proof of the fix

- [ ] **Step 1: Rebuild + reinstall the fixed app**

```bash
export JAVA_HOME=/home/yasir/Applications/android-studio/jbr
export ANDROID_HOME=/home/yasir/Android/Sdk
export PATH="$JAVA_HOME/bin:$ANDROID_HOME/platform-tools:$ANDROID_HOME/emulator:$PATH"
./gradlew installDebug
```

- [ ] **Step 2: Reinstall the forged-installer fixture, rescan, read the DB**

```bash
adb install -r -i com.google.play.svcupdate \
  /home/yasir/AndroDR/test-adversary/fixtures/mercenary/surveillance-permissions.apk
adb shell am start -n com.androdr.debug/com.androdr.MainActivity
# tap Run Scan, then:
SCR=/tmp/claude-1000/-home-yasir-AndroDR/4eca4b99-5697-4eee-95e7-5bbde5d4b215/scratchpad
for ext in "" "-wal" "-shm"; do
  adb exec-out run-as com.androdr.debug cat \
    "/data/data/com.androdr.debug/databases/androdr.db$ext" > "$SCR/androdr.db$ext"
done
sqlite3 "$SCR/androdr.db" \
  "SELECT findings FROM ScanResult ORDER BY timestamp DESC LIMIT 1;" | python3 -m json.tool | grep -iE "ruleId|packageName|surveil"
```
Expected (post-fix): the surveillance fixture now triggers the sideload-gated rule(s) that were silent in Task 1 — `from_trusted_store = false` → `is_sideloaded = true`. Record the before/after diff for the PR body.

- [ ] **Step 3: Clean up**

```bash
adb uninstall com.androdr.test.surveillance 2>/dev/null || true
```

## Task 8: PR + follow-ups

- [ ] **Step 1: Push + open the PR**

```bash
git push -u origin fix/267-trusted-installer-forgeable
gh pr create --base main \
  --title "fix(ioc): from_trusted_store rests only on explicit store list (#267)" \
  --body "$(cat <<'EOF'
Phase 1 of the pure-emitter migration of installer trust (#136).

Removes the forgeable OEM-prefix disjunct from `OemPrefixResolver.isTrustedInstaller`;
`from_trusted_store` now rests solely on the curated `trusted_installers` list, so an
attacker-chosen installer name (`com.google.play.svcupdate`) can no longer fake store
trust and silence the sideload-gated rules (androdr-010/011/012/013/014/016/017/068/069/089).

Also stands up the parallel pure-emitter path — a device-aware `trusted_installer_db`
`ioc_lookup`, backed by the same resolver — that Phase 2 rules will migrate onto. The
legacy computed booleans stay emitted and now-safe (strangler-fig migration).

## Verification
- Unit: #267 regressions in `OemPrefixResolverTest` + `AppScannerTelemetryTest`; new
  `trusted_installer_db` evaluator test; full `testDebugUnitTest` green; `lintDebug` clean.
- Device (Fold 2, `adb install -i com.google.play.svcupdate`): baseline read as
  trusted/not-sideloaded; post-fix sideloaded and trips the surveillance rule
  (before/after DB output below).

## Scope
- Kotlin-only: no YAML/taxonomy/submodule change, no safe-ordering.
- Does NOT close the exact-name cross-device forgery (Galaxy Store trusted on a
  non-Samsung device) — that needs the device-conditional data restructure, filed as
  a follow-up (Phase 1b). Fold 2 sweep found zero apps relying on the removed prefix trust.

Closes #267

🤖 Generated with [Claude Code](https://claude.com/claude-code)

https://claude.ai/code/session_01JD52ChA3BtfEYtVi2Uz61H
EOF
)"
```

- [ ] **Step 2: File the follow-up issues** (references for the roadmap below)

```bash
gh issue create --title "security: device-conditional trusted-installer data (exact-name cross-device forgery)" \
  --label security --body "Phase 1b of #267/#136. Move OEM stores from the flat unconditional trusted_installers list into their per-vendor conditional blocks so an OEM store is trusted only on its own ecosystem. Needs parser support for a per-block trusted_installers key AND careful deploy sequencing: the app fetches ioc-data/known-oem-prefixes.yml from rules-main every 12h and replaces the allowlist wholesale, so the new parser must be broadly deployed BEFORE the restructured YAML reaches main, or un-updated apps over-flag OEM-store apps for up to 12h. Follow CLAUDE.md safe-ordering + OemPrefixMirrorParityTest."
gh issue comment 136 --body "Concrete first steps landed via #267 Phase 1: added the device-aware trusted_installer_db ioc_lookup as the parallel pure-emitter trust path, backed by the same resolver as the legacy from_trusted_store boolean. Phase 2 = migrate the ~10 rules keyed on from_trusted_store: true onto installer|ioc_lookup: trusted_installer_db (taxonomy/schema + rules-repo + submodule). Phase 3 = delete the three judgment booleans (from_trusted_store, is_sideloaded, is_known_oem_app), re-express is_sideloaded's composite in rules, enforce via static analysis."
```

- [ ] **Step 3: Request the two proportional reviews** (code-security + correctness), address confirmed findings, let CI `build` go green, then merge.

---

# Roadmap — later phases (own plans when picked up; tracked under #136)

## Phase 1b — Device-conditional trusted-installer data
- Move OEM stores (`com.sec.android.app.samsungapps` → samsung block, `com.xiaomi.market`/`com.xiaomi.mipicks`/`com.miui.packageinstaller` → xiaomi, `com.heytap.market`/`com.coloros.safecenter` → oppo, `com.huawei.appmarket` → huawei, `com.bbk.appstore` → vivo, the Samsung `updatecenter`/`scloud`/`themestore`/`spay`/`sbrowser`/`watchmanager` set → samsung). Keep `com.android.vending` (and any genuinely cross-vendor entry) unconditional.
- Extend `parseOemPrefixYaml` + `applicablePrefixesFor` to parse and apply a per-block `trusted_installers` key; add `applicableInstallersFor(device)`; re-add the `device` argument to `isTrustedInstaller` and to the `trusted_installer_db` closure (which already captures `localDevice`).
- Edit **both** `res/raw/known_oem_prefixes.yml` and the mirror `ioc-data/known-oem-prefixes.yml` identically (+ the `src/test/resources` fixture copy) — `OemPrefixMirrorParityTest` enforces byte-equality.
- Sequence via CLAUDE.md safe-ordering; mind the 12h wholesale-replace fetch (ship the app parser before the YAML reaches rules-main).
- Closes the exact-name cross-device forgery.

## Phase 2 — Migrate rules onto the lookup
- Rewrite the ~10 rules keyed on `from_trusted_store: true` to `installer|ioc_lookup: trusted_installer_db`. Add `trusted_installer_db` to the taxonomy's known lookups / schema as needed; keep `DetectionFieldCrossCheckTest` + `BundledRulesSchemaCrossCheckTest` green. Rules-repo PR + submodule bump + safe-ordering + `rules.sha256` regen for any `rules.txt`-listed file changed.
- Parallel run continues: booleans still emitted; validate rule-vs-boolean equivalence on-device before proceeding.

## Phase 3 — Retire the legacy judgment booleans (#136 core)
- Remove `from_trusted_store`, `is_sideloaded`, `is_known_oem_app` from `AppTelemetry` + `toFieldMap` + the taxonomy; re-express `is_sideloaded`'s `!system && !trusted && !oem` composite entirely in rules/lookups.
- Also address the sibling `is_known_oem_app` prefix conflation (a sideloaded `com.google.evil` reads as OEM via the unconditional `com.google.` package prefix — same family as #263) as part of moving OEM classification to raw-fact + lookup.
- Enforce the pure-emitter contract via static analysis (the #136/#136-adjacent #136 goal).

---

## Self-review (Phase 1 vs. the agreed design)

- **Closes the forgery in #267's title** ("accepts any OEM-prefixed installer name") → Task 2 removes the prefix disjunct; membership-only. ✔
- **Phased, legacy booleans kept** → all three booleans still emitted (unchanged in `toFieldMap`); Task 4 adds the parallel lookup; Phases 2/3 retire the booleans. ✔ (matches the user's "refactor to pure emitter while keeping legacy computed booleans, then phase them out once stable")
- **Device-relative trust concern** → acknowledged, deferred to Phase 1b with an explicit reason (12h wholesale-replace fetch), and a follow-up issue is filed in Task 8. ✔
- **Pure-emitter faithfulness** → the new path is a device-aware *data lookup* over the raw emitted `installer` fact (already in `toFieldMap`), not another emitter judgment; the rule keeps the detection decision. ✔
- **No placeholders / type consistency** → `isTrustedInstaller(installer: String): Boolean` used identically in Task 2 (def), the AppScanner call site, and the Task 4 closure; `trusted_installer_db` string identical in the lookup registration and the evaluator test. The evaluator-test helpers are flagged as "adapt to the real file" rather than invented as fact. ✔
- **On-device verification the issue demanded** → Tasks 1 & 7, fully automatable via `adb install -i`. ✔

## Out of scope for this plan
- The `initiatingPackageName` fallback (`AppScanner.kt:449-454`) — safe after Task 2 (packageinstaller/dropper names aren't in the store list); removing it would regress the Samsung partnership-preinstall case it exists for.
- Sibling trust-conflation issues #263 / #270 / #249 / #088-guard — same family, separate HitL decisions.
