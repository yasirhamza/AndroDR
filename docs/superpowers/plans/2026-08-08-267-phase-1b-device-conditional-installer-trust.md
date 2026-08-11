# Phase 1b — Device-Conditional Trusted-Installer Trust Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make installer trust device-conditional (an OEM store is trusted only on its own ecosystem) so the exact-name cross-device forgery — a foreign OEM store name conferring trust on any device — is closed, extending the existing per-device prefix machinery to installers.

**Architecture:** Two sequenced PRs. **PR A (1b-i)** ships the parser capability only — per-block `trusted_installers` parsing, `isTrustedInstaller(installer, device)`, device-aware callers — with the YAML *unchanged*, so behavior is byte-identical to today and the new path is dormant until data activates it. **PR B (1b-ii)** flips the YAML (bundled + mirror + fixture) to move OEM stores into their vendor blocks and drop the MIUI sideload UI, activating device-conditional trust. PR A must be deployed on-device before PR B's mirror change reaches `android-sigma-rules` main (the app fetches that feed every 12h and replaces the allowlist wholesale).

**Tech Stack:** Kotlin, JUnit4 + MockK, snakeyaml-engine, Android SDK 34 / JDK 21, Gradle; `android-sigma-rules` git submodule for the mirror feed.

## Global Constraints

- **JDK 21** for every gradle/adb command:
  `export JAVA_HOME=/home/yasir/Applications/android-studio/jbr`
  `export ANDROID_HOME=/home/yasir/Android/Sdk`
  `export PATH="$JAVA_HOME/bin:$ANDROID_HOME/platform-tools:$ANDROID_HOME/emulator:$PATH"`
- **No new dependencies.** Builds offline.
- **Detekt / Android Lint clean.** No unused params, no `@Suppress` to hide one.
- **All changes via PRs targeting `main`**; never push to `main` directly. CI `build` must pass.
- **Mandatory review:** each PR (A and B) gets the **full 4-agent parallel ceremony — correctness, code-quality, architect, code-security** — as four independent adversarial lenses (NOT subagent-driven-development's default per-task-plus-one-final). Size does not reduce this; it is a security trust boundary. The code-security lens must actively try to defeat the device-conditional check.
- **PR B safe-ordering** (mirror feed): edit `android-sigma-rules` mirror on a branch → bump AndroDR submodule to that branch commit in the AndroDR PR → confirm `RuleManifestIntegrityTest` + `OemPrefixMirrorParityTest` green → merge the rules branch to main → re-point submodule at the main commit. `known-oem-prefixes.yml` is **not** in `rules.txt`, so **no `rules.sha256` regen**.
- **Commit trailers** on every commit:
  `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`
  `Claude-Session: https://claude.ai/code/session_01JD52ChA3BtfEYtVi2Uz61H`

## File Structure

- `app/src/main/java/com/androdr/ioc/OemPrefixResolver.kt` — data classes (`ConditionalBlock`, `ApplicablePrefixes`), `parseOemPrefixYaml`, `applicablePrefixesFor`, `isTrustedInstaller`, `refresh` caps. **Core of PR A.**
- `app/src/main/java/com/androdr/scanner/AppScanner.kt:245-246` — `isTrustedInstaller` call site. **PR A.**
- `app/src/main/java/com/androdr/scanner/ScanOrchestrator.kt` — `trusted_installer_db` closure. **PR A.**
- `app/src/test/java/com/androdr/ioc/OemPrefixResolverTest.kt` — parser + device-conditional resolver tests. **PR A adds synthetic-YAML tests; PR B updates fixture-based assertions.**
- `app/src/main/res/raw/known_oem_prefixes.yml`, `third-party/android-sigma-rules/ioc-data/known-oem-prefixes.yml` (submodule), `app/src/test/resources/raw/known_oem_prefixes.yml` — the three byte-equal YAML copies. **PR B only.**

---

# Deliverable A — PR A (1b-i): parser capability (branch `fix/280-1b-i-installer-parser`)

AndroDR-only. No YAML/mirror/submodule change. On merge, behavior is unchanged (YAML still has all installers top-level); the device-conditional path is dormant, exercised only by synthetic-YAML unit tests.

## Task 1: Per-block installers in data model, parser, and applicable set

**Files:**
- Modify: `app/src/main/java/com/androdr/ioc/OemPrefixResolver.kt`
- Test: `app/src/test/java/com/androdr/ioc/OemPrefixResolverTest.kt`

**Interfaces:**
- Produces: `ConditionalBlock` gains `val installers: Set<String>`; `ApplicablePrefixes` gains `val installers: Set<String>`; `applicablePrefixesFor(device).installers` = unconditional `trustedInstallers` ∪ every matching block's `installers`. `isTrustedInstaller` is UNCHANGED in this task (still single-arg).
- Consumes: existing `ParsedOemData.trustedInstallers` (top-level unconditional installers), `ConditionalBlock.matches(device)`.

- [ ] **Step 1: Write failing parser + union tests**

Add to `OemPrefixResolverTest.kt`. First add a helper that builds a resolver from an inline YAML string (mirrors the existing `init` mock-context pattern):

```kotlin
    private fun resolverFromYaml(yaml: String): OemPrefixResolver {
        val ctx: Context = mockk(relaxed = true)
        val res: Resources = mockk(relaxed = true)
        every { ctx.resources } returns res
        every { res.openRawResource(R.raw.known_oem_prefixes) } returns
            yaml.byteInputStream()
        return OemPrefixResolver(ctx)
    }

    private val SYNTHETIC_YAML = """
        version: "test"
        unconditional:
          aosp_prefixes: ["com.android."]
          trusted_installers: ["com.android.vending"]
        conditional:
          samsung:
            manufacturer_match: ["samsung"]
            brand_match: ["samsung"]
            strict_prefixes: ["com.samsung."]
            trusted_installers: ["com.sec.android.app.samsungapps"]
    """.trimIndent()

    private val motorola = DeviceIdentity(manufacturer = "motorola", brand = "motorola")
```

```kotlin
    @Test
    fun `parseOemPrefixYaml reads per-block trusted_installers`() {
        val r = resolverFromYaml(SYNTHETIC_YAML)
        val samsungInstallers = r.applicablePrefixesFor(samsung).installers
        assertTrue(samsungInstallers.contains("com.sec.android.app.samsungapps"))
        assertTrue(samsungInstallers.contains("com.android.vending")) // unconditional included
    }

    @Test
    fun `conditional installers apply only on a matching device`() {
        val r = resolverFromYaml(SYNTHETIC_YAML)
        assertTrue(r.applicablePrefixesFor(samsung).installers.contains("com.sec.android.app.samsungapps"))
        assertFalse(r.applicablePrefixesFor(motorola).installers.contains("com.sec.android.app.samsungapps"))
        // Unconditional store is present on every device:
        assertTrue(r.applicablePrefixesFor(motorola).installers.contains("com.android.vending"))
    }
```

- [ ] **Step 2: Run — expect failure**

`./gradlew :app:testDebugUnitTest --tests "com.androdr.ioc.OemPrefixResolverTest"`
Expected: FAIL — `ApplicablePrefixes` has no `installers` property (compile error).

- [ ] **Step 3: Add `installers` to the data classes**

In `OemPrefixResolver.kt`, `ConditionalBlock`:

```kotlin
    internal data class ConditionalBlock(
        val id: String,
        val manufacturerMatch: Set<String>,
        val brandMatch: Set<String>,
        val strictPrefixes: Set<String>,
        val installers: Set<String> = emptySet(),
    ) {
```

`ApplicablePrefixes`:

```kotlin
    data class ApplicablePrefixes(
        val strict: Set<String>,
        val installers: Set<String> = emptySet(),
    )
```

- [ ] **Step 4: Parse per-block `trusted_installers` and fix the retention guard**

In `parseOemPrefixYaml`'s conditional loop, after `strictPrefixes` is parsed, add:

```kotlin
                val blockInstallers = (block["trusted_installers"] as? List<*>)
                    ?.filterIsInstance<String>()
                    ?.filter { it.length >= MIN_INSTALLER_LEN && it.contains('.') }
                    ?.take(MAX_INSTALLER_COUNT)
                    ?.toSet() ?: emptySet()
```

Change the retention condition and constructor:

```kotlin
                if (strictPrefixes.isNotEmpty() || blockInstallers.isNotEmpty()) {
                    conditionalBlocks += ConditionalBlock(
                        id = blockId,
                        manufacturerMatch = manufacturerMatch,
                        brandMatch = brandMatch,
                        strictPrefixes = strictPrefixes,
                        installers = blockInstallers,
                    )
                }
```

- [ ] **Step 5: Union installers in `applicablePrefixesFor`**

Replace the body of `applicablePrefixesFor`:

```kotlin
    fun applicablePrefixesFor(device: DeviceIdentity): ApplicablePrefixes =
        perDeviceCache.getOrPut(device) {
            val d = data.get()
            val strict = mutableSetOf<String>()
            val installers = mutableSetOf<String>()

            strict.addAll(d.unconditionalStrict)
            installers.addAll(d.trustedInstallers) // unconditional installers apply everywhere

            for (block in d.conditional) {
                if (block.matches(device)) {
                    strict.addAll(block.strictPrefixes)
                    installers.addAll(block.installers)
                }
            }

            ApplicablePrefixes(strict = strict.toSet(), installers = installers.toSet())
        }
```

- [ ] **Step 6: Run — expect pass**

`./gradlew :app:testDebugUnitTest --tests "com.androdr.ioc.OemPrefixResolverTest"`
Expected: PASS (new tests green; existing tests unaffected — `isTrustedInstaller` unchanged, still single-arg).

- [ ] **Step 7: Commit**

```bash
git add app/src/main/java/com/androdr/ioc/OemPrefixResolver.kt \
        app/src/test/java/com/androdr/ioc/OemPrefixResolverTest.kt
git commit -m "feat(ioc): parse per-block trusted_installers into applicable set (#280)"
```

## Task 2: Device-conditional `isTrustedInstaller` + callers + feed caps

**Files:**
- Modify: `app/src/main/java/com/androdr/ioc/OemPrefixResolver.kt` (`isTrustedInstaller`, `refresh`)
- Modify: `app/src/main/java/com/androdr/scanner/AppScanner.kt:245-246`
- Modify: `app/src/main/java/com/androdr/scanner/ScanOrchestrator.kt` (`trusted_installer_db` closure)
- Test: `app/src/test/java/com/androdr/ioc/OemPrefixResolverTest.kt`

**Interfaces:**
- Produces: `isTrustedInstaller(installer: String, device: DeviceIdentity): Boolean` = `installer in applicablePrefixesFor(device).installers`.
- Consumes: `applicablePrefixesFor(device).installers` (Task 1); `localDevice` at both call sites.

- [ ] **Step 1: Rewrite the installer tests for the two-arg, device-conditional contract**

Replace the three current installer tests in `OemPrefixResolverTest.kt` (`bundled store installers are trusted`, `OEM-prefixed non-store installers are NOT trusted (#267)`, `forged store-looking installer names are not trusted (#267)`, `unknown installers are not trusted`) with these. Note: against the **current unchanged bundled fixture** (all installers top-level unconditional), stores are trusted on ANY device — device-conditionality is proven with `SYNTHETIC_YAML` from Task 1.

```kotlin
    @Test
    fun `bundled store installers are trusted on any device (fixture still flat)`() {
        // Bundled fixture is unchanged in PR A: all installers are top-level unconditional.
        assertTrue(resolver.isTrustedInstaller("com.android.vending", generic))
        assertTrue(resolver.isTrustedInstaller("com.sec.android.app.samsungapps", generic))
        assertTrue(resolver.isTrustedInstaller("com.xiaomi.market", motorola))
    }

    @Test
    fun `forged store-looking installer names are not trusted (#267)`() {
        assertFalse(resolver.isTrustedInstaller("com.google.play.svcupdate", generic))
        assertFalse(resolver.isTrustedInstaller("com.google.android.packageinstaller", generic))
        assertFalse(resolver.isTrustedInstaller("com.android.packageinstaller", generic))
    }

    @Test
    fun `unknown installers are not trusted`() {
        assertFalse(resolver.isTrustedInstaller("com.unknown.installer", generic))
    }

    @Test
    fun `store trust is device-conditional when data uses per-block installers (#280)`() {
        val r = resolverFromYaml(SYNTHETIC_YAML)
        assertTrue(r.isTrustedInstaller("com.sec.android.app.samsungapps", samsung))
        assertFalse(r.isTrustedInstaller("com.sec.android.app.samsungapps", motorola)) // cross-device forgery closed
        assertTrue(r.isTrustedInstaller("com.android.vending", motorola)) // Play everywhere
    }
```

Add `private val motorola` if not already added in Task 1's file (it is).

- [ ] **Step 2: Run — expect failure**

`./gradlew :app:testDebugUnitTest --tests "com.androdr.ioc.OemPrefixResolverTest"`
Expected: FAIL — `isTrustedInstaller` takes one arg; the two-arg calls don't compile.

- [ ] **Step 3: Make `isTrustedInstaller` device-conditional**

Replace the method + KDoc:

```kotlin
    /**
     * Returns true iff [installer] is a trusted app-store package for [device]:
     * exact membership in the applicable installer set — unconditional stores
     * (e.g. Play) plus the stores of any conditional block matching [device].
     *
     * Trust is NOT inferred from OEM package prefixes (a forgeable installer
     * name; see #267), and an OEM store is trusted only on its own ecosystem
     * (a Samsung store name on a non-Samsung device is not trusted; #280).
     */
    fun isTrustedInstaller(installer: String, device: DeviceIdentity): Boolean =
        installer in applicablePrefixesFor(device).installers
```

- [ ] **Step 4: Update both call sites**

`AppScanner.kt:245-246`:

```kotlin
        val fromTrustedStore = installerPackage != null &&
            oemPrefixResolver.isTrustedInstaller(installerPackage, localDevice)
```

`ScanOrchestrator.kt` `trusted_installer_db` closure:

```kotlin
            "trusted_installer_db" to { v ->
                oemPrefixResolver.isTrustedInstaller(v.toString(), localDevice)
            }
```

- [ ] **Step 5: Extend the remote-feed sanity caps to per-block installers**

In `refresh()`, replace the acceptance count so per-block installers are counted:

```kotlin
            val allInstallers = parsed.trustedInstallers +
                parsed.conditional.flatMap { it.installers }
            val accepted = allPrefixes.size + allInstallers.size
```

(The `allPrefixes` size/length checks above are unchanged. Per-block installers are already `.take(MAX_INSTALLER_COUNT)`-bounded at parse time in Task 1.)

- [ ] **Step 6: Run — expect pass**

`./gradlew :app:testDebugUnitTest --tests "com.androdr.ioc.OemPrefixResolverTest"`
Then compile the whole app to catch any other caller:
`./gradlew :app:compileDebugKotlin`
Expected: PASS / SUCCESS. (Grep confirmed only AppScanner + ScanOrchestrator + the test call `isTrustedInstaller`.)

- [ ] **Step 7: Commit**

```bash
git add app/src/main/java/com/androdr/ioc/OemPrefixResolver.kt \
        app/src/main/java/com/androdr/scanner/AppScanner.kt \
        app/src/main/java/com/androdr/scanner/ScanOrchestrator.kt \
        app/src/test/java/com/androdr/ioc/OemPrefixResolverTest.kt
git commit -m "feat(ioc): device-conditional isTrustedInstaller(installer, device) (#280)"
```

## Task 3 (PR A): Full suite + lint, then ceremony + PR

- [ ] **Step 1:** `./gradlew testDebugUnitTest lintDebug` → BUILD SUCCESSFUL, 0 failures, lint 0 findings. (Behavior unchanged vs `main`: bundled YAML still flat, so existing AppScannerTelemetryTest etc. pass untouched.)
- [ ] **Step 2:** Push `fix/280-1b-i-installer-parser`; open PR (base `main`); body notes: parser capability only, YAML unchanged, dormant until PR B; `Refs #280`.
- [ ] **Step 3:** Run the **4-agent ceremony** (correctness, code-quality, architect, code-security) on the PR A diff. Code-security lens: confirm the union can't be bypassed (malformed/installers-only block, cap evasion, null device). Reconcile findings; merge on green.
- [ ] **Step 4:** **Deploy PR A on-device** (`./gradlew installDebug` on the Fold 2, or ship the release) BEFORE starting PR B. This is the migration gate.

---

# ⛔ DEPLOYMENT GATE

Do not begin Deliverable B's mirror change until PR A's parser is on the target device(s). The app fetches `known-oem-prefixes.yml` from `android-sigma-rules` main every 12h and replaces the allowlist wholesale — a restructured feed reaching main before the new parser is deployed makes old apps over-flag OEM-store installs for up to 12h.

---

# Deliverable B — PR B (1b-ii): YAML flip (branch `fix/280-1b-ii-yaml`, + `android-sigma-rules` branch)

## Task 4: Restructure the three YAML copies + update fixture-based assertions

**Files:**
- Modify (identically, byte-equal): `app/src/main/res/raw/known_oem_prefixes.yml`, `third-party/android-sigma-rules/ioc-data/known-oem-prefixes.yml` (submodule), `app/src/test/resources/raw/known_oem_prefixes.yml`
- Test: `app/src/test/java/com/androdr/ioc/OemPrefixResolverTest.kt`

**Interfaces:**
- Consumes: `isTrustedInstaller(installer, device)` and per-block parsing from PR A.

- [ ] **Step 1: Edit the mirror on an `android-sigma-rules` branch**

```bash
cd third-party/android-sigma-rules
git checkout -b feat/280-device-conditional-installers
```
In `ioc-data/known-oem-prefixes.yml`: (a) in `unconditional.trusted_installers` keep ONLY `com.android.vending` and `com.facebook.system`; (b) add a `trusted_installers:` list to each vendor block:
- `samsung`: `com.sec.android.app.samsungapps`, `com.samsung.android.app.updatecenter`, `com.samsung.android.app.watchmanager`, `com.samsung.android.scloud`, `com.samsung.android.themestore`, `com.samsung.android.spay`, `com.sec.android.app.sbrowser`
- `xiaomi`: `com.xiaomi.market`, `com.xiaomi.mipicks`  *(drop `com.miui.packageinstaller` — MIUI sideload UI, not a store)*
- `oppo`: `com.heytap.market`, `com.coloros.safecenter`
- `huawei`: `com.huawei.appmarket`
- `vivo`: `com.bbk.appstore`

Bump the YAML `version:` field. Commit on the branch (with trailers). Note the commit SHA.

- [ ] **Step 2: Mirror the identical change into the bundled + fixture copies**

Copy the edited mirror file over both AndroDR copies verbatim (filenames differ — underscores bundled, hyphens mirrored, but contents are byte-equal):

```bash
cd /home/yasir/AndroDR   # (or the worktree root)
cp third-party/android-sigma-rules/ioc-data/known-oem-prefixes.yml app/src/main/res/raw/known_oem_prefixes.yml
cp third-party/android-sigma-rules/ioc-data/known-oem-prefixes.yml app/src/test/resources/raw/known_oem_prefixes.yml
git -C third-party/android-sigma-rules rev-parse HEAD   # submodule now points at the branch commit
```

- [ ] **Step 3: Update the fixture-based assertions to device-conditional**

In `OemPrefixResolverTest.kt`, the `bundled store installers are trusted on any device (fixture still flat)` test from PR A is now false — the fixture is no longer flat. Replace it with device-conditional assertions against the restructured fixture:

```kotlin
    @Test
    fun `bundled OEM stores are trusted only on their ecosystem (#280)`() {
        // Play stays unconditional.
        assertTrue(resolver.isTrustedInstaller("com.android.vending", generic))
        assertTrue(resolver.isTrustedInstaller("com.android.vending", samsung))
        // Galaxy Store: trusted on Samsung, not elsewhere.
        assertTrue(resolver.isTrustedInstaller("com.sec.android.app.samsungapps", samsung))
        assertFalse(resolver.isTrustedInstaller("com.sec.android.app.samsungapps", generic))
        // Xiaomi Market: trusted on Xiaomi, not on Samsung.
        assertTrue(resolver.isTrustedInstaller("com.xiaomi.market", xiaomi))
        assertFalse(resolver.isTrustedInstaller("com.xiaomi.market", samsung))
    }

    @Test
    fun `MIUI package installer is no longer a trusted installer anywhere (#280)`() {
        assertFalse(resolver.isTrustedInstaller("com.miui.packageinstaller", xiaomi))
        assertFalse(resolver.isTrustedInstaller("com.miui.packageinstaller", generic))
    }
```

- [ ] **Step 4: Run parity + resolver tests**

`./gradlew :app:testDebugUnitTest --tests "com.androdr.ioc.OemPrefixResolverTest" --tests "com.androdr.ioc.OemPrefixMirrorParityTest"`
Expected: PASS — parity confirms the three copies are byte-equal; resolver confirms device-conditional trust.

- [ ] **Step 5: Full suite + lint + commit**

```bash
./gradlew testDebugUnitTest lintDebug   # expect green, 0 lint findings
git add app/src/main/res/raw/known_oem_prefixes.yml \
        app/src/test/resources/raw/known_oem_prefixes.yml \
        third-party/android-sigma-rules \
        app/src/test/java/com/androdr/ioc/OemPrefixResolverTest.kt
git commit -m "feat(ioc): device-condition OEM stores; drop MIUI sideload UI (#280)

Move OEM stores into per-vendor conditional blocks; Play + facebook.system
stay unconditional. Bundled+mirror+fixture kept byte-equal (parity gate).
Submodule bumped to the android-sigma-rules branch (safe-ordering)."
```

## Task 5 (PR B): On-device verification (Fold 2, Samsung)

**Files:** none (verification).

- [ ] **Step 1:** `./gradlew installDebug` (the restructured-YAML build).
- [ ] **Step 2: Home-ecosystem store still trusted (the key regression check).** Galaxy Store is installed on the Samsung Fold 2, so its installer name is visible to the app (not redacted):

```bash
adb install -r -i com.sec.android.app.samsungapps \
  /home/yasir/AndroDR/test-adversary/fixtures/mercenary/surveillance-permissions.apk
```
Launch, tap Run Scan (headless via `uiautomator dump` → locate "Run Scan" → `adb shell input tap`), poll the Room DB (pull all 3 files, WAL). Expected: `from_trusted_store=true`, `is_sideloaded=false`, fixture **not** flagged — moving Galaxy Store into the samsung block did not break home-ecosystem trust on a Samsung device.
- [ ] **Step 3: Play still trusted.** Reinstall with `-i com.android.vending`, rescan → not flagged.
- [ ] **Step 4:** `adb uninstall com.androdr.fixture.surveillance`.
- [ ] **Note (documented limitation):** cross-vendor *rejection* on-device (e.g. `com.heytap.market` on this Samsung device) cannot be cleanly shown — Android 11+ redacts an uninstalled installer's name to null before the app sees it (established in Phase 1), so a foreign store not installed here reads as `null`, not as the foreign name. Cross-vendor rejection is proven at the unit level (`isTrustedInstaller("com.sec.android.app.samsungapps", motorola) == false`).

## Task 6 (PR B): Ceremony, safe-ordering merge, follow-up

- [ ] **Step 1:** Push `fix/280-1b-ii-yaml`; open PR (base `main`); body: `Closes #280`, notes the submodule points at the rules branch (safe-ordering), on-device results, and the deployment gate.
- [ ] **Step 2:** Confirm `RuleManifestIntegrityTest` + `OemPrefixMirrorParityTest` + `build-and-test` green in CI.
- [ ] **Step 3:** Run the **4-agent ceremony** on the PR B diff. Reconcile findings.
- [ ] **Step 4: Safe-ordering merge:** merge the `android-sigma-rules` branch to its main; re-point the AndroDR submodule at the resulting main commit (amend/one more commit on the PR branch); confirm CI green; merge PR B.
- [ ] **Step 5:** File the follow-up issue: audit ambiguous Samsung-service trusted-installer entries (`scloud`/`spay`/`sbrowser`/`updatecenter`/`watchmanager`) — kept device-gated as-is in this PR.

---

## Self-Review

**Spec coverage:**
- Parser learns per-block `trusted_installers` → Task 1. ✔
- `isTrustedInstaller(installer, device)` device-conditional + callers → Task 2. ✔
- Remote-feed caps count per-block installers → Task 2 Step 5. ✔
- Block-retention keeps installers-only blocks → Task 1 Step 4 (`|| blockInstallers.isNotEmpty()`). ✔
- YAML flip mapping incl. keep Play/facebook.system unconditional, drop `com.miui.packageinstaller` → Task 4 Step 1. ✔
- Three copies byte-equal, parity-gated → Task 4 Steps 2/4. ✔
- Safe-ordering + no `rules.sha256` regen → Global Constraints + Task 6 Step 4. ✔
- Deployment gate (parser-first) → the ⛔ gate + Task 3 Step 4. ✔
- Device-conditional unit proof + on-device home-ecosystem/Play checks + redaction caveat → Tasks 2/5. ✔
- 4-agent ceremony per PR → Global Constraints + Task 3 Step 3 + Task 6 Step 3. ✔
- Follow-up for Samsung-service entries → Task 6 Step 5. ✔

**Placeholder scan:** every code step carries real code/commands; no TBD/"handle edge cases". ✔

**Type consistency:** `ApplicablePrefixes(strict, installers)` and `ConditionalBlock(..., installers)` defined in Task 1 and used identically in Task 2's `applicablePrefixesFor`/`isTrustedInstaller`; `isTrustedInstaller(installer: String, device: DeviceIdentity): Boolean` signature identical across Task 2, both call sites, and all test calls; `resolverFromYaml`/`SYNTHETIC_YAML`/`motorola` defined once in Task 1 and reused in Task 2. ✔
