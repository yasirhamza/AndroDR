# Data-Broker SDK Scanner — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extend `AppScanner` to emit two new list-typed telemetry fields — `embeddedComponentClasses` and `embeddedNativeLibs` — so subsequent rule packs can fingerprint ad-broker SDKs that ship embedded inside otherwise-mainstream apps.

**Architecture:** Two pure-function extractors added as `internal` members of `AppScanner`. Manifest extractor reads `.name` from `PackageInfo.services|receivers|activities|providers`. Native-libs extractor opens the APK via `applicationInfo.publicSourceDir` as a `ZipFile` and lists `lib/*/*.so` entries. Output is appended to `AppTelemetry` (Approach A, per spec). Schema parity enforced by `BundledRulesSchemaCrossCheckTest` after coordinated submodule taxonomy update.

**Tech Stack:** Kotlin, AndroidX, Hilt, JUnit4, mockk, `java.util.zip.ZipFile`, `java.util.zip.ZipOutputStream` (test fixture building).

**Spec:** `docs/superpowers/specs/2026-05-17-data-broker-sdk-scanner-design.md`

**Issue:** [#168](https://github.com/yasirhamza/AndroDR/issues/168)

---

## PR boundary 1: Submodule (`android-sigma-rules`)

This work happens in `/home/yasir/AndroDR/third-party/android-sigma-rules/`. Open the PR in the `android-sigma-rules/rules` repo, admin-merge there, then come back to AndroDR for the rest.

### Task 1: Add taxonomy fields to logsource-taxonomy.yml

**Files:**
- Modify: `third-party/android-sigma-rules/validation/logsource-taxonomy.yml` (under `app_scanner.fields`)

- [ ] **Step 1: Create the submodule branch**

```bash
cd third-party/android-sigma-rules
git checkout main
git pull --ff-only origin main
git checkout -b feat/168-embedded-sdk-fields
```

- [ ] **Step 2: Insert the two new field entries**

Open `validation/logsource-taxonomy.yml`. Find the `app_scanner.fields:` block. After the existing `last_update_time` entry, add:

```yaml
      embedded_component_class: { type: list, description: "Class names from manifest services/receivers/activities/providers; deduplicated; capped per app. Used by embedded-SDK fingerprinting rules (AndroDR #168)." }
      embedded_native_lib: { type: list, description: "Filenames of lib/*/*.so entries inside the APK, ABI prefix stripped; deduplicated; capped per app. Used by embedded-SDK fingerprinting rules (AndroDR #168)." }
```

Match the existing inline-flow style on every neighbouring entry. Do **not** add a multi-line yaml block — the existing entries are all single-line.

- [ ] **Step 3: Run the validator's self-test**

```bash
cd /home/yasir/AndroDR/third-party/android-sigma-rules
python3 -m pytest validation/test_validate_ioc_complementarity.py -v
```

Expected: all tests still pass. (None reference these new fields, but this confirms the YAML still parses.)

- [ ] **Step 4: Commit + push**

```bash
git add validation/logsource-taxonomy.yml
git commit -m "feat(taxonomy): add embedded_component_class + embedded_native_lib to app_scanner (AndroDR #168)"
git push -u origin feat/168-embedded-sdk-fields
```

- [ ] **Step 5: Open submodule PR + admin-merge**

```bash
gh pr create --base main --head feat/168-embedded-sdk-fields \
  --title "feat(taxonomy): add embedded-SDK fields to app_scanner (AndroDR #168)" \
  --body "Adds embedded_component_class + embedded_native_lib under app_scanner.fields, both list-typed. Used by AndroDR #168 scanner extension (parent: docs/superpowers/specs/2026-05-17-data-broker-sdk-scanner-design.md in AndroDR repo). No rule-side consumers in this submodule yet; rules land in AndroDR-side PRs after the scanner ships."
gh pr merge --admin --squash --delete-branch
```

Capture the merged commit SHA — you will need it for the submodule pointer bump in Task 2:

```bash
git fetch origin main
git rev-parse origin/main
```

---

## PR boundary 2: AndroDR

Back in `/home/yasir/AndroDR`. Single PR; tasks 2-7 belong here.

### Task 2: Bump submodule pointer + create AndroDR feature branch

**Files:**
- Modify: `third-party/android-sigma-rules` (gitlink only)

- [ ] **Step 1: Branch off main**

```bash
cd /home/yasir/AndroDR
git checkout main
git pull --ff-only origin main
git checkout -b feat/168-app-scanner-embedded-sdk-signals
```

- [ ] **Step 2: Bump the submodule pointer to the freshly-merged taxonomy commit**

```bash
cd third-party/android-sigma-rules
git fetch origin main
git checkout main
git pull --ff-only origin main
cd ../..
```

- [ ] **Step 3: Stage + commit the pointer bump**

```bash
git add third-party/android-sigma-rules
git -c commit.gpgsign=false commit -m "chore(submodule): bump android-sigma-rules for embedded-SDK fields (#168)"
```

(Drop the `gpgsign=false` if the project doesn't require it — match what prior `chore(submodule):` commits used; see `git log --grep "chore(submodule)"`.)

### Task 3: Add `extractComponentClassNames` (TDD)

**Files:**
- Test: `app/src/test/java/com/androdr/scanner/AppScannerTelemetryTest.kt` (modify — append tests + helpers)
- Modify: `app/src/main/java/com/androdr/scanner/AppScanner.kt` (add function)

This task adds the pure-function extractor only. Wiring into `collectTelemetry()` happens in Task 5.

- [ ] **Step 1: Write the failing test for the happy path**

Open `app/src/test/java/com/androdr/scanner/AppScannerTelemetryTest.kt`. Append after the existing tests:

```kotlin
import android.content.pm.ProviderInfo
import android.content.pm.ActivityInfo
import android.content.pm.ServiceInfo

@Test
fun `extractComponentClassNames returns deduped sorted class names from all four component kinds`() {
    val pkgInfo = PackageInfo().apply {
        services = arrayOf(
            ServiceInfo().apply { name = "com.outlogic.collector.GeoSyncService" },
            ServiceInfo().apply { name = "com.example.legit.NormalService" }
        )
        receivers = arrayOf(
            ActivityInfo().apply { name = "com.outlogic.collector.WakeReceiver" }
        )
        activities = arrayOf(
            ActivityInfo().apply { name = "com.example.legit.MainActivity" },
            ActivityInfo().apply { name = "com.example.legit.MainActivity" } // dup
        )
        providers = arrayOf(
            ProviderInfo().apply { name = "com.example.legit.SettingsProvider" }
        )
    }

    val result = scanner.extractComponentClassNames(pkgInfo)

    assertEquals(
        listOf(
            "com.example.legit.MainActivity",
            "com.example.legit.NormalService",
            "com.example.legit.SettingsProvider",
            "com.outlogic.collector.GeoSyncService",
            "com.outlogic.collector.WakeReceiver"
        ),
        result
    )
}

@Test
fun `extractComponentClassNames returns emptyList when all four arrays are null`() {
    val pkgInfo = PackageInfo().apply {
        services = null
        receivers = null
        activities = null
        providers = null
    }
    assertEquals(emptyList<String>(), scanner.extractComponentClassNames(pkgInfo))
}

@Test
fun `extractComponentClassNames truncates to MAX_COMPONENTS_PER_APP`() {
    val many = (1..2000).map { ActivityInfo().apply { name = "com.example.A$it" } }.toTypedArray()
    val pkgInfo = PackageInfo().apply { activities = many; services = null; receivers = null; providers = null }
    val result = scanner.extractComponentClassNames(pkgInfo)
    assertEquals(1024, result.size)
}
```

(`scanner` is the existing `AppScanner` instance built in this file's `@Before`. If that name differs in the actual `@Before`, match the existing field name — search the file for `lateinit var.*AppScanner` to confirm.)

- [ ] **Step 2: Run the failing test**

```bash
export JAVA_HOME=/home/yasir/Applications/jdk-21
./gradlew testDebugUnitTest --tests "com.androdr.scanner.AppScannerTelemetryTest"
```

Expected: compile error — `extractComponentClassNames` does not exist on `AppScanner`.

- [ ] **Step 3: Add the function to `AppScanner.kt`**

Open `app/src/main/java/com/androdr/scanner/AppScanner.kt`. Add this `internal` function inside the class (just below `collectTelemetry()` is the natural spot):

```kotlin
/**
 * Returns deduped, sorted class names from a PackageInfo's services,
 * receivers, activities, and providers arrays. Used downstream by SIGMA
 * rules that fingerprint embedded SDKs by class-name prefix. See
 * spec `docs/superpowers/specs/2026-05-17-data-broker-sdk-scanner-design.md`.
 *
 * Output is capped at [MAX_COMPONENTS_PER_APP] to bound memory against
 * pathological/malicious manifests. Stable sort produces consistent
 * diffs in scan history.
 */
internal fun extractComponentClassNames(packageInfo: PackageInfo): List<String> {
    val out = LinkedHashSet<String>()
    packageInfo.services?.forEach { it.name?.takeIf { n -> n.isNotBlank() }?.let { n -> out.add(n) } }
    packageInfo.receivers?.forEach { it.name?.takeIf { n -> n.isNotBlank() }?.let { n -> out.add(n) } }
    packageInfo.activities?.forEach { it.name?.takeIf { n -> n.isNotBlank() }?.let { n -> out.add(n) } }
    packageInfo.providers?.forEach { it.name?.takeIf { n -> n.isNotBlank() }?.let { n -> out.add(n) } }
    return out.asSequence().take(MAX_COMPONENTS_PER_APP).sorted().toList()
}
```

Add the cap constant to the `companion object` (find the existing one in `AppScanner.kt` — there is one for `TAG` etc.):

```kotlin
companion object {
    // existing entries unchanged
    private const val MAX_COMPONENTS_PER_APP = 1024
    private const val MAX_NATIVE_LIBS_PER_APP = 256
}
```

(Add both constants together — Task 4 will use `MAX_NATIVE_LIBS_PER_APP`.)

- [ ] **Step 4: Run the test to verify it passes**

```bash
./gradlew testDebugUnitTest --tests "com.androdr.scanner.AppScannerTelemetryTest.extractComponentClassNames*"
```

Expected: all three new test cases pass; no other tests break.

- [ ] **Step 5: Commit**

```bash
git add app/src/main/java/com/androdr/scanner/AppScanner.kt \
        app/src/test/java/com/androdr/scanner/AppScannerTelemetryTest.kt
git -c commit.gpgsign=false commit -m "feat(scanner): extract manifest component class names (#168)"
```

### Task 4: Add `extractNativeLibFileNames` (TDD)

**Files:**
- Test: `app/src/test/java/com/androdr/scanner/AppScannerTelemetryTest.kt` (append tests)
- Modify: `app/src/main/java/com/androdr/scanner/AppScanner.kt` (add function)

The test builds a synthetic ZIP at runtime via `ZipOutputStream` — no binary fixture checked in.

- [ ] **Step 1: Write the failing tests**

Append to `AppScannerTelemetryTest.kt`:

```kotlin
import java.io.File
import java.io.FileOutputStream
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream
import org.junit.rules.TemporaryFolder
import org.junit.Rule

// ... if @Rule already declared elsewhere in the class, don't redeclare; just reuse
@get:Rule
val tempFolder = TemporaryFolder()

private fun buildSyntheticApk(name: String, entries: List<String>): File {
    val file = tempFolder.newFile(name)
    ZipOutputStream(FileOutputStream(file)).use { zip ->
        for (entry in entries) {
            zip.putNextEntry(ZipEntry(entry))
            zip.write(byteArrayOf(0)) // placeholder body so the entry is well-formed
            zip.closeEntry()
        }
    }
    return file
}

@Test
fun `extractNativeLibFileNames returns deduped leaf filenames across ABIs`() {
    val apk = buildSyntheticApk("test.apk", listOf(
        "AndroidManifest.xml",
        "classes.dex",
        "lib/arm64-v8a/libxmode.so",
        "lib/arm64-v8a/libcollector.so",
        "lib/x86_64/libxmode.so",                 // dup of arm64-v8a leaf
        "lib/armeabi-v7a/libcollector.so",        // dup of arm64-v8a leaf
        "lib/arm64-v8a/libunique.so",
        "res/values/strings.xml"
    ))
    val appInfo = ApplicationInfo().apply { publicSourceDir = apk.absolutePath }

    val result = scanner.extractNativeLibFileNames(appInfo)

    assertEquals(listOf("libcollector.so", "libunique.so", "libxmode.so"), result)
}

@Test
fun `extractNativeLibFileNames returns emptyList for a non-existent path`() {
    val appInfo = ApplicationInfo().apply { publicSourceDir = "/does/not/exist.apk" }
    assertEquals(emptyList<String>(), scanner.extractNativeLibFileNames(appInfo))
}

@Test
fun `extractNativeLibFileNames returns emptyList for a corrupt zip`() {
    val bogus = tempFolder.newFile("bogus.apk")
    bogus.writeText("not a zip file")
    val appInfo = ApplicationInfo().apply { publicSourceDir = bogus.absolutePath }
    assertEquals(emptyList<String>(), scanner.extractNativeLibFileNames(appInfo))
}

@Test
fun `extractNativeLibFileNames truncates to MAX_NATIVE_LIBS_PER_APP`() {
    val entries = (1..400).map { "lib/arm64-v8a/lib$it.so" }
    val apk = buildSyntheticApk("big.apk", entries)
    val appInfo = ApplicationInfo().apply { publicSourceDir = apk.absolutePath }
    val result = scanner.extractNativeLibFileNames(appInfo)
    assertEquals(256, result.size)
}
```

- [ ] **Step 2: Run the failing tests**

```bash
./gradlew testDebugUnitTest --tests "com.androdr.scanner.AppScannerTelemetryTest.extractNativeLibFileNames*"
```

Expected: compile error — `extractNativeLibFileNames` not found.

- [ ] **Step 3: Add the function to `AppScanner.kt`**

Add an import: `import java.util.zip.ZipFile`. Then add this `internal` function next to `extractComponentClassNames`:

```kotlin
/**
 * Returns deduped, sorted leaf filenames of native libraries embedded
 * in the APK at [applicationInfo.publicSourceDir]. ABI prefix is stripped
 * so `lib/arm64-v8a/libxmode.so` and `lib/x86_64/libxmode.so` collapse
 * to a single `libxmode.so` entry. Output is capped at
 * [MAX_NATIVE_LIBS_PER_APP]. Failures (unreadable APK, corrupt zip) are
 * logged and produce an empty list — never thrown — so one bad APK
 * cannot abort the whole scan.
 */
@Suppress("TooGenericExceptionCaught", "SwallowedException")
internal fun extractNativeLibFileNames(applicationInfo: ApplicationInfo): List<String> {
    val path = applicationInfo.publicSourceDir ?: return emptyList()
    val out = LinkedHashSet<String>()
    try {
        ZipFile(path).use { zip ->
            val entries = zip.entries()
            while (entries.hasMoreElements()) {
                val name = entries.nextElement().name
                if (name.startsWith("lib/") && name.endsWith(".so")) {
                    val leaf = name.substringAfterLast('/')
                    if (leaf.isNotBlank()) out.add(leaf)
                }
            }
        }
    } catch (e: Exception) {
        Log.w(TAG, "extractNativeLibFileNames failed for $path: ${e.message}")
        return emptyList()
    }
    return out.asSequence().take(MAX_NATIVE_LIBS_PER_APP).sorted().toList()
}
```

- [ ] **Step 4: Run the tests to verify they pass**

```bash
./gradlew testDebugUnitTest --tests "com.androdr.scanner.AppScannerTelemetryTest.extractNativeLibFileNames*"
```

Expected: all four new test cases pass.

- [ ] **Step 5: Commit**

```bash
git add app/src/main/java/com/androdr/scanner/AppScanner.kt \
        app/src/test/java/com/androdr/scanner/AppScannerTelemetryTest.kt
git -c commit.gpgsign=false commit -m "feat(scanner): extract embedded native lib filenames (#168)"
```

### Task 5: Add fields to `AppTelemetry` and wire extractors into `collectTelemetry()`

**Files:**
- Modify: `app/src/main/java/com/androdr/data/model/AppTelemetry.kt`
- Modify: `app/src/main/java/com/androdr/scanner/AppScanner.kt` (`collectTelemetry()`)
- Test: `app/src/test/java/com/androdr/scanner/AppScannerTelemetryTest.kt` (integration test on the full pipeline)

- [ ] **Step 1: Write the failing integration test**

Append to `AppScannerTelemetryTest.kt`:

```kotlin
@Test
fun `collectTelemetry populates embeddedComponentClasses and embeddedNativeLibs`() = runTest {
    // Use the existing test scaffolding to install a stub package via
    // the same `packageManager` mockk that other tests in this file
    // already program. The pattern is: every { packageManager.getInstalledPackages(any()) }
    // returns a list including a PackageInfo whose services/receivers/etc
    // and applicationInfo.publicSourceDir are set to the synthetic APK from buildSyntheticApk.
    //
    // If unsure how the existing `@Before` builds the mock, copy the
    // pattern from `collectTelemetry returns expected metadata for an installed app`
    // (or the closest equivalent already in this file).

    val apk = buildSyntheticApk("integration.apk", listOf("lib/arm64-v8a/libxmode.so"))
    val pkgInfo = PackageInfo().apply {
        packageName = "com.example.broker"
        applicationInfo = ApplicationInfo().apply {
            publicSourceDir = apk.absolutePath
            sourceDir = apk.absolutePath
        }
        services = arrayOf(ServiceInfo().apply { name = "com.outlogic.GeoCollectorService" })
        receivers = null
        activities = arrayOf(ActivityInfo().apply { name = "com.example.broker.MainActivity" })
        providers = null
    }
    every { packageManager.getInstalledPackages(any<Int>()) } returns listOf(pkgInfo)

    val telemetry = scanner.collectTelemetry()

    val entry = telemetry.single { it.packageName == "com.example.broker" }
    assertEquals(
        listOf("com.example.broker.MainActivity", "com.outlogic.GeoCollectorService"),
        entry.embeddedComponentClasses
    )
    assertEquals(listOf("libxmode.so"), entry.embeddedNativeLibs)
}
```

If `every { packageManager.getInstalledPackages(...) }` isn't already set up in this file, match the existing pattern from `AppScannerTelemetryTest` (search the file for `getInstalledPackages` to see how other tests stub it).

- [ ] **Step 2: Run the failing test**

```bash
./gradlew testDebugUnitTest --tests "com.androdr.scanner.AppScannerTelemetryTest.collectTelemetry populates embeddedComponentClasses*"
```

Expected: compile error — `embeddedComponentClasses` and `embeddedNativeLibs` don't exist on `AppTelemetry` yet.

- [ ] **Step 3: Add the two fields to `AppTelemetry`**

Open `app/src/main/java/com/androdr/data/model/AppTelemetry.kt`. Find the data class declaration. Add these two fields **at the end** of the constructor parameter list, both with `= emptyList()` defaults so no existing call sites need updating:

```kotlin
// ... existing fields ...
val firstInstallTime: Long = 0L,
val lastUpdateTime: Long = 0L,
val source: TelemetrySource,
// NEW (#168):
val embeddedComponentClasses: List<String> = emptyList(),
val embeddedNativeLibs: List<String> = emptyList(),
```

If the data class has a trailing field or different shape, the principle is: append, never insert; default to `emptyList()`; no behavior change for callers that don't pass them.

- [ ] **Step 4: Wire the extractors into `collectTelemetry()`**

In `AppScanner.kt`, find the body of `collectTelemetry()` where each `AppTelemetry(...)` is constructed. Just before constructing the `AppTelemetry`, compute:

```kotlin
val embeddedComponentClasses = extractComponentClassNames(packageInfo)
val embeddedNativeLibs = extractNativeLibFileNames(packageInfo.applicationInfo)
```

Then pass them to the constructor:

```kotlin
AppTelemetry(
    // ... existing args ...
    source = TelemetrySource.RUNTIME,
    embeddedComponentClasses = embeddedComponentClasses,
    embeddedNativeLibs = embeddedNativeLibs,
)
```

- [ ] **Step 5: Run the integration test**

```bash
./gradlew testDebugUnitTest --tests "com.androdr.scanner.AppScannerTelemetryTest.collectTelemetry populates embeddedComponentClasses*"
```

Expected: PASS.

- [ ] **Step 6: Run the entire AppScannerTelemetryTest to check nothing else broke**

```bash
./gradlew testDebugUnitTest --tests "com.androdr.scanner.AppScannerTelemetryTest"
```

Expected: all tests pass.

- [ ] **Step 7: Commit**

```bash
git add app/src/main/java/com/androdr/data/model/AppTelemetry.kt \
        app/src/main/java/com/androdr/scanner/AppScanner.kt \
        app/src/test/java/com/androdr/scanner/AppScannerTelemetryTest.kt
git -c commit.gpgsign=false commit -m "feat(scanner): wire embedded-SDK signals into AppTelemetry (#168)"
```

### Task 6: Schema cross-check + lint + full unit test sweep

**Files:** (none modified; this is a verification gate)

- [ ] **Step 1: Run the schema cross-check test**

```bash
./gradlew testDebugUnitTest --tests "com.androdr.sigma.BundledRulesSchemaCrossCheckTest"
```

Expected: PASS. The two new YAML fields (in the bumped submodule) now have matching Kotlin properties on `AppTelemetry`.

If it fails with "field X declared in YAML but not in Kotlin": you misnamed a field — YAML uses `embedded_component_class` / `embedded_native_lib` (snake_case), Kotlin uses `embeddedComponentClasses` / `embeddedNativeLibs` (camelCase). The cross-check converts between cases; if it complains, the case-conversion expects exactly that mapping.

If it fails with "field Y declared in Kotlin but not in YAML": submodule pointer wasn't bumped, or the submodule PR didn't include both fields. Fix and re-run.

- [ ] **Step 2: Run lint**

```bash
./gradlew lintDebug
```

Expected: BUILD SUCCESSFUL. The new code uses only existing project imports and patterns; no new lint baseline should be needed.

- [ ] **Step 3: Run the full unit test suite to catch unrelated regressions**

```bash
./gradlew testDebugUnitTest
```

Expected: all tests pass.

- [ ] **Step 4: Build the debug APK**

```bash
./gradlew assembleDebug
```

Expected: BUILD SUCCESSFUL. APK at `app/build/outputs/apk/debug/app-debug.apk`.

### Task 7: On-device sanity check

**Files:** (none modified; on-device verification)

- [ ] **Step 1: Install the new APK on the test phone**

```bash
ADB=/home/yasir/Android/Sdk/platform-tools/adb
$ADB devices    # confirm device is listed as "device", not "unauthorized"
$ADB install -r app/build/outputs/apk/debug/app-debug.apk
```

Expected: `Success`.

- [ ] **Step 2: Add a one-time debug log so on-device verification is possible**

In `AppScanner.collectTelemetry()`, after building the full `List<AppTelemetry>`, add a debug-only summary log (the spec promises this in the acceptance criteria):

```kotlin
val telemetryList = installed.map { /* ... existing construction ... */ }
Log.d(TAG, "collectTelemetry: ${telemetryList.size} apps, " +
    "${telemetryList.count { it.embeddedComponentClasses.isNotEmpty() }} with components, " +
    "${telemetryList.count { it.embeddedNativeLibs.isNotEmpty() }} with native libs")
return@withContext telemetryList
```

Place this immediately before the existing return statement of `collectTelemetry()`. The exact return shape may vary — match what's already there.

- [ ] **Step 3: Rebuild and reinstall**

```bash
./gradlew assembleDebug
$ADB install -r app/build/outputs/apk/debug/app-debug.apk
```

- [ ] **Step 4: Launch the app + trigger a scan**

```bash
$ADB shell am start -W -n com.androdr.debug/com.androdr.MainActivity
```

Then in the device UI: Dashboard → "Run Scan". Wait for completion (a few seconds on a low-app-count test phone).

- [ ] **Step 5: Confirm the debug log fires with non-zero counts**

```bash
$ADB logcat -d -s AppScanner:D | tail -20
```

Expected: a line of the form `collectTelemetry: N apps, M with components, K with native libs`. `M` should be roughly equal to `N` (every app has at least a launcher activity), and `K` should be at least 1 (Google Play Services / Chrome / similar will have native libs).

If `M == 0`: the wiring in Task 5 didn't take effect; double-check the field is passed to the AppTelemetry constructor.
If `K == 0` on a phone with Google Play Services installed: the ZIP iteration is broken or `applicationInfo.publicSourceDir` is empty; add a transient `Log.d` at the top of `extractNativeLibFileNames` to confirm the path and re-run.

- [ ] **Step 6: Commit the debug log**

```bash
git add app/src/main/java/com/androdr/scanner/AppScanner.kt
git -c commit.gpgsign=false commit -m "chore(scanner): one-time debug log of embedded-SDK signal counts (#168)"
```

### Task 8: Two-reviewer cycle + PR

**Files:** (none modified; review + PR ceremony)

- [ ] **Step 1: Dispatch both reviewers in parallel via the Agent tool**

Use the `Agent` tool to launch **two background agents** with non-overlapping mandates. Use these exact prompt templates (truncate file paths if your wrapper requires it):

**Spec compliance reviewer** (subagent_type: `general-purpose`):

> You are the Spec Compliance Reviewer. Personality: strict, literal. Verify the implementation matches `docs/superpowers/specs/2026-05-17-data-broker-sdk-scanner-design.md` line-by-line. For each acceptance criterion in the spec, point to a file:line where it's implemented. End with VERDICT: PASS or FAIL. Files: `app/src/main/java/com/androdr/data/model/AppTelemetry.kt`, `app/src/main/java/com/androdr/scanner/AppScanner.kt`, `app/src/test/java/com/androdr/scanner/AppScannerTelemetryTest.kt`. Submodule taxonomy change is in `third-party/android-sigma-rules/validation/logsource-taxonomy.yml`.

**Harsh quality reviewer** (subagent_type: `git-pr-workflows:code-reviewer`):

> You are the Harsh Code Quality Reviewer. Personality: skeptical, no participation trophies. Find bugs, footguns, missed edge cases, lifecycle issues. Same files as the spec reviewer. Specifically check: (1) does `extractNativeLibFileNames` correctly handle the AAB / split-APK case where `applicationInfo.splitPublicSourceDirs` carries additional .so files? (2) does `extractComponentClassNames` correctly handle null elements within the services/receivers/activities/providers arrays (mocking permits this; real Android sometimes does too)? (3) does the cap truncation happen BEFORE or AFTER sorting — and which is correct? (4) does the new debug log leak PII? (5) what happens if the same APK is opened concurrently from two threads — is `ZipFile.use` safe? Output: severity-tagged bullet list ending in NO BLOCKERS — APPROVE FOR MERGE or DO NOT APPROVE.

- [ ] **Step 2: Wait for both reviewer notifications**

Don't poll; the harness notifies you when each completes.

- [ ] **Step 3: Triage findings + fix accepted ones**

For each BLOCKER/MAJOR: either accept (fix it in the code, commit with a message like `fix(scanner): <issue> per harsh review (#168)`) or reject with documented reasoning to be cited in the PR body. Mirror the pattern from PR #177's review-triage table.

- [ ] **Step 4: Push the branch**

```bash
git push -u origin feat/168-app-scanner-embedded-sdk-signals
```

- [ ] **Step 5: Open the AndroDR PR**

```bash
gh pr create --base main --head feat/168-app-scanner-embedded-sdk-signals \
  --title "feat(scanner): emit embedded-SDK signals for AppTelemetry (#168)" \
  --body "$(cat <<'EOF'
## Summary

Implements the scanner extension specified in docs/superpowers/specs/2026-05-17-data-broker-sdk-scanner-design.md. Adds two list-typed fields to AppTelemetry — embeddedComponentClasses and embeddedNativeLibs — and the corresponding extraction logic in AppScanner. Prereq for issue #168 (data-broker SDK detection rule pack); rule packs follow in separate PRs.

## What changed

- Submodule bumped: logsource-taxonomy.yml now declares embedded_component_class + embedded_native_lib under app_scanner.fields.
- AppTelemetry: two new list fields, both default emptyList() so no caller breaks.
- AppScanner: two new internal extractors (extractComponentClassNames, extractNativeLibFileNames) called from collectTelemetry().
- Tests: per-extractor unit tests plus a wiring integration test.
- A one-time debug log in collectTelemetry() reports per-scan counts so on-device verification doesn't need a Room round-trip.

## Two-reviewer cycle
- Spec reviewer verdict + evidence
- Harsh reviewer findings + triage table

## Test plan
- ./gradlew testDebugUnitTest — all tests pass (count: ___)
- ./gradlew lintDebug — BUILD SUCCESSFUL
- ./gradlew assembleDebug — BUILD SUCCESSFUL
- adb install on Z Fold 2 (R3CR300WRRH) — Success; logcat shows non-zero component/native-lib counts

Closes nothing yet — issue #168 stays open. This is the first of several PRs.

Refs #168
EOF
)"
```

- [ ] **Step 6: Admin-merge (GHA is out of budget per CLAUDE.md memory)**

```bash
gh pr merge --admin --squash --delete-branch
```

- [ ] **Step 7: Sync local main**

```bash
git checkout main
git pull --ff-only origin main
git log --oneline -3
```

Expected: the squash-merge commit at HEAD, with the matching `feat(scanner)` subject.

---

## Done criteria

- Submodule PR merged with the two new taxonomy entries.
- AndroDR PR merged with the AppTelemetry + AppScanner changes.
- `BundledRulesSchemaCrossCheckTest` passes.
- On-device debug log confirms non-zero embedded-component and native-lib counts.
- Two-reviewer cycle completed with all BLOCKERs and MAJORs resolved or documented as rejected.

After this lands, the next session can brainstorm the **SIR research** sub-spec (which broker SDKs to fingerprint, what evidence per SDK), then move on to authoring the `installed_app` rule pack that consumes these new fields.
