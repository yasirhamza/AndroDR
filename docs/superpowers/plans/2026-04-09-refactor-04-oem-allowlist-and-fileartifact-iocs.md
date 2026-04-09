# Refactor Plan 4: OEM Allowlist + FileArtifactScanner IOC Migration

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Parent refactor:** Unified telemetry/findings architecture (#84). Spec: `docs/superpowers/specs/2026-04-09-unified-telemetry-findings-refactor-design.md`, §9.

**Plan order:** Plan 4 of 7. Starts after plan 3's final commit. Serialized execution on `claude/unified-telemetry-findings-refactor`.

**Goal:** Add Unisoc/SPRD chipset prefixes to `known_oem_prefixes.yml` (fixes the Redmi A5 false-positive that motivated the entire refactor). Migrate `FileArtifactScanner`'s hardcoded Pegasus/Predator path list from Kotlin to a YAML resource `known_spyware_artifacts.yml`. Introduce `KnownSpywareArtifactsResolver` (mirrors the existing `OemPrefixResolver` pattern). The rule `sigma_androdr_020_spyware_artifact` continues to evaluate the telemetry unchanged — only the Kotlin→YAML data migration is in scope.

**Architecture:** Detection data lives in YAML resources, loaded once at startup by a Hilt-injected resolver, and injected into the scanner that needs it. This mirrors the existing pattern used by `OemPrefixResolver` for the OEM prefix list. The scanner itself remains simple: for each path in the resolver, check if the file exists and emit telemetry.

**Tech Stack:** Kotlin, Hilt, YAML parser (already present, used by SIGMA rules and OEM prefixes), JUnit 4 + MockK.

**Acceptance criteria:**
- `known_oem_prefixes.yml` includes `com.unisoc.`, `com.sprd.`, `vendor.unisoc.`, `vendor.sprd.` under the `chipset_prefixes` section.
- New file `app/src/main/res/raw/known_spyware_artifacts.yml` exists, containing the 5 current hardcoded paths from `FileArtifactScanner.kt:32-38` plus metadata (family, source attribution, first-observed date where known).
- New class `KnownSpywareArtifactsResolver` loads the YAML, resolves template placeholders (`{ext_storage}`), exposes `fun paths(): List<String>`.
- `FileArtifactScanner` uses the resolver via Hilt injection; the hardcoded `knownArtifactPaths` Kotlin constant is removed.
- Existing rule `sigma_androdr_020_spyware_artifact.yml` unchanged.
- Unit test for `KnownSpywareArtifactsResolver` verifying loading, parsing, and template resolution.
- Regression test: pre- and post-refactor, `FileArtifactScanner` returns the same set of paths for a clean device.
- All gradle checks pass.
- No rule YAML changes except the new `known_spyware_artifacts.yml`.
- No sigma package changes.

---

## File Structure

### Created

- `app/src/main/res/raw/known_spyware_artifacts.yml` — YAML resource with 5 current Pegasus/Predator paths + metadata
- `app/src/main/java/com/androdr/ioc/KnownSpywareArtifactsResolver.kt` — Hilt-injected resolver
- `app/src/test/java/com/androdr/ioc/KnownSpywareArtifactsResolverTest.kt` — unit test

### Modified

- `app/src/main/res/raw/known_oem_prefixes.yml` — add Unisoc/SPRD chipset prefixes
- `app/src/main/java/com/androdr/scanner/FileArtifactScanner.kt` — remove hardcoded path list, inject resolver
- `app/src/test/java/com/androdr/scanner/FileArtifactScannerTest.kt` (if exists) — update test to use resolver mock

### Not touched

- `sigma_androdr_020_spyware_artifact.yml` — rule evaluates telemetry unchanged
- Any other rule YAML
- Any sigma package code
- Any data model code
- Any UI code

---

## Phase A: Add Unisoc/SPRD to OEM Allowlist

### Task A1: Edit `known_oem_prefixes.yml`

**Files:**
- Modify: `app/src/main/res/raw/known_oem_prefixes.yml`

- [ ] **Step 1: Read the current file**

```bash
cd /home/yasir/AndroDR
cat app/src/main/res/raw/known_oem_prefixes.yml | head -60
```

Locate the `chipset_prefixes` section. Current contents (from plan 1 audit):

```yaml
chipset_prefixes:
  - "com.qualcomm."
  - "com.qti."
  - "vendor.qti."
  - "com.mediatek."
  - "com.mtk."
```

- [ ] **Step 2: Add Unisoc / SPRD entries**

Append to the `chipset_prefixes` section:

```yaml
chipset_prefixes:
  - "com.qualcomm."
  - "com.qti."
  - "vendor.qti."
  - "com.mediatek."
  - "com.mtk."
  - "com.unisoc."
  - "com.sprd."
  - "vendor.unisoc."
  - "vendor.sprd."
```

(SPRD = Spreadtrum, the legacy brand name for what's now Unisoc. Many existing Unisoc-based devices ship with packages using either prefix depending on firmware age.)

- [ ] **Step 3: Verify the other sections are untouched**

```bash
git diff app/src/main/res/raw/known_oem_prefixes.yml
```

Expected: only the 4 new lines added under `chipset_prefixes`. Nothing else changed.

- [ ] **Step 4: Compile + tests** (sanity check)

```bash
export JAVA_HOME=/home/yasir/Applications/android-studio/jbr
./gradlew compileDebugKotlin 2>&1 | tail -5
./gradlew testDebugUnitTest 2>&1 | tail -15
```

Expected: BUILD SUCCESSFUL. The YAML is resource-loaded at runtime so compilation is unaffected; the real verification would be manual (install on a Unisoc device and confirm the false positives are gone), but that's deferred to plan 7's regression fixture.

- [ ] **Step 5: Commit**

```bash
git add app/src/main/res/raw/known_oem_prefixes.yml
git commit -m "fix(oem): add Unisoc and SPRD chipset prefixes to allowlist (#84)

The tester-provided bugreport that motivated this refactor came from
a Unisoc-based Android device, and the report showed com.unisoc.*
system firmware packages being flagged as HIGH-risk third-party apps.
Root cause: the OEM allowlist at known_oem_prefixes.yml had entries
for Qualcomm and MediaTek chipsets but not Unisoc/SPRD.

Adds:
- com.unisoc.
- com.sprd.          (legacy Spreadtrum brand, still used in older firmware)
- vendor.unisoc.
- vendor.sprd.

Every rule that filters on is_known_oem_app via OemPrefixResolver
now correctly classifies com.unisoc.* packages as OEM/system and
suppresses spurious alerts.

This is the one-line fix for the tester's false-positive report.
The architectural work to prevent this class of bug (move allowlists
out of hardcoded Kotlin in 3 bugreport modules) happens in plan 5.

Part of #84 (plan 4, phase A)."
```

---

## Phase B: `known_spyware_artifacts.yml` Resource File

### Task B1: Create the YAML resource

**Files:**
- Create: `app/src/main/res/raw/known_spyware_artifacts.yml`

- [ ] **Step 1: Read the current hardcoded list**

```bash
cat app/src/main/java/com/androdr/scanner/FileArtifactScanner.kt
```

Find the `knownArtifactPaths` list. From the plan 1 audit, it contains:

```kotlin
private val knownArtifactPaths: List<String> by lazy {
    val extStorage = Environment.getExternalStorageDirectory().absolutePath
    listOf(
        "/data/local/tmp/.raptor",
        "/data/local/tmp/.stat",
        "/data/local/tmp/.mobilesoftwareupdate",
        "$extStorage/.hidden_config",
        "$extStorage/Android/data/.system_update"
    )
}
```

Verify the exact list matches (it may have changed since the audit).

- [ ] **Step 2: Write the YAML resource**

Create `app/src/main/res/raw/known_spyware_artifacts.yml` with this content:

```yaml
# Known spyware file artifacts.
#
# Paths associated with mercenary spyware, stalkerware, and forensic tools.
# Evaluated by sigma_androdr_020_spyware_artifact.yml against FileArtifactTelemetry.
#
# Path templates:
# - {ext_storage} resolves at runtime to Environment.getExternalStorageDirectory().absolutePath
#
# Sources:
# - mvt: Amnesty International's Mobile Verification Toolkit
# - citizen-lab: The Citizen Lab (University of Toronto)
# - androdr-research: AndroDR's own threat research
#
# See docs/superpowers/specs/2026-04-09-unified-telemetry-findings-refactor-design.md §9
# for the migration from hardcoded Kotlin constants to this YAML resource.

version: "2026-04-09"
last_reviewed: "2026-04-09"

artifacts:
  - path: "/data/local/tmp/.raptor"
    family: "pegasus"
    source: "citizen-lab"
    first_observed: "2021-07-18"

  - path: "/data/local/tmp/.stat"
    family: "pegasus"
    source: "mvt"

  - path: "/data/local/tmp/.mobilesoftwareupdate"
    family: "pegasus"
    source: "mvt"

  - path: "{ext_storage}/.hidden_config"
    family: "generic_stalkerware"
    source: "androdr-research"

  - path: "{ext_storage}/Android/data/.system_update"
    family: "generic_stalkerware"
    source: "androdr-research"
```

- [ ] **Step 3: No commit yet** — combine with the resolver creation in the next task.

---

## Phase C: `KnownSpywareArtifactsResolver`

### Task C1: Inspect the existing `OemPrefixResolver` pattern

- [ ] **Step 1: Read it**

```bash
cat app/src/main/java/com/androdr/ioc/OemPrefixResolver.kt
```

Note the pattern: Hilt-injected `@Singleton`, takes `@ApplicationContext Context`, loads the YAML from `R.raw.known_oem_prefixes` via resource ID, parses with the project's existing YAML parser, exposes typed accessors.

Understand: which YAML library is used, how the resource ID is referenced (via `R.raw.known_spyware_artifacts` will be auto-generated at build time), and the error handling for malformed files.

### Task C2: Create the resolver class

**Files:**
- Create: `app/src/main/java/com/androdr/ioc/KnownSpywareArtifactsResolver.kt`

- [ ] **Step 1: Write the file**

Adapt to the exact YAML library and Hilt conventions used by `OemPrefixResolver`. The outline:

```kotlin
package com.androdr.ioc

import android.content.Context
import android.os.Environment
import com.androdr.R
import dagger.hilt.android.qualifiers.ApplicationContext
import javax.inject.Inject
import javax.inject.Singleton
// + whatever YAML library import OemPrefixResolver uses

/**
 * Loads the known spyware artifact path list from `res/raw/known_spyware_artifacts.yml`
 * and exposes the resolved paths for [FileArtifactScanner] to probe.
 *
 * The YAML file lives in `app/src/main/res/raw/` and is the authoritative
 * source of known spyware file paths — previously hardcoded in
 * `FileArtifactScanner.kt`. Moving to YAML lets the `update-rules` agents
 * add new paths from threat intel feeds without touching Kotlin.
 *
 * Path templates:
 * - `{ext_storage}` is resolved to [Environment.getExternalStorageDirectory].
 *
 * See `docs/superpowers/specs/2026-04-09-unified-telemetry-findings-refactor-design.md`
 * §9 for the full rationale.
 */
@Singleton
class KnownSpywareArtifactsResolver @Inject constructor(
    @ApplicationContext private val context: Context,
) {

    /**
     * Resolved absolute paths for the scanner to probe. Computed lazily on
     * first access; subsequent calls return the cached list.
     */
    val paths: List<String> by lazy {
        loadAndResolve()
    }

    private fun loadAndResolve(): List<String> {
        val yamlString = context.resources.openRawResource(R.raw.known_spyware_artifacts)
            .bufferedReader()
            .use { it.readText() }

        // Parse YAML into a Map / List structure using the project's existing
        // parser. The exact API depends on which YAML library is used — adapt
        // to match OemPrefixResolver's pattern.
        val parsed = parseYaml(yamlString)
        val artifacts = parsed["artifacts"] as? List<Map<String, Any>> ?: emptyList()

        val extStorage = Environment.getExternalStorageDirectory().absolutePath

        return artifacts.mapNotNull { entry ->
            val pathTemplate = entry["path"] as? String ?: return@mapNotNull null
            pathTemplate.replace("{ext_storage}", extStorage)
        }
    }

    private fun parseYaml(yaml: String): Map<String, Any> {
        // Use whatever YAML library OemPrefixResolver uses.
        // This is a placeholder — replace with the actual parser call.
        TODO("adapt to project YAML parser")
    }
}
```

**Important**: the `parseYaml` stub must be replaced with the actual YAML parsing call used elsewhere in the project (e.g. snakeyaml, kaml, or a custom parser). Read `OemPrefixResolver.kt` first to see what it uses, and copy the same pattern exactly. Do not introduce a new dependency.

- [ ] **Step 2: Compile**

```bash
./gradlew compileDebugKotlin 2>&1 | tail -5
```
Expected: BUILD SUCCESSFUL. If compilation fails because the YAML library isn't on the classpath for the ioc package, check the existing imports in `OemPrefixResolver.kt` and add whatever dependency is needed (but don't add a new library — use what's already there).

### Task C3: Unit test for the resolver

**Files:**
- Create: `app/src/test/java/com/androdr/ioc/KnownSpywareArtifactsResolverTest.kt`

- [ ] **Step 1: Check existing test patterns**

```bash
find app/src/test -name "OemPrefixResolver*Test*.kt"
```

If a test exists for `OemPrefixResolver`, read it and copy the pattern.

- [ ] **Step 2: Write the test**

```kotlin
package com.androdr.ioc

import android.content.Context
import android.content.res.Resources
import android.os.Environment
import com.androdr.R
import io.mockk.every
import io.mockk.mockk
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream

class KnownSpywareArtifactsResolverTest {

    private val sampleYaml = """
        version: "2026-04-09"
        artifacts:
          - path: "/data/local/tmp/.raptor"
            family: "pegasus"
            source: "citizen-lab"
          - path: "/data/local/tmp/.stat"
            family: "pegasus"
            source: "mvt"
          - path: "{ext_storage}/.hidden_config"
            family: "generic_stalkerware"
            source: "androdr-research"
    """.trimIndent()

    @Test
    fun `resolver loads and resolves artifact paths from YAML`() {
        val context = mockk<Context>(relaxed = true)
        val resources = mockk<Resources>(relaxed = true)
        every { context.resources } returns resources
        every { resources.openRawResource(R.raw.known_spyware_artifacts) } returns
            ByteArrayInputStream(sampleYaml.toByteArray())

        val resolver = KnownSpywareArtifactsResolver(context)
        val paths = resolver.paths

        assertEquals(3, paths.size)
        assertTrue(paths.contains("/data/local/tmp/.raptor"))
        assertTrue(paths.contains("/data/local/tmp/.stat"))
        // The {ext_storage} template should be resolved to some absolute path
        assertTrue(paths.any { it.endsWith("/.hidden_config") })
    }

    @Test
    fun `resolver caches paths after first access`() {
        val context = mockk<Context>(relaxed = true)
        val resources = mockk<Resources>(relaxed = true)
        every { context.resources } returns resources

        var openCallCount = 0
        every { resources.openRawResource(R.raw.known_spyware_artifacts) } answers {
            openCallCount++
            ByteArrayInputStream(sampleYaml.toByteArray())
        }

        val resolver = KnownSpywareArtifactsResolver(context)
        repeat(3) { resolver.paths }

        assertEquals("Expected the resolver to cache and call openRawResource exactly once", 1, openCallCount)
    }
}
```

Note: `Environment.getExternalStorageDirectory()` is Android SDK code and won't work in a pure JUnit test. The test's third assertion should accept that the resolved path ends with `/.hidden_config` without asserting the specific prefix. If mocking `Environment` is easy with the project's test setup, use it; otherwise accept the loose assertion.

- [ ] **Step 3: Run the test**

```bash
./gradlew testDebugUnitTest --tests "com.androdr.ioc.KnownSpywareArtifactsResolverTest" 2>&1 | tail -15
```
Expected: BUILD SUCCESSFUL, 2 tests pass.

If there are issues with `Environment.getExternalStorageDirectory()` in the test (likely, since it's an Android SDK call), either:
- Inject a `getExternalStoragePath: () -> String` lambda into the resolver constructor for testability
- Use Robolectric if the project has it set up
- Skip the specific test assertion about the template resolution and only assert list size + the two unchanged paths

Adapt as needed — correctness of the assertions matters more than the specific technique.

### Task C4: Commit B + C

```bash
git add app/src/main/res/raw/known_spyware_artifacts.yml \
        app/src/main/java/com/androdr/ioc/KnownSpywareArtifactsResolver.kt \
        app/src/test/java/com/androdr/ioc/KnownSpywareArtifactsResolverTest.kt
git commit -m "feat(ioc): KnownSpywareArtifactsResolver loads paths from YAML (#84)

New Hilt-injected resolver that reads known spyware file paths from
res/raw/known_spyware_artifacts.yml instead of the hardcoded list
currently in FileArtifactScanner.kt. Template {ext_storage} is
resolved at runtime to the device's external storage directory.

The YAML resource contains the 5 Pegasus/Predator artifacts currently
hardcoded plus metadata (family, source attribution, first-observed
date where known). Moving to YAML lets the update-rules agents add
new paths from threat intel feeds without touching Kotlin code.

The existing rule sigma_androdr_020_spyware_artifact.yml continues
to evaluate FileArtifactTelemetry unchanged — the migration is purely
data, not rules.

FileArtifactScanner is wired to use this resolver in the next commit.

Part of #84 (plan 4, phase B+C)."
```

---

## Phase D: Refactor `FileArtifactScanner`

### Task D1: Inject the resolver and remove hardcoded paths

**Files:**
- Modify: `app/src/main/java/com/androdr/scanner/FileArtifactScanner.kt`

- [ ] **Step 1: Read the current scanner**

```bash
cat app/src/main/java/com/androdr/scanner/FileArtifactScanner.kt
```

Note its constructor signature, the `knownArtifactPaths` constant, and how it iterates the paths.

- [ ] **Step 2: Update the constructor to accept the resolver**

The current class likely looks like:

```kotlin
@Singleton
class FileArtifactScanner @Inject constructor() {
    private val knownArtifactPaths: List<String> by lazy { ... }
    fun scan(): List<FileArtifactTelemetry> { ... }
}
```

Change to:

```kotlin
@Singleton
class FileArtifactScanner @Inject constructor(
    private val knownSpywareArtifactsResolver: KnownSpywareArtifactsResolver,
) {
    fun scan(): List<FileArtifactTelemetry> {
        return knownSpywareArtifactsResolver.paths.map { path ->
            val file = File(path)
            val exists = file.exists()
            FileArtifactTelemetry(
                filePath = path,
                fileExists = exists,
                fileSize = if (exists) file.length() else null,
                fileModified = if (exists) file.lastModified() else null,
                source = TelemetrySource.LIVE_SCAN,
            )
        }
    }
}
```

Delete the `knownArtifactPaths` lazy property and its backing code.

- [ ] **Step 3: Verify imports**

Remove `import android.os.Environment` if it's no longer used. Add `import com.androdr.ioc.KnownSpywareArtifactsResolver`.

- [ ] **Step 4: Compile**

```bash
./gradlew compileDebugKotlin 2>&1 | tail -10
```

Expected: BUILD SUCCESSFUL. If Hilt complains about missing bindings, it's probably because `KnownSpywareArtifactsResolver` isn't discoverable yet — verify `@Singleton` and `@Inject constructor` are both present.

### Task D2: Update the FileArtifactScanner test (if one exists)

**Files:**
- Modify: `app/src/test/java/com/androdr/scanner/FileArtifactScannerTest.kt` (if present) or a relevant test file

- [ ] **Step 1: Find existing tests**

```bash
find app/src/test -name "FileArtifactScanner*Test*.kt"
```

- [ ] **Step 2: Update tests to use the resolver mock**

If the test instantiated `FileArtifactScanner()` directly, it now needs a `KnownSpywareArtifactsResolver` mock:

```kotlin
private val mockResolver = mockk<KnownSpywareArtifactsResolver> {
    every { paths } returns listOf(
        "/data/local/tmp/.raptor",
        "/data/local/tmp/.stat",
        "/data/local/tmp/.mobilesoftwareupdate",
        "/sdcard/.hidden_config",
        "/sdcard/Android/data/.system_update",
    )
}

private val scanner = FileArtifactScanner(mockResolver)
```

If no test existed for `FileArtifactScanner`, create a minimal one:

```kotlin
package com.androdr.scanner

import com.androdr.data.model.TelemetrySource
import com.androdr.ioc.KnownSpywareArtifactsResolver
import io.mockk.every
import io.mockk.mockk
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class FileArtifactScannerTest {

    private val mockResolver = mockk<KnownSpywareArtifactsResolver> {
        every { paths } returns listOf(
            "/data/local/tmp/.test_not_a_real_file_1",
            "/data/local/tmp/.test_not_a_real_file_2",
        )
    }

    private val scanner = FileArtifactScanner(mockResolver)

    @Test
    fun `scanner emits one telemetry row per resolver path`() {
        val result = scanner.scan()
        assertEquals(2, result.size)
    }

    @Test
    fun `scanner sets source = LIVE_SCAN on all emitted telemetry`() {
        val result = scanner.scan()
        assertTrue(result.all { it.source == TelemetrySource.LIVE_SCAN })
    }

    @Test
    fun `scanner reports non-existent files as fileExists = false`() {
        val result = scanner.scan()
        // These paths don't exist on the test runner filesystem
        assertTrue(result.all { !it.fileExists })
        assertTrue(result.all { it.fileSize == null })
    }
}
```

- [ ] **Step 3: Run the tests**

```bash
./gradlew testDebugUnitTest --tests "com.androdr.scanner.FileArtifactScannerTest" 2>&1 | tail -15
```
Expected: BUILD SUCCESSFUL.

### Task D3: Regression test — pre/post path set parity

- [ ] **Step 1: Add a single assertion confirming the 5 expected paths survive the migration**

Add to `KnownSpywareArtifactsResolverTest` (or `FileArtifactScannerTest` — whichever makes more sense):

```kotlin
@Test
fun `resolver returns exactly the 5 paths previously hardcoded in FileArtifactScanner`() {
    // Use the real resource file, not the inline sample.
    // If this requires Robolectric or Android Context, skip this specific test
    // and rely on the inline sample tests for CI coverage.

    // Expected list — was hardcoded in FileArtifactScanner.kt:32-38 before the refactor
    val expectedPaths = setOf(
        "/data/local/tmp/.raptor",
        "/data/local/tmp/.stat",
        "/data/local/tmp/.mobilesoftwareupdate",
        // The two {ext_storage} templates can't be asserted exactly without
        // Android environment — assert they have the expected suffix
    )

    // ... assertion logic
}
```

If this test is too awkward in pure unit-test land (because the real resource loads via Android's resource system), document in a comment that the test relies on the inline sample already exercising the same code path. The important thing is proving the resolver correctly reads the YAML structure — whether it reads it from `res/raw` or an inline string is an implementation detail.

### Task D4: Commit phase D

```bash
git add app/src/main/java/com/androdr/scanner/FileArtifactScanner.kt \
        app/src/test/java/com/androdr/scanner/FileArtifactScannerTest.kt
git commit -m "refactor(scanner): FileArtifactScanner reads paths from YAML resolver (#84)

Removes the hardcoded knownArtifactPaths Kotlin constant from
FileArtifactScanner.kt. The scanner now takes a KnownSpywareArtifactsResolver
via Hilt constructor injection and iterates the resolver's resolved path
list (5 paths today, potentially more when update-rules agents append to
the YAML).

The detection rule sigma_androdr_020_spyware_artifact.yml continues to
evaluate the emitted FileArtifactTelemetry unchanged. This refactor is
pure data migration: Kotlin constant → YAML resource.

Part of #84 (plan 4, phase D)."
```

---

## Phase E: Final Verification

### Task E1: Run all gradle checks

```bash
export JAVA_HOME=/home/yasir/Applications/android-studio/jbr
cd /home/yasir/AndroDR

./gradlew testDebugUnitTest 2>&1 | tail -20
./gradlew lintDebug 2>&1 | tail -10
./gradlew assembleDebug 2>&1 | tail -5
./gradlew detekt 2>&1 | tail -10
```
All four must be BUILD SUCCESSFUL.

### Task E2: Invariant checks

- [ ] **Check 1: Unisoc/SPRD present in allowlist**

```bash
grep -c "com.unisoc.\|com.sprd.\|vendor.unisoc.\|vendor.sprd." app/src/main/res/raw/known_oem_prefixes.yml
```
Expected: 4.

- [ ] **Check 2: No hardcoded artifact paths in FileArtifactScanner**

```bash
grep -n "raptor\|mobilesoftwareupdate\|hidden_config\|system_update" app/src/main/java/com/androdr/scanner/FileArtifactScanner.kt
```
Expected: zero hits (all paths moved to YAML).

- [ ] **Check 3: YAML resource exists and parses**

```bash
ls app/src/main/res/raw/known_spyware_artifacts.yml
cat app/src/main/res/raw/known_spyware_artifacts.yml | head -20
```
Expected: file exists, has the expected structure.

- [ ] **Check 4: Resolver exists and is Hilt-injectable**

```bash
ls app/src/main/java/com/androdr/ioc/KnownSpywareArtifactsResolver.kt
grep "@Singleton\|@Inject" app/src/main/java/com/androdr/ioc/KnownSpywareArtifactsResolver.kt
```
Expected: file exists, has `@Singleton` annotation and `@Inject constructor`.

- [ ] **Check 5: FileArtifactScanner uses the resolver**

```bash
grep "KnownSpywareArtifactsResolver" app/src/main/java/com/androdr/scanner/FileArtifactScanner.kt
```
Expected: at least one reference (constructor injection).

- [ ] **Check 6: No rule YAML files modified**

```bash
git diff 3f36439..HEAD -- 'app/src/main/res/raw/sigma_androdr_*.yml'
```
Expected: empty.

- [ ] **Check 7: No sigma package files modified**

```bash
git diff 3f36439..HEAD -- app/src/main/java/com/androdr/sigma/
```
Expected: empty.

### Task E3: Working tree clean + commit log

```bash
git status
git log 3f36439..HEAD --oneline
```
Expected: clean tree, 3-5 commits for plan 4.

---

## Plan 4 Retrospective Checklist

- [ ] `com.unisoc.`, `com.sprd.`, `vendor.unisoc.`, `vendor.sprd.` added to `known_oem_prefixes.yml`
- [ ] `known_spyware_artifacts.yml` exists with 5 paths + metadata
- [ ] `KnownSpywareArtifactsResolver` created, Hilt-injectable, loads YAML, resolves `{ext_storage}` template
- [ ] Unit test for the resolver passes
- [ ] `FileArtifactScanner` no longer has hardcoded paths
- [ ] `FileArtifactScanner` takes the resolver via constructor injection
- [ ] `FileArtifactScanner` test updated or added
- [ ] `sigma_androdr_020_spyware_artifact.yml` unchanged
- [ ] No sigma package changes
- [ ] All gradle checks pass

---

**End of plan 4.**
