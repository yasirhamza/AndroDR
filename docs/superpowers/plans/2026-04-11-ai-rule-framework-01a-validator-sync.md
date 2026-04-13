# Validator Sync + Build-time Gate — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the drift loop between the dev pipeline and AI-powered rule updater by syncing the validator schema and adding a build-time cross-check gate.

**Architecture:** `android-sigma-rules` is the authoritative schema source, brought into AndroDR via git submodule at `third-party/android-sigma-rules/`. A new Kotlin unit test cross-checks every bundled detection/atom rule against both `SigmaRuleParser.parse()` and the JSON schema using `com.networknt:json-schema-validator:2.0.1`. The build fails if they disagree.

**Tech Stack:** Kotlin (JVM unit tests), snakeyaml-engine (existing), com.networknt:json-schema-validator + Jackson (new test deps), Python (validate-rule.py — unchanged logic), git submodules.

**Spec:** `docs/superpowers/specs/2026-04-11-validator-sync-and-build-time-gate.md`  
**Tracking issue:** #105  

---

## File Map

### `android-sigma-rules` repo (upstream)

| Action | File | Responsibility |
|--------|------|----------------|
| Modify | `validation/rule-schema.json` | Add `category` required, expand service enum, add optional fields |
| Modify | `validation/validate-rule.py` | Sync `valid_services` whitelist (line 63) |

### `AndroDR` repo (main app)

| Action | File | Responsibility |
|--------|------|----------------|
| Create | `.gitmodules` | Register submodule |
| Create | `third-party/android-sigma-rules/` | Submodule checkout (pinned SHA) |
| Modify | `app/build.gradle.kts` | Add `testImplementation` for json-schema-validator |
| Create | `app/src/test/java/com/androdr/sigma/BundledRulesSchemaCrossCheckTest.kt` | Build-time cross-check gate |
| Modify | `.github/workflows/android-build.yml` | Add submodule init step |
| Modify | `CLAUDE.md` | Document submodule workflow |

---

## Task 1: Update `rule-schema.json` in `android-sigma-rules`

**Files:**
- Modify: `/home/yasir/android-sigma-rules/validation/rule-schema.json`

- [ ] **Step 1: Replace rule-schema.json with the synced version**

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "AndroDR SIGMA Rule",
  "type": "object",
  "required": ["title", "id", "status", "description", "logsource", "detection", "level", "tags", "category"],
  "properties": {
    "title": { "type": "string", "minLength": 1 },
    "id": { "type": "string", "pattern": "^androdr-(\\d{3}|atom-[a-z-]+|corr-\\d{3})$" },
    "status": { "type": "string", "enum": ["experimental", "test", "production"] },
    "description": { "type": "string" },
    "author": { "type": "string" },
    "date": { "type": "string" },
    "references": { "type": "array", "items": { "type": "string" } },
    "category": { "type": "string", "enum": ["incident", "device_posture"] },
    "enabled": { "type": "boolean" },
    "report_safe_state": { "type": "boolean" },
    "logsource": {
      "type": "object",
      "required": ["product", "service"],
      "properties": {
        "product": { "const": "androdr" },
        "service": {
          "type": "string",
          "enum": [
            "app_scanner", "device_auditor", "dns_monitor",
            "process_monitor", "file_scanner",
            "receiver_audit", "tombstone_parser",
            "accessibility", "appops", "network_monitor"
          ]
        }
      }
    },
    "detection": {
      "type": "object",
      "required": ["condition"],
      "properties": {
        "condition": { "type": "string", "minLength": 1 }
      }
    },
    "level": { "type": "string", "enum": ["critical", "high", "medium", "low"] },
    "tags": {
      "type": "array",
      "items": { "type": "string" }
    },
    "falsepositives": { "type": "array", "items": { "type": "string" } },
    "remediation": { "type": "array", "items": { "type": "string" } },
    "display": {
      "type": "object",
      "properties": {
        "category": { "type": "string", "enum": ["app_risk", "device_posture", "network"] },
        "icon": { "type": "string" },
        "triggered_title": { "type": "string" },
        "safe_title": { "type": "string" },
        "evidence_type": { "type": "string", "enum": ["none", "cve_list", "ioc_match", "permission_cluster"] },
        "summary_template": { "type": "string" },
        "guidance": { "type": "string" }
      }
    }
  }
}
```

- [ ] **Step 2: Verify the JSON is valid**

Run: `cd /home/yasir/android-sigma-rules && python3 -c "import json; json.load(open('validation/rule-schema.json'))"`

Expected: No output (successful parse).

---

## Task 2: Update `validate-rule.py` in `android-sigma-rules`

**Files:**
- Modify: `/home/yasir/android-sigma-rules/validation/validate-rule.py` (line 63)

- [ ] **Step 1: Update the `valid_services` set**

Replace line 63:
```python
    valid_services = {"app_scanner", "device_auditor", "dns_monitor", "process_monitor", "file_scanner"}
```

With:
```python
    valid_services = {
        "app_scanner", "device_auditor", "dns_monitor",
        "process_monitor", "file_scanner",
        "receiver_audit", "tombstone_parser",
        "accessibility", "appops", "network_monitor",
    }
```

- [ ] **Step 2: Run the validator against all rules in the sigma-rules repo**

Run:
```bash
cd /home/yasir/android-sigma-rules
for dir in app_scanner device_auditor dns_monitor file_scanner process_monitor receiver_audit; do
  for f in "$dir"/*.yml; do
    [ -f "$f" ] && python3 validation/validate-rule.py "$f"
  done
done
```

Expected: All files print `PASS: <filename>`.

- [ ] **Step 3: Run the validator against the 5 staging rules (preview for sub-plan 1c)**

Run:
```bash
cd /home/yasir/android-sigma-rules
for f in staging/*/*.yml; do
  python3 validation/validate-rule.py "$f" 2>&1 || true
done
```

Expected: Some will fail on missing `category` field — this is expected and documents what 1c needs to fix. Capture the output for reference.

- [ ] **Step 4: Commit and push**

```bash
cd /home/yasir/android-sigma-rules
git add validation/rule-schema.json validation/validate-rule.py
git commit -m "fix: sync rule-schema.json and validate-rule.py with AndroDR runtime

Add category to required fields (incident | device_posture).
Expand logsource.service enum to include all 10 telemetry services.
Add optional fields: enabled, report_safe_state, display.guidance.
Sync validate-rule.py valid_services whitelist.

Part of yasirhamza/AndroDR#105"
git push origin main
```

---

## Task 3: Add git submodule to AndroDR

**Files:**
- Create: `/home/yasir/AndroDR/.gitmodules`
- Create: `/home/yasir/AndroDR/third-party/android-sigma-rules/` (submodule)

- [ ] **Step 1: Add the submodule**

Run:
```bash
cd /home/yasir/AndroDR
git submodule add https://github.com/android-sigma-rules/rules.git third-party/android-sigma-rules
```

Expected: Creates `.gitmodules` and clones the repo into `third-party/android-sigma-rules/`.

- [ ] **Step 2: Verify the submodule contains the updated schema**

Run:
```bash
grep '"category"' third-party/android-sigma-rules/validation/rule-schema.json | head -1
```

Expected: Shows the `"category"` property line from the updated schema. If it shows the OLD schema (without category in required), the submodule needs to be updated to the latest commit:
```bash
cd third-party/android-sigma-rules && git pull origin main && cd ../..
```

- [ ] **Step 3: Commit the submodule addition**

```bash
cd /home/yasir/AndroDR
git add .gitmodules third-party/android-sigma-rules
git commit -m "build: add android-sigma-rules as git submodule at third-party/

Establishes the sigma-rules repo as the authoritative schema source.
The build-time cross-check test (next commit) reads rule-schema.json
from this submodule to validate bundled rules.

Part of #105"
```

---

## Task 4: Add json-schema-validator test dependency

**Files:**
- Modify: `/home/yasir/AndroDR/app/build.gradle.kts` (dependencies block)

- [ ] **Step 1: Add the dependency**

Add after the existing `testImplementation(libs.org.json)` line (around line 208):

```kotlin
    testImplementation("com.networknt:json-schema-validator:2.0.1")
```

- [ ] **Step 2: Verify Gradle resolves the dependency**

Run:
```bash
cd /home/yasir/AndroDR
./gradlew app:dependencies --configuration testDebugRuntimeClasspath 2>&1 | grep networknt
```

Expected: Shows `com.networknt:json-schema-validator:2.0.1` in the dependency tree.

- [ ] **Step 3: Commit**

```bash
cd /home/yasir/AndroDR
git add app/build.gradle.kts
git commit -m "build: add json-schema-validator test dependency for cross-check gate

com.networknt:json-schema-validator:2.0.1 (pure JVM, JSON Schema draft
2020-12). Used by BundledRulesSchemaCrossCheckTest to validate bundled
rules against rule-schema.json from the submodule. Test-only scope —
Jackson transitive dep does not affect production classpath.

Part of #105"
```

---

## Task 5: Write `BundledRulesSchemaCrossCheckTest.kt`

**Files:**
- Create: `/home/yasir/AndroDR/app/src/test/java/com/androdr/sigma/BundledRulesSchemaCrossCheckTest.kt`

- [ ] **Step 1: Write the complete test class**

```kotlin
package com.androdr.sigma

import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import com.networknt.schema.JsonSchemaFactory
import com.networknt.schema.SpecVersion
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.snakeyaml.engine.v2.api.Load
import org.snakeyaml.engine.v2.api.LoadSettings
import java.io.File

/**
 * Build-time cross-check gate: every bundled detection/atom rule must pass
 * BOTH the Kotlin runtime parser (SigmaRuleParser.parse()) AND the JSON
 * schema from the android-sigma-rules submodule (rule-schema.json).
 *
 * If these two validators disagree on any rule, the build fails — surfacing
 * drift between the dev pipeline and the AI-powered rule updater before it
 * reaches production.
 *
 * Correlation rules (sigma_androdr_corr_*.yml) are excluded — they have a
 * different structure and are validated only by SigmaRuleParser.parseCorrelation().
 */
class BundledRulesSchemaCrossCheckTest {

    private val objectMapper = ObjectMapper()

    private val yamlSettings = LoadSettings.builder()
        .setMaxAliasesForCollections(10)
        .setAllowDuplicateKeys(false)
        .build()

    /**
     * Locate rule-schema.json from the submodule. Tries multiple paths to
     * work regardless of which directory Gradle invokes the test from.
     */
    private fun schemaFile(): File {
        val candidates = listOf(
            File("third-party/android-sigma-rules/validation/rule-schema.json"),
            File("../third-party/android-sigma-rules/validation/rule-schema.json"),
            File("/home/yasir/AndroDR/third-party/android-sigma-rules/validation/rule-schema.json"),
        )
        return candidates.firstOrNull { it.exists() }
            ?: error(
                "rule-schema.json not found. Run: git submodule update --init\n" +
                "Tried: ${candidates.map { it.absolutePath }}"
            )
    }

    /**
     * Locate the res/raw directory containing bundled rules.
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

    /**
     * All detection and atom rule files — everything EXCEPT correlation rules.
     * This includes sigma_androdr_atom_*.yml (atoms are structurally identical
     * to detection rules and parsed by SigmaRuleParser.parse()).
     */
    private fun detectionAndAtomRuleFiles(): List<File> =
        rulesDirectory().listFiles { f ->
            f.name.startsWith("sigma_androdr_") &&
                f.name.endsWith(".yml") &&
                !f.name.startsWith("sigma_androdr_corr_")
        }?.sorted() ?: emptyList()

    /**
     * Convert a YAML string to a Jackson JsonNode for schema validation.
     * YAML pipe-keys like "field|endswith" become literal JSON object keys —
     * snakeyaml-engine parses them as plain strings, no special handling needed.
     */
    private fun yamlToJsonNode(yaml: String): JsonNode {
        val load = Load(yamlSettings)
        val parsed = load.loadFromString(yaml)
        return objectMapper.valueToTree(parsed)
    }

    @Test
    fun `schema file is reachable from submodule`() {
        val schema = schemaFile()
        assertTrue(
            "rule-schema.json must exist at submodule path. " +
                "Run: git submodule update --init",
            schema.exists()
        )
    }

    @Test
    fun `every bundled detection rule is accepted by SigmaRuleParser`() {
        val ruleFiles = detectionAndAtomRuleFiles()

        assertTrue(
            "Expected at least 40 detection/atom rule files; found ${ruleFiles.size}. " +
                "Is the test running from the app module root?",
            ruleFiles.size >= 40
        )

        val failures = mutableListOf<String>()

        ruleFiles.forEach { file ->
            try {
                val result = SigmaRuleParser.parse(file.readText())
                if (result == null) {
                    failures += "${file.name}: SigmaRuleParser.parse() returned null"
                }
            } catch (e: SigmaRuleParseException) {
                failures += "${file.name}: SigmaRuleParseException — ${e.message}"
            } catch (e: Exception) {
                failures += "${file.name}: ${e.javaClass.simpleName} — ${e.message}"
            }
        }

        if (failures.isNotEmpty()) {
            fail(
                "Kotlin parser rejected ${failures.size} rule(s):\n" +
                    failures.joinToString("\n") { "  - $it" } + "\n\n" +
                    "Fix the rule YAML or update SigmaRuleParser to accept it."
            )
        }
    }

    @Test
    fun `every bundled detection rule passes JSON schema validation`() {
        // Skip if submodule not initialized (avoid cryptic failures in local dev)
        val schemaPath = try { schemaFile() } catch (e: Exception) {
            assumeTrue("Skipping: submodule not initialized", false)
            return
        }

        val schemaFactory = JsonSchemaFactory.getInstance(SpecVersion.VersionFlag.V202012)
        val schema = schemaFactory.getSchema(schemaPath.toURI())

        val ruleFiles = detectionAndAtomRuleFiles()

        assertTrue(
            "Expected at least 40 detection/atom rule files; found ${ruleFiles.size}.",
            ruleFiles.size >= 40
        )

        val failures = mutableListOf<String>()

        ruleFiles.forEach { file ->
            try {
                val jsonNode = yamlToJsonNode(file.readText())
                val errors = schema.validate(jsonNode)
                if (errors.isNotEmpty()) {
                    val errorMessages = errors.joinToString("; ") { it.message }
                    failures += "${file.name}: $errorMessages"
                }
            } catch (e: Exception) {
                failures += "${file.name}: ${e.javaClass.simpleName} — ${e.message}"
            }
        }

        if (failures.isNotEmpty()) {
            fail(
                "JSON schema rejected ${failures.size} rule(s):\n" +
                    failures.joinToString("\n") { "  - $it" } + "\n\n" +
                    "If you added a new field or service to SigmaRuleParser, " +
                    "update rule-schema.json in the android-sigma-rules repo " +
                    "and bump the submodule."
            )
        }
    }
}
```

- [ ] **Step 2: Run the tests to verify they pass**

Run:
```bash
cd /home/yasir/AndroDR
./gradlew testDebugUnitTest --tests "com.androdr.sigma.BundledRulesSchemaCrossCheckTest" --stacktrace
```

Expected: All 3 tests PASS. If any fail, check:
- Submodule schema has `category` in required → submodule at latest commit?
- All 44 bundled rules have `category:` at top level → they already do per `AllRulesHaveCategoryTest`
- Jackson/snakeyaml classpath issue → check Gradle dependency tree

- [ ] **Step 3: Commit**

```bash
cd /home/yasir/AndroDR
git add app/src/test/java/com/androdr/sigma/BundledRulesSchemaCrossCheckTest.kt
git commit -m "test: add build-time schema cross-check gate for bundled rules

BundledRulesSchemaCrossCheckTest validates every detection/atom rule
against both SigmaRuleParser.parse() (Kotlin runtime) and rule-schema.json
(JSON Schema from the android-sigma-rules submodule). Build fails if
they disagree — closing the drift loop between the dev pipeline and
the AI-powered rule updater.

Uses com.networknt:json-schema-validator for JSON Schema draft 2020-12
validation. Correlation rules are excluded (deferred to Bundle 3).

Part of #105"
```

---

## Task 6: Update CI workflow

**Files:**
- Modify: `/home/yasir/AndroDR/.github/workflows/android-build.yml`

- [ ] **Step 1: Add submodule initialization to the `build` job**

After the existing `actions/checkout@v4` step (line 17-19), add:

```yaml
      - name: Initialize submodules
        run: git submodule update --init --recursive
```

- [ ] **Step 2: Add submodule initialization to the `instrumented-test` job**

After the existing `actions/checkout@v4` step in the `instrumented-test` job (line 114), add:

```yaml
      - name: Initialize submodules
        run: git submodule update --init --recursive
```

- [ ] **Step 3: Commit**

```bash
cd /home/yasir/AndroDR
git add .github/workflows/android-build.yml
git commit -m "ci: initialize submodules before build and instrumented tests

Required for BundledRulesSchemaCrossCheckTest to find rule-schema.json
from the android-sigma-rules submodule at third-party/.

Part of #105"
```

---

## Task 7: Update CLAUDE.md with submodule workflow

**Files:**
- Modify: `/home/yasir/AndroDR/CLAUDE.md`

- [ ] **Step 1: Add submodule section after the "Local development" section**

Add the following after the `### Smoke test (local emulator)` section at the end of CLAUDE.md:

```markdown
### Submodule: android-sigma-rules

The sigma-rules repo is the authoritative source for the rule schema
(`rule-schema.json`). It lives at `third-party/android-sigma-rules/` as a
git submodule.

    # After cloning AndroDR (one-time setup):
    git submodule update --init

    # When you need to update the submodule to pick up upstream changes:
    cd third-party/android-sigma-rules && git pull origin main && cd ../..
    git add third-party/android-sigma-rules
    git commit -m "build: bump android-sigma-rules submodule"

**Adding a new field or logsource service to `SigmaRuleParser.kt`:**

1. Open a PR in `android-sigma-rules` updating `validation/rule-schema.json`
2. Merge that PR
3. In your AndroDR PR: bump the submodule pointer AND make the Kotlin change
4. `BundledRulesSchemaCrossCheckTest` will fail if the schema and parser disagree

**Submodule update direction (AI pipeline → AndroDR):** The submodule
pointer stays pinned until explicitly bumped. New rules added upstream by
`/update-rules` don't affect the build until they're bundled into
`app/src/main/res/raw/`. Bump the submodule when you need upstream schema
changes (e.g., after the AI pipeline reveals a schema gap).
```

- [ ] **Step 2: Commit**

```bash
cd /home/yasir/AndroDR
git add CLAUDE.md
git commit -m "docs: add submodule workflow section to CLAUDE.md

Documents the two-PR dance for schema changes, one-time setup,
and submodule update direction.

Part of #105"
```

---

## Task 8: Final verification and PR

**Files:** None (verification only)

- [ ] **Step 1: Run the full test suite to confirm nothing broke**

Run:
```bash
cd /home/yasir/AndroDR
./gradlew testDebugUnitTest --stacktrace
```

Expected: All tests pass, including the new `BundledRulesSchemaCrossCheckTest` (3 tests) alongside all existing tests.

- [ ] **Step 2: Run lint to confirm no warnings**

Run:
```bash
cd /home/yasir/AndroDR
./gradlew lintDebug --stacktrace
```

Expected: Clean (no new warnings).

- [ ] **Step 3: Verify the drift-prevention guarantee (intentional break test)**

Temporarily remove `category:` from one bundled rule to confirm the gate catches it:

```bash
cd /home/yasir/AndroDR
# Backup
cp app/src/main/res/raw/sigma_androdr_005_graphite_paragon.yml /tmp/sigma_005_backup.yml
# Remove category line
sed -i '/^category:/d' app/src/main/res/raw/sigma_androdr_005_graphite_paragon.yml
# Run test — should FAIL
./gradlew testDebugUnitTest --tests "com.androdr.sigma.BundledRulesSchemaCrossCheckTest" 2>&1 | tail -20
# Restore
cp /tmp/sigma_005_backup.yml app/src/main/res/raw/sigma_androdr_005_graphite_paragon.yml
```

Expected: Test fails with `SigmaRuleParseException — Rule androdr-005 is missing required 'category' field`. This proves the gate works.

- [ ] **Step 4: Push and open PR**

```bash
cd /home/yasir/AndroDR
git push origin HEAD
```

Open PR with title: `feat(build): add sigma-rules submodule + build-time schema cross-check gate`

Body must include: `Closes #105`

---

## Verification Checklist (post-merge)

After both PRs merge (sigma-rules first, then AndroDR):

- [ ] `./gradlew testDebugUnitTest` passes with all 44 detection/atom rules validated
- [ ] CI passes with submodule initialized automatically
- [ ] `python validate-rule.py <any-bundled-rule.yml>` passes in the sigma-rules repo
- [ ] Intentional breakage (remove category) is caught by the gate
- [ ] CLAUDE.md documents the developer workflow
