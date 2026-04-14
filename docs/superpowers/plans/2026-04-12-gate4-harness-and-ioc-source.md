# Gate 4 Harness + IOC Source Validation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make Gate 4 (dry-run evaluation) programmatic and enforce IOC data source provenance.

**Architecture:** Kotlin test harness wraps `SigmaRuleEvaluator.evaluate()` with stub IOC lookups, driven by YAML fixture files. Python script validates IOC data entries against a shared `allowed-sources.json` registry. `merge-ioc-data.py` gains a pre-merge validation pass.

**Tech Stack:** Kotlin + JUnit 5 parameterized tests, snakeyaml-engine (already a dependency), Python 3.

---

## File Map

| Action | Path | Responsibility |
|--------|------|----------------|
| Create | `app/src/test/java/com/androdr/sigma/GateFourTestHarness.kt` | Harness API: (rule, TP, TN, stubs) → Gate4Result |
| Create | `app/src/test/java/com/androdr/sigma/GateFourFixtureTest.kt` | Parameterized test loading fixtures |
| Create | `app/src/test/resources/gate4-fixtures/sideloaded-app.yml` | Fixture: androdr-010 simple selection |
| Create | `app/src/test/resources/gate4-fixtures/package-ioc.yml` | Fixture: androdr-001 ioc_lookup |
| Create | `app/src/test/resources/gate4-fixtures/accessibility-atom.yml` | Fixture: androdr-060 atom rule |
| Create | `third-party/android-sigma-rules/validation/allowed-sources.json` | Source registry (id, name, url) |
| Create | `third-party/android-sigma-rules/validation/validate-ioc-data.py` | IOC data validator script |
| Modify | `scripts/merge-ioc-data.py` | Add source validation before merge |
| Modify | `.claude/commands/update-rules-validate.md` | Rewrite Gate 4 section |

---

## Task 1: Gate4Result Data Class + GateFourTestHarness

**Files:**
- Create: `app/src/test/java/com/androdr/sigma/GateFourTestHarness.kt`

- [ ] **Step 1: Create the harness file with data class and object**

```kotlin
// app/src/test/java/com/androdr/sigma/GateFourTestHarness.kt
package com.androdr.sigma

/**
 * Programmatic Gate 4 dry-run evaluator.
 * Tests that a SIGMA rule fires on true-positive telemetry
 * and does NOT fire on true-negative telemetry.
 */
data class Gate4Result(
    val pass: Boolean,
    val tpFired: Boolean,
    val tnClean: Boolean,
    val errors: List<String>
)

object GateFourTestHarness {

    fun runGate4(
        rule: SigmaRule,
        truePositives: List<Map<String, Any?>>,
        trueNegatives: List<Map<String, Any?>>,
        iocStubs: Map<String, Set<String>> = emptyMap()
    ): Gate4Result {
        val errors = mutableListOf<String>()

        // Build iocLookups from stubs
        val iocLookups: Map<String, (Any) -> Boolean> = iocStubs.mapValues { (_, allowed) ->
            { value: Any -> value.toString() in allowed }
        }

        // Warn on unused stubs
        val referencedLookups = rule.detection.selections.values
            .flatMap { it.fieldMatchers }
            .filter { it.modifier == SigmaModifier.IOC_LOOKUP }
            .mapNotNull { it.values.firstOrNull()?.toString() }
            .toSet()
        for (stubKey in iocStubs.keys) {
            if (stubKey !in referencedLookups) {
                errors.add("WARNING: iocStub '$stubKey' is not referenced by rule '${rule.id}'")
            }
        }

        // Evaluate true positives
        var tpFired = true
        truePositives.forEachIndexed { idx, record ->
            val findings = SigmaRuleEvaluator.evaluate(
                listOf(rule), listOf(record), rule.service, iocLookups
            )
            if (findings.isEmpty()) {
                tpFired = false
                errors.add("TP[$idx] did not fire: $record")
            }
        }

        // Evaluate true negatives
        var tnClean = true
        trueNegatives.forEachIndexed { idx, record ->
            val findings = SigmaRuleEvaluator.evaluate(
                listOf(rule), listOf(record), rule.service, iocLookups
            )
            if (findings.isNotEmpty()) {
                tnClean = false
                errors.add("TN[$idx] fired unexpectedly (${findings.size} finding(s)): $record")
            }
        }

        return Gate4Result(
            pass = tpFired && tnClean && errors.none { !it.startsWith("WARNING") },
            tpFired = tpFired,
            tnClean = tnClean,
            errors = errors
        )
    }
}
```

- [ ] **Step 2: Verify it compiles**

Run: `./gradlew compileTestDebugKotlin 2>&1 | tail -5`
Expected: BUILD SUCCESSFUL

- [ ] **Step 3: Commit**

```bash
git add app/src/test/java/com/androdr/sigma/GateFourTestHarness.kt
git commit -m "feat: add Gate 4 programmatic test harness (#106)"
```

---

## Task 2: Fixture Files

**Files:**
- Create: `app/src/test/resources/gate4-fixtures/sideloaded-app.yml`
- Create: `app/src/test/resources/gate4-fixtures/package-ioc.yml`
- Create: `app/src/test/resources/gate4-fixtures/accessibility-atom.yml`

- [ ] **Step 1: Create fixture directory**

```bash
mkdir -p app/src/test/resources/gate4-fixtures
```

- [ ] **Step 2: Create sideloaded-app.yml**

This tests androdr-010 (simple selection with `not filter_known_good`). The rule fires when `is_system_app: false`, `from_trusted_store: false`, `is_known_oem_app: false`, AND the package is NOT in `known_good_app_db`.

```yaml
# Fixture for androdr-010: sideloaded app detection
rule_file: sigma_androdr_010_sideloaded_app.yml
service: app_scanner
ioc_stubs:
  known_good_app_db:
    - "com.google.android.gm"
true_positives:
  - package_name: "com.shady.sideload"
    is_system_app: false
    from_trusted_store: false
    is_known_oem_app: false
true_negatives:
  # Known-good app (in stub DB) — filtered out by condition
  - package_name: "com.google.android.gm"
    is_system_app: false
    from_trusted_store: false
    is_known_oem_app: false
  # Trusted store app — selection doesn't match
  - package_name: "com.example.legitimate"
    is_system_app: false
    from_trusted_store: true
    is_known_oem_app: false
```

- [ ] **Step 3: Create package-ioc.yml**

This tests androdr-001 (ioc_lookup on `package_ioc_db` with system app filter).

```yaml
# Fixture for androdr-001: package name IOC lookup
rule_file: sigma_androdr_001_package_ioc.yml
service: app_scanner
ioc_stubs:
  package_ioc_db:
    - "com.thetruthspy"
    - "com.flexispy.app"
true_positives:
  - package_name: "com.thetruthspy"
    is_system_app: false
true_negatives:
  # System app with matching package — filtered by condition
  - package_name: "com.thetruthspy"
    is_system_app: true
  # Non-matching package
  - package_name: "com.google.android.gm"
    is_system_app: false
```

- [ ] **Step 4: Create accessibility-atom.yml**

This tests androdr-060 (accessibility_audit service, atom rule).

```yaml
# Fixture for androdr-060: active accessibility service detection
rule_file: sigma_androdr_060_active_accessibility.yml
service: accessibility_audit
ioc_stubs:
  known_good_app_db:
    - "com.lastpass.lpandroid"
true_positives:
  - package_name: "com.shady.keylogger"
    is_system_app: false
    is_enabled: true
true_negatives:
  # Known-good app — filtered out
  - package_name: "com.lastpass.lpandroid"
    is_system_app: false
    is_enabled: true
  # System app — selection doesn't match
  - package_name: "com.android.talkback"
    is_system_app: true
    is_enabled: true
  # Disabled service — selection doesn't match
  - package_name: "com.shady.keylogger"
    is_system_app: false
    is_enabled: false
```

- [ ] **Step 5: Commit**

```bash
git add app/src/test/resources/gate4-fixtures/
git commit -m "test: add Gate 4 fixture files for 3 representative rule types (#106)"
```

---

## Task 3: GateFourFixtureTest (Parameterized Runner)

**Files:**
- Create: `app/src/test/java/com/androdr/sigma/GateFourFixtureTest.kt`

- [ ] **Step 1: Create the parameterized test**

```kotlin
// app/src/test/java/com/androdr/sigma/GateFourFixtureTest.kt
package com.androdr.sigma

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.Parameterized
import org.snakeyaml.engine.v2.api.Load
import org.snakeyaml.engine.v2.api.LoadSettings
import java.io.File

/**
 * Parameterized test that runs Gate 4 dry-run evaluation for every
 * fixture file in test resources gate4-fixtures/.
 */
@RunWith(Parameterized::class)
class GateFourFixtureTest(
    private val fixtureName: String,
    private val fixtureFile: File
) {
    companion object {
        private fun fixturesDir(): File {
            val candidates = listOf(
                File("app/src/test/resources/gate4-fixtures"),
                File("src/test/resources/gate4-fixtures"),
                File("/home/yasir/AndroDR/app/src/test/resources/gate4-fixtures"),
            )
            return candidates.firstOrNull { it.isDirectory }
                ?: error("gate4-fixtures directory not found; tried: ${candidates.map { it.absolutePath }}")
        }

        private fun rulesDir(): File {
            val candidates = listOf(
                File("app/src/main/res/raw"),
                File("src/main/res/raw"),
                File("/home/yasir/AndroDR/app/src/main/res/raw"),
            )
            return candidates.firstOrNull { it.isDirectory }
                ?: error("res/raw directory not found")
        }

        @JvmStatic
        @Parameterized.Parameters(name = "{0}")
        fun fixtures(): List<Array<Any>> {
            return fixturesDir().listFiles { f -> f.extension == "yml" }
                ?.sorted()
                ?.map { arrayOf(it.nameWithoutExtension, it) as Array<Any> }
                ?: emptyList()
        }
    }

    private val yamlLoader = Load(
        LoadSettings.builder()
            .setMaxAliasesForCollections(10)
            .setAllowDuplicateKeys(false)
            .build()
    )

    @Test
    fun `fixture passes Gate 4`() {
        val fixture = parseFixture(fixtureFile)

        // Load and parse the referenced rule
        val ruleFile = File(rulesDir(), fixture.ruleFile)
        assertTrue(
            "Rule file not found: ${ruleFile.absolutePath}",
            ruleFile.isFile
        )
        val rule = SigmaRuleParser.parse(ruleFile.readText())
        assertNotNull("SigmaRuleParser.parse() returned null for ${fixture.ruleFile}", rule)

        // Assert service matches
        assertEquals(
            "Fixture service '${fixture.service}' does not match rule service '${rule!!.service}'",
            fixture.service, rule.service
        )

        // Run Gate 4
        val result = GateFourTestHarness.runGate4(
            rule = rule,
            truePositives = fixture.truePositives,
            trueNegatives = fixture.trueNegatives,
            iocStubs = fixture.iocStubs
        )

        assertTrue(
            "Gate 4 FAILED for $fixtureName:\n${result.errors.joinToString("\n") { "  - $it" }}",
            result.pass
        )
    }

    private fun parseFixture(file: File): FixtureData {
        @Suppress("UNCHECKED_CAST")
        val raw = yamlLoader.loadFromString(file.readText()) as Map<String, Any?>

        val ruleFile = raw["rule_file"] as String
        val service = raw["service"] as String

        @Suppress("UNCHECKED_CAST")
        val iocStubsRaw = (raw["ioc_stubs"] as? Map<String, List<String>>) ?: emptyMap()
        val iocStubs = iocStubsRaw.mapValues { (_, v) -> v.toSet() }

        @Suppress("UNCHECKED_CAST")
        val tp = (raw["true_positives"] as? List<Map<String, Any?>>) ?: emptyList()
        @Suppress("UNCHECKED_CAST")
        val tn = (raw["true_negatives"] as? List<Map<String, Any?>>) ?: emptyList()

        return FixtureData(ruleFile, service, iocStubs, tp, tn)
    }

    private data class FixtureData(
        val ruleFile: String,
        val service: String,
        val iocStubs: Map<String, Set<String>>,
        val truePositives: List<Map<String, Any?>>,
        val trueNegatives: List<Map<String, Any?>>
    )
}
```

- [ ] **Step 2: Run the tests**

Run: `./gradlew testDebugUnitTest --tests "com.androdr.sigma.GateFourFixtureTest" 2>&1 | tail -20`
Expected: 3 tests pass (one per fixture file)

- [ ] **Step 3: Commit**

```bash
git add app/src/test/java/com/androdr/sigma/GateFourFixtureTest.kt
git commit -m "test: add parameterized Gate 4 fixture runner (#106)"
```

---

## Task 4: allowed-sources.json

**Files:**
- Create: `third-party/android-sigma-rules/validation/allowed-sources.json`

- [ ] **Step 1: Create the file**

```json
[
  {
    "id": "stalkerware-indicators",
    "name": "AssoEchap Stalkerware Indicators",
    "url": "https://github.com/AssoEchap/stalkerware-indicators"
  },
  {
    "id": "malwarebazaar",
    "name": "abuse.ch MalwareBazaar",
    "url": "https://bazaar.abuse.ch"
  },
  {
    "id": "threatfox",
    "name": "abuse.ch ThreatFox",
    "url": "https://threatfox.abuse.ch"
  },
  {
    "id": "amnesty-investigations",
    "name": "Amnesty International Security Lab",
    "url": "https://github.com/AmnestyTech/investigations"
  },
  {
    "id": "citizenlab-indicators",
    "name": "Citizen Lab Malware Indicators",
    "url": "https://github.com/citizenlab/malware-indicators"
  },
  {
    "id": "mvt-indicators",
    "name": "MVT Project STIX2 Indicators",
    "url": "https://github.com/mvt-project/mvt-indicators"
  },
  {
    "id": "virustotal",
    "name": "VirusTotal Intelligence",
    "url": "https://www.virustotal.com"
  },
  {
    "id": "android-security-bulletin",
    "name": "Google Android Security Bulletins",
    "url": "https://source.android.com/docs/security/bulletin"
  }
]
```

- [ ] **Step 2: Commit to submodule**

```bash
cd third-party/android-sigma-rules
git add validation/allowed-sources.json
git commit -m "feat: add allowed-sources.json registry for IOC provenance validation"
git push origin main
cd ../..
git add third-party/android-sigma-rules
git commit -m "build: bump android-sigma-rules submodule (allowed-sources.json)"
```

---

## Task 5: validate-ioc-data.py

**Files:**
- Create: `third-party/android-sigma-rules/validation/validate-ioc-data.py`

- [ ] **Step 1: Create the validator script**

```python
#!/usr/bin/env python3
"""Validate an AndroDR IOC data YAML file.

Usage: python3 validate-ioc-data.py <ioc-data-file.yml>

Exit codes:
  0 = valid
  1 = validation errors (printed to stderr)
  2 = file not found / parse error
"""

import json
import re
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    sys.exit("pyyaml required: pip install pyyaml")

SCRIPT_DIR = Path(__file__).parent
BLOCKED_CATEGORIES = {"TEST", "FIXTURE", "SIMULATION", "DEBUG"}
BLOCKED_FAMILY_PATTERNS = re.compile(
    r"(test|fixture|simulation|sample|example)", re.IGNORECASE
)
HEX_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def load_allowed_sources(path: Path) -> set[str]:
    with open(path) as f:
        entries = json.load(f)
    return {entry["id"] for entry in entries}


def validate_ioc_file(data: dict, allowed_sources: set[str], filename: str) -> list[str]:
    """Return list of error strings. Empty = valid."""
    errors = []
    entries = data.get("entries", [])
    if not entries:
        errors.append("No 'entries' list found in file")
        return errors

    seen_indicators = set()
    is_cert_file = "cert" in filename.lower()

    for idx, entry in enumerate(entries):
        prefix = f"entries[{idx}]"

        # Source field
        source = entry.get("source")
        if not source:
            errors.append(f"{prefix}: missing 'source' field")
        elif source not in allowed_sources:
            errors.append(f"{prefix}: unknown source '{source}' (not in allowed-sources.json)")

        # Blocked categories
        category = entry.get("category", "")
        if category.upper() in BLOCKED_CATEGORIES:
            errors.append(f"{prefix}: blocked category '{category}'")

        # Blocked family patterns
        family = entry.get("family", "") or entry.get("familyName", "")
        if family and BLOCKED_FAMILY_PATTERNS.search(family):
            errors.append(f"{prefix}: blocked family name '{family}' (matches test/fixture pattern)")

        # Cert hash format
        indicator = entry.get("indicator", "")
        if is_cert_file and indicator:
            if not HEX_SHA256.match(indicator):
                errors.append(f"{prefix}: invalid cert hash format (expected 64 lowercase hex chars): '{indicator[:20]}...'")

        # Duplicate check
        if indicator:
            if indicator in seen_indicators:
                errors.append(f"{prefix}: duplicate indicator '{indicator}'")
            seen_indicators.add(indicator)

    return errors


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 validate-ioc-data.py <ioc-data-file.yml>", file=sys.stderr)
        sys.exit(2)

    ioc_path = Path(sys.argv[1])
    if not ioc_path.exists():
        print(f"File not found: {ioc_path}", file=sys.stderr)
        sys.exit(2)

    sources_path = SCRIPT_DIR / "allowed-sources.json"
    if not sources_path.exists():
        print(f"allowed-sources.json not found at: {sources_path}", file=sys.stderr)
        sys.exit(2)

    allowed_sources = load_allowed_sources(sources_path)

    with open(ioc_path) as f:
        try:
            data = yaml.safe_load(f)
        except yaml.YAMLError as e:
            print(f"YAML parse error: {e}", file=sys.stderr)
            sys.exit(2)

    if not data:
        print(f"PASS: {ioc_path.name} (empty file)")
        sys.exit(0)

    errors = validate_ioc_file(data, allowed_sources, ioc_path.name)

    if errors:
        print(f"FAIL: {ioc_path.name} — {len(errors)} error(s):", file=sys.stderr)
        for err in errors:
            print(f"  - {err}", file=sys.stderr)
        sys.exit(1)
    else:
        print(f"PASS: {ioc_path.name}")
        sys.exit(0)


if __name__ == "__main__":
    main()
```

- [ ] **Step 2: Test it against existing IOC data files**

Run:
```bash
python3 third-party/android-sigma-rules/validation/validate-ioc-data.py \
    third-party/android-sigma-rules/ioc-data/package-names.yml
```
Expected: `PASS: package-names.yml`

Run against all IOC files:
```bash
for f in third-party/android-sigma-rules/ioc-data/*.yml; do
    python3 third-party/android-sigma-rules/validation/validate-ioc-data.py "$f"
done
```
Expected: All PASS. If any fail (e.g. missing `source` on some entries), fix the IOC data entries.

- [ ] **Step 3: Commit to submodule**

```bash
cd third-party/android-sigma-rules
git add validation/validate-ioc-data.py
git commit -m "feat: add validate-ioc-data.py for source provenance enforcement"
git push origin main
cd ../..
git add third-party/android-sigma-rules
git commit -m "build: bump android-sigma-rules submodule (validate-ioc-data.py)"
```

---

## Task 6: Update merge-ioc-data.py with Source Validation

**Files:**
- Modify: `scripts/merge-ioc-data.py`

- [ ] **Step 1: Add source validation logic**

Add after the existing imports (line 7), add:

```python
ALLOWED_SOURCES_PATH = os.path.join(
    os.path.dirname(__file__), "..",
    "third-party", "android-sigma-rules", "validation", "allowed-sources.json"
)
```

Add a new function after `load_yaml`:

```python
def load_allowed_sources():
    """Load allowed source IDs from the submodule registry."""
    if not os.path.exists(ALLOWED_SOURCES_PATH):
        print(f"WARNING: allowed-sources.json not found at {ALLOWED_SOURCES_PATH}", file=sys.stderr)
        print("  Skipping source validation (submodule may not be initialized)", file=sys.stderr)
        return None
    with open(ALLOWED_SOURCES_PATH) as f:
        entries = json.load(f)
    return {entry["id"] for entry in entries}


def validate_sources(entries, allowed_sources):
    """Validate source field on all entries. Return list of errors."""
    if allowed_sources is None:
        return []
    errors = []
    for i, entry in enumerate(entries):
        source = entry.get("source")
        if not source:
            errors.append(f"Entry {i}: missing 'source' field (indicator: {entry.get('indicator', '?')})")
        elif source not in allowed_sources:
            errors.append(f"Entry {i}: unknown source '{source}' (indicator: {entry.get('indicator', '?')})")
    return errors
```

Modify `main()` — add validation before the merge calls. After `print("Merging IOC data...")` (line 129), add:

```python
    allowed_sources = load_allowed_sources()

    # Validate all source entries before merging
    all_errors = []
    for label, path in [("packages", pkg_path), ("certs", cert_path), ("domains", domain_path)]:
        if os.path.exists(path):
            entries = load_yaml(path)
            errs = validate_sources(entries, allowed_sources)
            if errs:
                all_errors.extend([f"[{label}] {e}" for e in errs])

    if all_errors:
        print(f"ERROR: Source validation failed ({len(all_errors)} error(s)):", file=sys.stderr)
        for err in all_errors:
            print(f"  - {err}", file=sys.stderr)
        sys.exit(1)
```

- [ ] **Step 2: Test the validation gate**

Create a temp file with a bad source and verify rejection:
```bash
cat > /tmp/test-bad-source.yml << 'EOF'
entries:
  - indicator: "com.evil.app"
    family: "EvilApp"
    category: "MALWARE"
    severity: "CRITICAL"
    source: "my-random-blog"
EOF
python3 scripts/merge-ioc-data.py --repo-dir /tmp/test-ioc-reject
```
Expected: exit code 1, error about unknown source

Run with real data (existing submodule):
```bash
python3 scripts/merge-ioc-data.py --repo-dir third-party/android-sigma-rules
```
Expected: merges successfully (all existing entries have valid sources)

- [ ] **Step 3: Commit**

```bash
git add scripts/merge-ioc-data.py
git commit -m "feat: enforce IOC source validation in merge-ioc-data.py (#106)"
```

---

## Task 7: Update update-rules-validate.md Skill

**Files:**
- Modify: `.claude/commands/update-rules-validate.md`

- [ ] **Step 1: Rewrite Gate 4 section**

Replace the existing Gate 4 section (lines 64-83) with:

```markdown
## Gate 4: Dry-Run Evaluation

Use the programmatic Gate 4 test harness to verify rule logic.

1. **Create a fixture YAML** in `/tmp/gate4-fixture.yml`:

```yaml
rule_file: sigma_androdr_NNN_rule_name.yml
service: <logsource.service from the rule>
ioc_stubs:
  <lookup_db_name>:
    - "<indicator_from_SIR>"
true_positives:
  - <field_name>: <value_from_SIR_that_should_trigger>
    <field2>: <value2>
true_negatives:
  - <field_name>: <benign_value>
    <field2>: <value2>
```

2. **Copy the fixture** to `app/src/test/resources/gate4-fixtures/` (temporary — remove after validation)

3. **Run the harness:**
```bash
./gradlew testDebugUnitTest --tests "com.androdr.sigma.GateFourFixtureTest"
```

4. **Record results:**
   - If the test passes: `tp_fired: true`, `tn_clean: true`
   - If it fails: record which records failed and why

**Fixture tips:**
- For `ioc_lookup` rules: stub the DB name with indicators from the SIR
- For simple selection rules: set fields to matching values for TP, non-matching for TN
- The harness uses stubbed IOC lookups (not real data) — this tests rule wiring only
- Use `benign-app.json` / `benign-device.json` from `validation/test-fixtures/` as TN templates

Record: `{ pass: bool, tp_fired: bool, tn_clean: bool, errors: string[] }`
```

- [ ] **Step 2: Update IOC Data Validation section**

Replace the paragraph starting "When the pipeline produces IOC data entries" to reference the script:

```markdown
## IOC Data Validation

When the pipeline produces IOC data entries (for `ioc-data/*.yml`), validate with:

```bash
python3 third-party/android-sigma-rules/validation/validate-ioc-data.py <ioc-data-file.yml>
```

The script enforces:
- `source` field present and in `allowed-sources.json`
- No blocked categories (TEST, FIXTURE, SIMULATION, DEBUG)
- No blocked family patterns (test/fixture/simulation/sample/example)
- Cert hashes: 64 lowercase hex
- No duplicate indicators

Exit 0 = valid, exit 1 = errors printed to stderr.

### Allowed sources

See `third-party/android-sigma-rules/validation/allowed-sources.json` for the canonical list with URLs.
```

- [ ] **Step 3: Commit**

```bash
git add .claude/commands/update-rules-validate.md
git commit -m "docs: update validate skill with Gate 4 harness + IOC validator instructions (#106)"
```

---

## Task 8: Integration Verification

- [ ] **Step 1: Run the full test suite to confirm nothing broke**

Run: `./gradlew testDebugUnitTest 2>&1 | tail -20`
Expected: BUILD SUCCESSFUL, all tests pass

- [ ] **Step 2: Run IOC validation on all bundled IOC data**

```bash
for f in third-party/android-sigma-rules/ioc-data/*.yml; do
    python3 third-party/android-sigma-rules/validation/validate-ioc-data.py "$f"
done
```
Expected: All PASS

- [ ] **Step 3: Final commit if any fixups needed, then push branch**

```bash
git push origin HEAD
```
