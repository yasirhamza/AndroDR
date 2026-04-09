# Refactor Plan 7: Integration, Regression Fixture, and PR

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Parent refactor:** Unified telemetry/findings architecture (#84). Spec: `docs/superpowers/specs/2026-04-09-unified-telemetry-findings-refactor-design.md`, §11 + R7.

**Plan order:** Plan 7 of 7 (final). Starts after plan 6's final commit. Serialized execution on `claude/unified-telemetry-findings-refactor`.

**Goal:** Create a redacted test fixture from the tester-provided bugreport that motivated the refactor. Write an end-to-end regression test that loads the fixture, runs the full refactored pipeline, and asserts the Unisoc false-positive story is fully fixed. Run manual verification across all gradle checks. Open the pull request against `main` with a comprehensive summary linking every plan, the spec, and the tracking issues.

**Architecture:** Minimal new code. This plan is primarily verification and PR-opening work. The regression test file is the only new test. Everything else is gradle runs and git/gh commands.

**Tech Stack:** Kotlin, JUnit 4, gh CLI.

**Acceptance criteria:**
- Tester-provided bugreport redacted per spec R7 (IMEI, phone number, device model, SoC, vendor build fingerprints, installed apps list).
- Redacted fixture checked in at `app/src/test/resources/fixtures/regression-unisoc-clean.txt`.
- New regression test `UnifiedRefactorRegressionTest` loads the fixture and asserts:
  - Zero findings with descriptions mentioning "graphite" substring
  - Zero findings with descriptions mentioning "base64" or "exfiltration"
  - Zero findings with descriptions mentioning "C2 beacon"
  - Zero HIGH or CRITICAL findings on `com.unisoc.*`, `com.sprd.*`, `com.go.browser`, `com.xiaomi.midrop` packages
  - Every produced finding has a non-empty `ruleId`
- All four gradle checks (`testDebugUnitTest`, `lintDebug`, `assembleDebug`, `detekt`) BUILD SUCCESSFUL.
- Manual verification checklist signed off.
- PR opened against `main` with `Fixes #84` trailer, comprehensive body, links to spec + all 7 plan documents + follow-up issues.

---

## Phase A: Test Fixture Redaction

### Task A1: Locate the source bugreport

- [ ] **Step 1: Check for the bugreport at the expected location**

The tester-provided bugreport is at `/home/yasir/Desktop/report/androdr_bugreport_20260409_162409.txt`. Verify it exists:

```bash
ls -l /home/yasir/Desktop/report/
```

If the file is missing or the directory doesn't exist, the plan needs to adapt:
- **Option 1**: Create a synthetic fixture that represents the same structural problems (Unisoc packages, graphite_renderengine flag, base64 dumpsys content). A synthetic fixture is less authoritative but avoids redaction concerns entirely.
- **Option 2**: Skip the fixture-based regression test and rely on unit tests from earlier plans plus the build-time enforcement tests. Document the deferral.

For this plan, assume the file is present. If not, fall back to Option 1 (synthetic fixture) and document in the report.

### Task A2: Perform redaction

**Files:**
- Create: `app/src/test/resources/fixtures/regression-unisoc-clean.txt`

- [ ] **Step 1: Copy the source file to a working location**

```bash
mkdir -p /tmp/redact-work
cp /home/yasir/Desktop/report/androdr_bugreport_20260409_162409.txt /tmp/redact-work/source.txt
```

- [ ] **Step 2: Run the redaction pass**

The goal: preserve structural elements (line counts, section boundaries, parse-relevant tokens) while replacing identifying information with stable placeholders. Key items to scrub per R7:

- **IMEI** (`\d{15}` numbers that appear near "imei" tokens) → `AAAAAAAAAAAAAAA`
- **Phone number** (patterns like `+\d{10,15}` or `\d{10,11}` near "phone") → `+10000000000`
- **Installed apps list** — the comprehensive list that could identify the user. Strategy:
  - Keep the *count* and *shape* of the list (e.g. line count, format)
  - Replace most package names with `com.redacted.appN` placeholders
  - **KEEP** entries that are structurally relevant to the regression test:
    - `com.unisoc.*` packages (required for the "Unisoc classified as OEM" assertion)
    - `com.sprd.*` packages (same)
    - `com.go.browser` (required for "AOSP Go browser not HIGH risk" assertion)
    - `com.xiaomi.midrop` (required for "ShareMe not HIGH risk" assertion)
    - Standard AOSP/Google packages (`com.android.*`, `com.google.*`)
  - Everything else becomes `com.redacted.appN`
- **Device model** (e.g. `"Redmi A5"`, `"ro.product.model"` value) → `"Redacted Device"`
- **SoC details** (e.g. `"Unisoc T7250"`, `"ro.board.platform"` value) → replace with `"unisoc_sc9863a"` (a valid Unisoc SoC identifier without identifying the specific tester)
- **Vendor build fingerprint** (e.g. `ro.build.fingerprint` value) → `"unisoc/redacted/redacted:12/RKQ1.200826.002/7520059:user/release-keys"` — preserving the `unisoc/` prefix for structural relevance
- **MAC addresses** (`xx:xx:xx:xx:xx:xx` patterns) → `aa:bb:cc:dd:ee:ff`
- **IP addresses** (192.168.*, 10.*, etc. in network dumps) → `10.0.0.1`
- **Serial numbers, UUIDs** — replace with static values
- **Account email addresses** — replace with `redacted@example.com`

For the installed apps list specifically — DO NOT delete lines, DO NOT change line count, because doing so could break parsers that expect specific offsets. Replace content in-place.

Use a Python or shell script to perform the redaction. Example Python:

```python
import re
import sys

def redact_line(line: str) -> str:
    # IMEI (15 digits)
    line = re.sub(r'\b\d{15}\b', 'AAAAAAAAAAAAAAA', line)
    # Phone numbers (+ 10-15 digits)
    line = re.sub(r'\+\d{10,15}', '+10000000000', line)
    # MAC addresses
    line = re.sub(r'[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}', 'aa:bb:cc:dd:ee:ff', line)
    # IP addresses (not 127.* or ::1)
    line = re.sub(r'\b(?!127\.)(?!0\.)\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', '10.0.0.1', line)
    # Emails
    line = re.sub(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', 'redacted@example.com', line)

    # Device model / build fingerprint
    line = re.sub(r'ro\.product\.model\s*=\s*[^\n]+', 'ro.product.model=Redacted Device', line)
    line = re.sub(r'ro\.product\.name\s*=\s*[^\n]+', 'ro.product.name=redacted', line)
    line = re.sub(r'ro\.product\.device\s*=\s*[^\n]+', 'ro.product.device=redacted', line)
    line = re.sub(r'ro\.build\.fingerprint\s*=\s*[^\n]+',
                  'ro.build.fingerprint=unisoc/redacted/redacted:12/RKQ1.200826.002/7520059:user/release-keys', line)
    line = re.sub(r'ro\.board\.platform\s*=\s*[^\n]+', 'ro.board.platform=unisoc_sc9863a', line)

    # Installed app package names — keep specific prefixes, redact others
    keep_prefixes = ('com.android.', 'com.google.', 'com.unisoc.', 'com.sprd.',
                     'vendor.unisoc.', 'vendor.sprd.', 'com.xiaomi.midrop',
                     'com.go.browser', 'android.', 'system')
    def redact_pkg(match):
        pkg = match.group(0)
        if any(pkg.startswith(p) for p in keep_prefixes):
            return pkg
        # Deterministic placeholder based on hash of original
        h = abs(hash(pkg)) % 10000
        return f'com.redacted.app{h}'
    line = re.sub(r'\bcom\.[a-z0-9_]+(\.[a-z0-9_]+)+\b', redact_pkg, line)

    return line

with open(sys.argv[1]) as f_in, open(sys.argv[2], 'w') as f_out:
    for line in f_in:
        f_out.write(redact_line(line))

print("Redaction complete")
```

Save this as `/tmp/redact-work/redact.py` and run:

```bash
python3 /tmp/redact-work/redact.py /tmp/redact-work/source.txt /tmp/redact-work/redacted.txt
```

- [ ] **Step 3: Manual sanity check**

After automated redaction, manually spot-check the output for missed PII:

```bash
# Check for anything that looks like an email
grep -E "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}" /tmp/redact-work/redacted.txt | head -5

# Check for long digit sequences that might be IMEIs
grep -E "\b\d{14,}\b" /tmp/redact-work/redacted.txt | head -5

# Check for anything that looks like a real device model
grep -Ei "redmi|poco|mi[ -]?\d+|xiaomi.*note" /tmp/redact-work/redacted.txt | head -5
```

Each grep should return zero lines. Any match indicates a redaction gap — patch the Python script and re-run.

- [ ] **Step 4: Reduce the fixture to the essential sections if it's too large**

Full Android bugreports can be 10-50+ MB. A test fixture that large is slow to load and bloats the repository. If the file is over ~5 MB:

- Extract only the sections relevant to the regression test: `dumpsys package`, `dumpsys appops`, `dumpsys power`, `dumpsys activity`, `tombstones/` section, `ro.*` system properties.
- Preserve the bugreport structure so parsers can locate sections (keep headers and section markers).
- Aim for a fixture under 2 MB.

This can be done after redaction by grep-extracting sections.

- [ ] **Step 5: Move the fixture to its final location**

```bash
mkdir -p app/src/test/resources/fixtures
cp /tmp/redact-work/redacted.txt app/src/test/resources/fixtures/regression-unisoc-clean.txt
```

- [ ] **Step 6: Add a metadata README alongside the fixture**

Create `app/src/test/resources/fixtures/regression-unisoc-clean.README.md`:

```markdown
# regression-unisoc-clean.txt

Redacted bugreport fixture from a Unisoc-based Android device. Used by
`UnifiedRefactorRegressionTest` to assert the unified telemetry/findings
refactor (#84) correctly handles the Unisoc false-positive case that
motivated the refactor.

## Source

Provided by a tester. Redacted on 2026-04-09 per spec R7 of
`docs/superpowers/specs/2026-04-09-unified-telemetry-findings-refactor-design.md`.

## What was scrubbed

- IMEI (15-digit numbers) → AAAAAAAAAAAAAAA
- Phone numbers → +10000000000
- MAC addresses → aa:bb:cc:dd:ee:ff
- IP addresses → 10.0.0.1
- Email addresses → redacted@example.com
- Device model, SoC name, build fingerprint → generic Unisoc placeholders
- Installed app package names → `com.redacted.appN`, except:
  - `com.unisoc.*`, `com.sprd.*`, `vendor.unisoc.*` (for Unisoc classification test)
  - `com.xiaomi.midrop` (for Xiaomi OEM classification test)
  - `com.go.browser` (for AOSP Go browser test)
  - Standard AOSP/Google packages (for baseline telemetry)

## What was preserved

- Section structure (all bugreport section headers/markers)
- `graphite_renderengine` occurrences (proves the deleted "graphite" keyword
  heuristic no longer fires on this input)
- Base64 blobs in dumpsys output (proves the deleted "base64 exfiltration"
  heuristic no longer fires)
- HTTP/POST fragments in log captures (proves the deleted "C2 beacon"
  heuristic no longer fires)

## Usage

See `app/src/test/java/com/androdr/scanner/UnifiedRefactorRegressionTest.kt`.
```

- [ ] **Step 7: Commit the fixture**

```bash
cd /home/yasir/AndroDR
git add app/src/test/resources/fixtures/regression-unisoc-clean.txt \
        app/src/test/resources/fixtures/regression-unisoc-clean.README.md
git commit -m "test(regression): add redacted Unisoc bugreport fixture (#84)

Redacted per spec R7. Source is the tester-provided bugreport that
triggered the entire unified telemetry/findings refactor — alarming
false positives from the three deleted heuristics plus missing
Unisoc OEM classification.

Scrubbed: IMEI, phone number, MAC, IP, email, device model, SoC,
build fingerprint, installed app list (except structurally-relevant
packages for the regression assertions).

Preserved: graphite_renderengine occurrences, base64 blobs in dumpsys,
HTTP/POST fragments, Unisoc system packages, Xiaomi ShareMe,
com.go.browser — all the things the deleted heuristics used to
trigger on.

The regression test comes next.

Part of #84 (plan 7, phase A)."
```

---

## Phase B: Regression Test

### Task B1: Write `UnifiedRefactorRegressionTest`

**Files:**
- Create: `app/src/test/java/com/androdr/scanner/UnifiedRefactorRegressionTest.kt`

- [ ] **Step 1: Study existing `BugReportAnalyzer` test fixtures**

```bash
find app/src/test -name "BugReport*Test*.kt"
grep -rn "Bugreport\|bugreport" app/src/test/java/com/androdr/scanner/ --include="*.kt" | head -10
```

Understand how existing tests instantiate the analyzer and feed it input. Use the same pattern.

- [ ] **Step 2: Write the test**

```kotlin
package com.androdr.scanner

import com.androdr.scanner.bugreport.BugReportAnalyzer
import com.androdr.sigma.Finding
import io.mockk.mockk
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.io.File

/**
 * End-to-end regression test for the unified telemetry/findings refactor (#84).
 *
 * Loads the redacted Unisoc-based-device bugreport fixture that triggered the
 * refactor, runs the full analyzer pipeline, and asserts that the false-positive
 * story is fully fixed:
 *
 * 1. None of the three deleted hardcoded heuristics produce findings (graphite
 *    keyword, base64 blob, C2 beacon).
 * 2. `com.unisoc.*`, `com.sprd.*`, `com.go.browser`, `com.xiaomi.midrop` are
 *    not flagged HIGH or CRITICAL (they're recognized as OEM/system or AOSP).
 * 3. Every produced finding has a non-empty `ruleId` field (enforcing spec §1:
 *    no finding without a rule).
 *
 * Fixture: `app/src/test/resources/fixtures/regression-unisoc-clean.txt`
 *
 * See `docs/superpowers/specs/2026-04-09-unified-telemetry-findings-refactor-design.md`
 * §11 for the full test plan.
 */
class UnifiedRefactorRegressionTest {

    private lateinit var fixtureFile: File
    private lateinit var analyzer: BugReportAnalyzer

    @Before
    fun setUp() {
        // Fixture loading — adapt path discovery to the project's test convention
        val candidates = listOf(
            File("app/src/test/resources/fixtures/regression-unisoc-clean.txt"),
            File("src/test/resources/fixtures/regression-unisoc-clean.txt"),
            File("/home/yasir/AndroDR/app/src/test/resources/fixtures/regression-unisoc-clean.txt"),
        )
        fixtureFile = candidates.firstOrNull { it.isFile }
            ?: error("Could not locate fixture; tried: ${candidates.map { it.absolutePath }}")

        // Analyzer construction — adapt to the real Hilt/constructor wiring
        analyzer = buildAnalyzer()
    }

    @Test
    fun `no findings mention graphite keyword`() {
        val findings = runAnalysis()
        val graphiteFindings = findings.filter {
            it.description.contains("graphite", ignoreCase = true) ||
                it.title.contains("graphite", ignoreCase = true)
        }
        assertTrue(
            "Expected zero findings mentioning 'graphite', got: ${graphiteFindings.map { it.ruleId + ": " + it.title }}",
            graphiteFindings.isEmpty(),
        )
    }

    @Test
    fun `no findings mention base64 exfiltration`() {
        val findings = runAnalysis()
        val base64Findings = findings.filter {
            it.description.contains("base64", ignoreCase = true) ||
                it.description.contains("exfiltration", ignoreCase = true)
        }
        assertTrue(
            "Expected zero findings mentioning 'base64' or 'exfiltration', got: ${base64Findings.map { it.ruleId }}",
            base64Findings.isEmpty(),
        )
    }

    @Test
    fun `no findings mention C2 beacon`() {
        val findings = runAnalysis()
        val c2Findings = findings.filter {
            it.description.contains("c2", ignoreCase = true) ||
                it.description.contains("beacon", ignoreCase = true)
        }
        assertTrue(
            "Expected zero findings mentioning 'c2' or 'beacon', got: ${c2Findings.map { it.ruleId }}",
            c2Findings.isEmpty(),
        )
    }

    @Test
    fun `no HIGH or CRITICAL findings on Unisoc or AOSP-Go packages`() {
        val findings = runAnalysis()
        val protectedPrefixes = listOf("com.unisoc.", "com.sprd.", "com.go.browser", "com.xiaomi.midrop")

        val violations = findings.filter { f ->
            val level = f.level.lowercase()
            (level == "high" || level == "critical") &&
                protectedPrefixes.any { prefix -> 
                    f.description.contains(prefix, ignoreCase = true) ||
                    f.title.contains(prefix, ignoreCase = true)
                }
        }

        assertTrue(
            "Expected zero HIGH/CRITICAL findings on Unisoc/AOSP-Go/Xiaomi-system packages. " +
                "These are OEM system packages that should be classified via OemPrefixResolver. " +
                "Violations: ${violations.map { "${it.ruleId}:${it.level}:${it.title}" }}",
            violations.isEmpty(),
        )
    }

    @Test
    fun `every finding has a non-empty ruleId`() {
        val findings = runAnalysis()
        val unruledFindings = findings.filter { it.ruleId.isBlank() }
        assertTrue(
            "Expected every finding to have a non-empty ruleId (spec §1: no finding without a rule). " +
                "Violators: ${unruledFindings.map { it.title }}",
            unruledFindings.isEmpty(),
        )
    }

    private fun runAnalysis(): List<Finding> {
        // Invoke the analyzer on the fixture and return the produced findings.
        // The exact API depends on BugReportAnalyzer's current shape — adapt.
        val result = analyzer.analyze(fixtureFile)
        return result.findings
    }

    private fun buildAnalyzer(): BugReportAnalyzer {
        // Construct a BugReportAnalyzer suitable for unit testing.
        // This will need to inject SigmaRuleEngine, the parsers, OemPrefixResolver, etc.
        // If the real wiring is too complex for a unit test, use mocks for the
        // non-critical dependencies and real instances for the ones being tested.
        //
        // IMPORTANT: the SigmaRuleEngine must be real (not mocked) because the
        // test is exercising the full rule evaluation pipeline.
        TODO("Adapt to project test wiring — see BugReportAnalyzerTest or similar")
    }
}
```

**Note:** `buildAnalyzer()` is a `TODO` because the exact wiring depends on the project's test infrastructure. You will need to:
- Read existing `BugReportAnalyzerTest` (if it wasn't deleted in plan 6) or similar
- Use the same injection pattern
- Ensure `SigmaRuleEngine` is real (with bundled rules loaded) so the regression actually exercises the rule pipeline
- Mock only truly expensive dependencies (Android `Context`, file system abstractions if any)

If getting real Hilt wiring in a unit test is too complex, use MockK with real `SigmaRuleEngine` as a last resort. Or mark the test as `@Ignore` with a note and ensure the manual verification step (phase C) covers the same ground.

- [ ] **Step 3: Run the test**

```bash
cd /home/yasir/AndroDR
export JAVA_HOME=/home/yasir/Applications/android-studio/jbr
./gradlew testDebugUnitTest --tests "com.androdr.scanner.UnifiedRefactorRegressionTest" 2>&1 | tail -20
```
Expected: BUILD SUCCESSFUL, all 5 tests pass.

If any test fails, that's the real test of the refactor. Investigate: which assertion failed? Does it indicate a genuine gap in the refactor, or a problem with the test setup?

- **Graphite test fails** → a rule is still firing on graphite. Check rule YAML files and `LegacyScanModule` deletion.
- **Base64 test fails** → a rule is still matching base64 patterns. Should not be possible after plan 6.
- **C2 beacon test fails** → same.
- **Unisoc HIGH/CRITICAL test fails** → the OEM allowlist isn't being consulted by the scanner that produced the finding. Debug the finding's origin and check `OemPrefixResolver` wiring.
- **Unruled finding test fails** → a finding was produced without a rule. Should not happen after plan 6 deleted `BugReportFinding`.

Fix whatever is broken, re-run, repeat until green.

- [ ] **Step 4: Commit the regression test**

```bash
git add app/src/test/java/com/androdr/scanner/UnifiedRefactorRegressionTest.kt
git commit -m "test(regression): end-to-end assertion suite for #84 refactor

Five regression tests against the redacted Unisoc-device fixture:

1. No findings mention 'graphite' substring → proves the deleted
   keyword heuristic is gone.
2. No findings mention 'base64' or 'exfiltration' → proves the
   deleted base64 length heuristic is gone.
3. No findings mention 'c2' or 'beacon' → proves the deleted
   C2 beacon regex is gone.
4. No HIGH or CRITICAL findings on com.unisoc.*, com.sprd.*,
   com.go.browser, com.xiaomi.midrop → proves the expanded OEM
   allowlist correctly classifies these as system packages.
5. Every finding has a non-empty ruleId → proves spec §1
   (no finding without a rule) is enforced end-to-end.

Any future commit that regresses any of these properties fails CI here.

Part of #84 (plan 7, phase B)."
```

---

## Phase C: Full Gradle Check Suite

### Task C1: Run all checks

```bash
cd /home/yasir/AndroDR
export JAVA_HOME=/home/yasir/Applications/android-studio/jbr

./gradlew testDebugUnitTest 2>&1 | tee /tmp/final_test.log | tail -30
./gradlew lintDebug 2>&1 | tee /tmp/final_lint.log | tail -10
./gradlew assembleDebug 2>&1 | tee /tmp/final_assemble.log | tail -5
./gradlew detekt 2>&1 | tee /tmp/final_detekt.log | tail -10
```

All four must be BUILD SUCCESSFUL. If any fails, diagnose and fix before proceeding to PR creation.

### Task C2: Invariant spot-checks across the whole refactor

```bash
# Check 1: no LegacyScanModule references (code, not doc)
grep -rn "LegacyScanModule" app/src/ --include="*.kt" | grep -v "^\s*\*\|// .*removed\|/\*"

# Check 2: no BugReportFinding references (code, not doc)
grep -rn "BugReportFinding" app/src/ --include="*.kt" | grep -v "^\s*\*\|// .*removed\|/\*"

# Check 3: all bundled rules declare category
./gradlew testDebugUnitTest --tests "com.androdr.sigma.AllRulesHaveCategoryTest" 2>&1 | tail -10

# Check 4: no severity field on ForensicTimelineEvent
grep "val severity" app/src/main/java/com/androdr/data/model/ForensicTimelineEvent.kt

# Check 5: Unisoc prefixes present in allowlist
grep -c "unisoc\|sprd" app/src/main/res/raw/known_oem_prefixes.yml

# Check 6: export format version bumped
grep "EXPORT_FORMAT_VERSION" app/src/main/java/com/androdr/reporting/ReportExporter.kt

# Check 7: TimelineRow exists
ls app/src/main/java/com/androdr/ui/timeline/TimelineRow.kt
```

Every check should pass. Document any failures.

---

## Phase D: Manual Verification Checklist

### Task D1: Verify each acceptance criterion from the spec

Go through the spec §11 "Testing strategy" section and confirm each item is satisfied:

- [ ] Unit tests for rule parser category enforcement (plan 1) ✓
- [ ] Unit tests for severity cap policy (plan 1) ✓
- [ ] Unit tests for correlation propagation (plan 1) ✓
- [ ] Unit tests for telemetry source invariant (plan 2) ✓
- [ ] Unit tests for migration 14→15 (plan 2) ✓
- [ ] Unit tests for migration 15→16 (plan 3) ✓
- [ ] Timeline UI unit tests (plan 3) ✓
- [ ] Unit tests for `KnownSpywareArtifactsResolver` (plan 4) ✓
- [ ] Unit tests for `TombstoneParser`, `WakelockParser` (plan 5) ✓
- [ ] Regression test against fixture (plan 7) ✓
- [ ] `AllRulesHaveCategoryTest` passes against bundled rules ✓

### Task D2: Spec coverage check

Read each section of the spec and check the corresponding implementation:

- §2 Principles → all 6 invariants held
- §3 Architecture two layers → telemetry/findings separated
- §4 Source-agnostic telemetry schema → `TelemetrySource` enum exists, used everywhere
- §5 Unified `Finding` type → `BugReportFinding` deleted
- §6 Severity caps by rule category → `SeverityCapPolicy` + build-time test
- §7 Bugreport parser refactor → 7 modules ported + new parsers
- §8 LegacyScanModule migration → file deleted, 3 tombstone commits, 2 rules ported
- §9 FileArtifactScanner IOC migration → `KnownSpywareArtifactsResolver` + YAML
- §10 Timeline UI + export separation → `TimelineRow` + export modes
- §11 Testing strategy → all tests present
- §12 Out of scope → follow-up issues tracked (#85-88)
- §13 Risks → R6/R7 (UI behavioral change + fixture redaction) addressed

Document any gaps. If any are found, either fix in a followup commit on this plan or explicitly defer with a note in the PR body.

---

## Phase E: Open Pull Request

### Task E1: Prepare the PR body

- [ ] **Step 1: Final branch log review**

```bash
cd /home/yasir/AndroDR
git log --oneline main..HEAD | head -80
```

Count commits. Expected: 60-80 commits total across 7 plans.

- [ ] **Step 2: Push the branch** (if not already pushed)

```bash
git push -u origin claude/unified-telemetry-findings-refactor 2>&1 | tail -10
```

### Task E2: Open the PR via `gh`

```bash
gh pr create \
  --base main \
  --head claude/unified-telemetry-findings-refactor \
  --title "refactor: unified telemetry/findings architecture (#84)" \
  --body "$(cat <<'EOF'
## Summary

Architectural refactor that separates telemetry (ground truth, no severity)
from findings (rule-derived matches with severity). Motivated by a tester's
false-positive report on a Unisoc-based Android device — the root cause was
hardcoded detection heuristics in Kotlin and missing OEM allowlist entries.

This PR ships all 7 sub-plans as a single atomic change. Every commit compiles
and every plan boundary leaves gradle checks green.

## Fixes

Fixes #84

## The 7 plans

1. **Rule engine foundation** (`refactor-01-rule-engine-foundation.md`) —
   `RuleCategory` enum, required `category:` field on every rule, `SeverityCapPolicy`
   (device_posture capped at medium), correlation category propagation, disabled-rule
   mechanism, build-time enforcement test.
2. **Telemetry foundation** (`refactor-02-telemetry-foundation.md`) —
   `TelemetrySource` enum, required `source` field on 7 existing telemetry types,
   7 new telemetry shell types, Room migration v14→v15 consolidating `ForensicTimelineEvent`
   provenance booleans into a single enum column, runtime scanner updates, 5 plan-1 follow-ups.
3. **Timeline UI refactor** (`refactor-03-timeline-ui.md`) — `ForensicTimelineEvent.severity`
   removed (Room migration v15→v16), `TimelineRow` sealed type with distinct `TelemetryRow`
   (neutral) and `FindingRow` (severity-badged) variants, "Hide informational telemetry"
   filter toggle, 3-mode export selector (telemetry/findings/both), export format version bump.
4. **OEM allowlist + FileArtifactScanner IOC migration** (`refactor-04-oem-allowlist-and-fileartifact-iocs.md`) —
   Unisoc/SPRD chipset prefixes added to `known_oem_prefixes.yml` (the direct fix for the tester's
   false-positive report), `known_spyware_artifacts.yml` resource file, `KnownSpywareArtifactsResolver`.
5. **Bugreport parser ports** (`refactor-05-bugreport-parser-ports.md`) —
   7 bugreport modules ported to emit typed telemetry instead of findings, hardcoded constant
   lists deleted (`systemPackagePrefixes`, `sensitiveIntents`, `sensitiveSchemes`, `sensitiveDbPaths`,
   `dangerousOps`, `CHANGE_ID_DOWNSCALED`), `TombstoneParser` and `WakelockParser` created,
   `TelemetryBundle` added to `BugReportAnalyzer`.
6. **LegacyScanModule teardown + BugReportFinding cleanup** (`refactor-06-legacy-teardown-and-bugreportfinding-cleanup.md`) —
   `LegacyScanModule.kt` deleted with 3 separate tombstone commits for the graphite keyword,
   base64 blob, and C2 beacon heuristics. 6 new rules added (1 enabled crash-loop + 5 disabled
   placeholders for future telemetry types). `BugReportFinding` type deleted, all consumers
   migrated to the unified `Finding` type. 6 new typed `evaluate*()` methods on `SigmaRuleEngine`.
7. **Integration testing + regression fixture + PR** (`refactor-07-integration-and-pr.md`, this plan) —
   Redacted fixture from the tester's bugreport, 5-assertion end-to-end regression test asserting
   the false-positive story is fully fixed, manual verification, this PR.

## Spec

`docs/superpowers/specs/2026-04-09-unified-telemetry-findings-refactor-design.md`

## Follow-up issues

- #85 — Archive superseded MVT-parity docs post-merge
- #86 — DeviceAuditor: replace bootloader string heuristic with `ro.boot.verifiedbootstate`
- #87 — Wakelock rule UAT tuning (the rule ships disabled-by-default pending calibration)
- #88 — Telemetry STATE/EVENT deduplication (separate architectural work)

## Test plan

- [x] Unit tests pass (`./gradlew testDebugUnitTest`)
- [x] Lint passes (`./gradlew lintDebug`)
- [x] Debug build assembles (`./gradlew assembleDebug`)
- [x] Detekt passes (`./gradlew detekt`)
- [x] `AllRulesHaveCategoryTest` enforces new category invariant on all bundled rules
- [x] `SigmaRuleEngineDisabledRuleTest` enforces disabled-rule behavior
- [x] `UnifiedRefactorRegressionTest` asserts the tester's false positives are fixed end-to-end
- [ ] Manual verification on a physical Unisoc device — post-merge smoke test recommended

## Breaking changes

- `BugReportFinding` type deleted — any external tooling depending on it must migrate to `Finding`
- Export format version bumped — external tools reading the format-version header should
  update their parser to handle the new bundle structure (explicit TELEMETRY / FINDINGS sections)
- Room schema v14 → v16 with two migrations; existing data is preserved

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)" 2>&1 | tail -10
```

- [ ] **Step 3: Confirm PR URL**

The command prints the PR URL. Return it in the final report.

---

## Plan 7 Retrospective Checklist

- [ ] Redacted fixture created at `app/src/test/resources/fixtures/regression-unisoc-clean.txt`
- [ ] Fixture README explains the redaction methodology
- [ ] `UnifiedRefactorRegressionTest` exists with 5 assertions
- [ ] All 5 regression tests pass
- [ ] `testDebugUnitTest`, `lintDebug`, `assembleDebug`, `detekt` all BUILD SUCCESSFUL
- [ ] Manual verification checklist complete
- [ ] Branch pushed to origin
- [ ] PR opened against main with `Fixes #84`
- [ ] PR body references all 7 plans + spec + follow-up issues

---

**End of plan 7. End of refactor.**
