# SIGMA Modifier Spec Compliance Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the SIGMA modifier spec-vs-implementation drift (ships `|all`, makes unknown modifiers fail loudly, enumerates supported modifiers for the Rule Author, and pins the dialect with a compliance test suite).

**Architecture:** Four coordinated fixes across the Kotlin parser/evaluator, the Python validator, the Rule Author skill prompt, and a new compliance test file. The test file is the single source of truth for which modifiers are supported and which are deliberately absent; parser/validator/prompt must keep up with it.

**Tech Stack:** Kotlin (Android library module `app`), JUnit 4, SnakeYAML-Engine, Python 3 + PyYAML (submodule `third-party/android-sigma-rules`).

**Related:** GitHub issue #120, epic #104, spec `docs/superpowers/specs/2026-03-27-sigma-rule-engine-design.md:203`.

---

## File Structure

### Created
- `app/src/test/java/com/androdr/sigma/SigmaModifierComplianceTest.kt` — compliance test suite (supported + deliberately-absent modifier assertions)

### Modified
- `app/src/main/java/com/androdr/sigma/SigmaRule.kt` — add `SigmaModifier.ALL` enum entry; add `allRequired: Boolean = false` flag to `SigmaFieldMatcher`
- `app/src/main/java/com/androdr/sigma/SigmaRuleParser.kt` — rewrite `parseFieldAndModifier` to handle chained modifiers, recognize `|all`, and throw `SigmaRuleParseException` on unknown modifiers (strict mode)
- `app/src/main/java/com/androdr/sigma/SigmaRuleEvaluator.kt` — handle `SigmaModifier.ALL` and the `allRequired` flag in `evaluateFieldMatcher`
- `third-party/android-sigma-rules/validation/validate-rule.py` — add `"all"` to `VALID_MODIFIERS`; extend modifier parsing to validate every `|`-separated token (not only the last)
- `.claude/commands/update-rules-author.md` — replace the `[field_name|modifier: value]` placeholder with an explicit modifier enumeration

---

## Design Notes (READ BEFORE IMPLEMENTING)

**`|all` semantics (from issue #120):**
- **Combining form** `field|contains|all: [A, B, C]` — list-quantifier over the values list: "every value in `[A, B, C]` must contain-match the record's field." `contains` is the base comparison; `all` flips the default `any` quantifier to `all`.
- **Standalone form** `field|all: [A, B, C]` — "the record's list-valued field must contain EVERY value in `[A, B, C]`" (per issue #120 wording "list content equals [A, B, C] (all elements present)").

**Representation choice:**
- Add `SigmaModifier.ALL` enum entry for the standalone form (per issue requirement).
- Add `allRequired: Boolean = false` on `SigmaFieldMatcher` for the combining form (`contains|all`, `startswith|all`, `endswith|all`).
- Standalone `|all` sets `modifier = ALL, allRequired = true`. Combining `|X|all` sets `modifier = X, allRequired = true`.

**Strict fallback:**
- `parseFieldAndModifier` currently silently maps unknown modifiers to `EQUALS`. Replace with `throw SigmaRuleParseException("Unknown modifier '$mod' in field '$key'. Supported: contains, startswith, endswith, re, gte, lte, gt, lt, ioc_lookup, all.")`.
- `SigmaRuleParseException` already propagates through `parse()` and `parseAll()` (see `SigmaRuleParser.kt:123, 138`) — a rule with an unknown modifier is rejected loudly, not silently dropped.

**Validator (`validate-rule.py`) — extend modifier parsing:**
- Current: `_, modifier = field_key.rsplit("|", 1)` only checks the last token.
- New: split the full chain after the field name and validate every token. Accept the `all` combiner either standalone or trailing another modifier.

**Modifier whitelist (MUST match across Kotlin parser, Python validator, Rule Author prompt, and compliance test):**
```
contains, startswith, endswith, re, gte, lte, gt, lt, ioc_lookup, all
```

**Deliberately absent (compliance test must assert rejection):**
```
base64, base64offset, utf16, utf16le, utf16be, wide, cidr, windash, expand, fieldref, contains_all
```

---

## Task 1: Add `SigmaModifier.ALL` and `allRequired` flag to data model

**Files:**
- Modify: `app/src/main/java/com/androdr/sigma/SigmaRule.kt`

- [ ] **Step 1: Modify the data model**

Edit `app/src/main/java/com/androdr/sigma/SigmaRule.kt`:

Change the `SigmaFieldMatcher` data class from:
```kotlin
data class SigmaFieldMatcher(
    val fieldName: String,
    val modifier: SigmaModifier,
    val values: List<Any>
)
```
to:
```kotlin
data class SigmaFieldMatcher(
    val fieldName: String,
    val modifier: SigmaModifier,
    val values: List<Any>,
    val allRequired: Boolean = false
)
```

Change the `SigmaModifier` enum from:
```kotlin
enum class SigmaModifier {
    EQUALS,
    CONTAINS,
    STARTSWITH,
    ENDSWITH,
    RE,
    GTE,
    LTE,
    GT,
    LT,
    IOC_LOOKUP
}
```
to:
```kotlin
enum class SigmaModifier {
    EQUALS,
    CONTAINS,
    STARTSWITH,
    ENDSWITH,
    RE,
    GTE,
    LTE,
    GT,
    LT,
    IOC_LOOKUP,
    ALL
}
```

- [ ] **Step 2: Verify the project still compiles**

Run: `./gradlew :app:compileDebugKotlin`
Expected: BUILD SUCCESSFUL (no usages broken because `allRequired` has a default and `ALL` is not yet referenced anywhere).

- [ ] **Step 3: Commit**

```bash
git add app/src/main/java/com/androdr/sigma/SigmaRule.kt
git commit -m "feat(sigma): add ALL modifier enum + allRequired flag on matcher"
```

---

## Task 2: Parser — strict unknown-modifier handling (TDD)

**Files:**
- Modify: `app/src/main/java/com/androdr/sigma/SigmaRuleParser.kt:294-314`
- Test: `app/src/test/java/com/androdr/sigma/SigmaRuleParserTest.kt`

- [ ] **Step 1: Add the failing test**

Append to `app/src/test/java/com/androdr/sigma/SigmaRuleParserTest.kt` inside the class:

```kotlin
    @Test(expected = SigmaRuleParseException::class)
    fun `unknown modifier throws SigmaRuleParseException, not silent EQUALS fallback`() {
        val yaml = """
            title: Unknown modifier rule
            id: test-unknown-modifier
            category: incident
            logsource:
                product: androdr
                service: app_scanner
            detection:
                selection:
                    permissions|contains_all:
                        - android.permission.READ_SMS
                        - android.permission.SEND_SMS
                condition: selection
            level: medium
        """.trimIndent()

        SigmaRuleParser.parse(yaml)
    }
```

- [ ] **Step 2: Run the test and verify it fails**

Run: `./gradlew :app:testDebugUnitTest --tests com.androdr.sigma.SigmaRuleParserTest`
Expected: `unknown modifier throws...` FAILS (no exception thrown — rule parses because `contains_all` silently falls through to `EQUALS`).

- [ ] **Step 3: Rewrite `parseFieldAndModifier` to be strict and handle `|all`**

In `app/src/main/java/com/androdr/sigma/SigmaRuleParser.kt`, replace the `parseFieldAndModifier` function (lines 294–314) with:

```kotlin
    private fun parseFieldAndModifier(key: String): Triple<String, SigmaModifier, Boolean> {
        val parts = key.split("|")
        val fieldName = parts[0]
        if (parts.size == 1) {
            return Triple(fieldName, SigmaModifier.EQUALS, false)
        }

        // Peel off a trailing "all" combiner; the preceding tokens carry the base modifier.
        val rawTokens = parts.drop(1).map { it.lowercase() }
        val allRequired = rawTokens.lastOrNull() == "all"
        val baseTokens = if (allRequired) rawTokens.dropLast(1) else rawTokens

        val baseModifier = when {
            baseTokens.isEmpty() -> SigmaModifier.ALL  // standalone |all form
            baseTokens.size == 1 -> modifierFromToken(baseTokens[0], key)
            else -> throw SigmaRuleParseException(
                "Too many modifiers in field '$key': only single-base-modifier chains " +
                "(optionally with trailing |all) are supported."
            )
        }
        return Triple(fieldName, baseModifier, allRequired)
    }

    private fun modifierFromToken(token: String, originalKey: String): SigmaModifier = when (token) {
        "contains" -> SigmaModifier.CONTAINS
        "startswith" -> SigmaModifier.STARTSWITH
        "endswith" -> SigmaModifier.ENDSWITH
        "re" -> SigmaModifier.RE
        "gte" -> SigmaModifier.GTE
        "lte" -> SigmaModifier.LTE
        "gt" -> SigmaModifier.GT
        "lt" -> SigmaModifier.LT
        "ioc_lookup" -> SigmaModifier.IOC_LOOKUP
        else -> throw SigmaRuleParseException(
            "Unknown modifier '$token' in field '$originalKey'. " +
            "Supported: contains, startswith, endswith, re, gte, lte, gt, lt, ioc_lookup, all."
        )
    }
```

Also update the caller at `parseSelection` (around line 219) from:
```kotlin
            val (fieldName, modifier) = parseFieldAndModifier(keyStr)
```
to:
```kotlin
            val (fieldName, modifier, allRequired) = parseFieldAndModifier(keyStr)
```

And update the two `SigmaFieldMatcher(...)` constructions in `parseSelection` (around lines 243-247 and 249-253) to include `allRequired = allRequired`. E.g., the first becomes:

```kotlin
                matchers.add(SigmaFieldMatcher(
                    fieldName = fieldName,
                    modifier = modifier,
                    values = validValues,
                    allRequired = allRequired
                ))
```

And similarly for the second block (the `else` branch).

- [ ] **Step 4: Run the test and verify it passes**

Run: `./gradlew :app:testDebugUnitTest --tests com.androdr.sigma.SigmaRuleParserTest`
Expected: `unknown modifier throws...` PASSES; all pre-existing `SigmaRuleParserTest` tests still PASS.

- [ ] **Step 5: Commit**

```bash
git add app/src/main/java/com/androdr/sigma/SigmaRuleParser.kt \
        app/src/test/java/com/androdr/sigma/SigmaRuleParserTest.kt
git commit -m "feat(sigma): strict unknown-modifier rejection + chained modifier parsing"
```

---

## Task 3: Evaluator — honor `SigmaModifier.ALL` and `allRequired` (TDD)

**Files:**
- Modify: `app/src/main/java/com/androdr/sigma/SigmaRuleEvaluator.kt:193-279`
- Test: `app/src/test/java/com/androdr/sigma/SigmaRuleEvaluatorTest.kt`

- [ ] **Step 1: Add two failing tests**

Append to `app/src/test/java/com/androdr/sigma/SigmaRuleEvaluatorTest.kt`:

```kotlin
    @Test
    fun `contains plus all requires every value to match`() {
        val yaml = """
            title: Contains + all combining
            id: test-contains-all
            category: incident
            logsource:
                product: androdr
                service: app_scanner
            detection:
                selection:
                    permissions|contains|all:
                        - READ_SMS
                        - SEND_SMS
                condition: selection
            level: medium
        """.trimIndent()

        val rule = SigmaRuleParser.parse(yaml)!!

        // All required values present -> matches
        val matching = mapOf(
            "permissions" to listOf(
                "android.permission.READ_SMS",
                "android.permission.SEND_SMS",
                "android.permission.INTERNET"
            )
        )
        val findingsMatching = SigmaRuleEvaluator.evaluate(
            listOf(rule), listOf(matching), service = "app_scanner"
        )
        assertEquals(1, findingsMatching.size)

        // Only one of the required values present -> does NOT match
        val partial = mapOf(
            "permissions" to listOf("android.permission.READ_SMS")
        )
        val findingsPartial = SigmaRuleEvaluator.evaluate(
            listOf(rule), listOf(partial), service = "app_scanner"
        )
        assertTrue(findingsPartial.isEmpty())
    }

    @Test
    fun `standalone all modifier requires every value present in list field`() {
        val yaml = """
            title: Standalone all modifier
            id: test-standalone-all
            category: incident
            logsource:
                product: androdr
                service: app_scanner
            detection:
                selection:
                    permissions|all:
                        - android.permission.READ_SMS
                        - android.permission.SEND_SMS
                condition: selection
            level: medium
        """.trimIndent()

        val rule = SigmaRuleParser.parse(yaml)!!

        val matching = mapOf(
            "permissions" to listOf(
                "android.permission.READ_SMS",
                "android.permission.SEND_SMS",
                "android.permission.INTERNET"
            )
        )
        assertEquals(1, SigmaRuleEvaluator.evaluate(
            listOf(rule), listOf(matching), service = "app_scanner"
        ).size)

        val partial = mapOf(
            "permissions" to listOf("android.permission.READ_SMS")
        )
        assertTrue(SigmaRuleEvaluator.evaluate(
            listOf(rule), listOf(partial), service = "app_scanner"
        ).isEmpty())
    }
```

If `assertTrue` / `assertEquals` / `SigmaRuleParser` are not already imported at the top of the test file, add the needed imports — match the existing style of the file.

- [ ] **Step 2: Run tests and verify they fail**

Run: `./gradlew :app:testDebugUnitTest --tests com.androdr.sigma.SigmaRuleEvaluatorTest`
Expected: both new tests FAIL (parser currently returns `SigmaModifier.ALL` for standalone form or `CONTAINS` with `allRequired=true`, but evaluator branches don't recognize `ALL` and ignore `allRequired`).

- [ ] **Step 3: Update the evaluator**

In `app/src/main/java/com/androdr/sigma/SigmaRuleEvaluator.kt`:

(a) Extend the `STRING_MODIFIERS` set (line 54) to keep existing membership — no change needed there.

(b) Inside `evaluateFieldMatcher`, replace the list-aware block (lines 200-225, the `if (fieldValue is List<*> && matcher.modifier in STRING_MODIFIERS) { ... }` section) with a version that flips `.any` to `.all` when `matcher.allRequired` is true:

```kotlin
        // List-aware matching: when fieldValue is a List, apply the modifier
        // element-wise. Default quantifier over `matcher.values` is ANY (default
        // SIGMA semantics). When `allRequired` is set, flip to ALL (|all combiner).
        if (fieldValue is List<*> && matcher.modifier in STRING_MODIFIERS) {
            val elements = fieldValue.filterNotNull().map { it.toString() }
            val valueQuantifier: (List<Any>, (Any) -> Boolean) -> Boolean =
                if (matcher.allRequired) { vs, pred -> vs.all(pred) } else { vs, pred -> vs.any(pred) }
            return when (matcher.modifier) {
                SigmaModifier.EQUALS -> valueQuantifier(matcher.values) { expected ->
                    elements.any { it.equals(expected.toString(), ignoreCase = true) }
                }
                SigmaModifier.CONTAINS -> valueQuantifier(matcher.values) { expected ->
                    val exp = expected.toString().lowercase()
                    elements.any { it.lowercase().contains(exp) }
                }
                SigmaModifier.STARTSWITH -> valueQuantifier(matcher.values) { expected ->
                    val exp = expected.toString().lowercase()
                    elements.any { it.lowercase().startsWith(exp) }
                }
                SigmaModifier.ENDSWITH -> valueQuantifier(matcher.values) { expected ->
                    val exp = expected.toString().lowercase()
                    elements.any { it.lowercase().endsWith(exp) }
                }
                SigmaModifier.RE -> valueQuantifier(matcher.values) { pattern ->
                    elements.any { safeRegexMatch(pattern.toString(), it) }
                }
                else -> false
            }
        }
```

(c) Add `SigmaModifier.ALL` as an explicit branch in the non-list `when` block (inside `evaluateFieldMatcher`, the `return when (matcher.modifier) { ... }` starting around line 227). Append before the closing brace of that `when`:

```kotlin
            SigmaModifier.ALL -> {
                // Standalone |all: record field must be a list whose elements cover
                // every required value (case-insensitive equality per value).
                if (fieldValue !is List<*>) return false
                val elements = fieldValue.filterNotNull().map { it.toString().lowercase() }
                matcher.values.all { expected ->
                    elements.contains(expected.toString().lowercase())
                }
            }
```

Note: the standalone-ALL branch is also reachable via the list-aware block above when `allRequired` is true and base modifier is `EQUALS`. Because `SigmaModifier.ALL` is not in `STRING_MODIFIERS`, the list-aware block doesn't catch it — the explicit branch above is the canonical path. Keep them consistent (both use case-insensitive equality, both require the field to be a list).

- [ ] **Step 4: Run tests and verify they pass**

Run: `./gradlew :app:testDebugUnitTest --tests com.androdr.sigma.SigmaRuleEvaluatorTest`
Expected: both new tests PASS; all pre-existing `SigmaRuleEvaluatorTest` tests still PASS.

- [ ] **Step 5: Commit**

```bash
git add app/src/main/java/com/androdr/sigma/SigmaRuleEvaluator.kt \
        app/src/test/java/com/androdr/sigma/SigmaRuleEvaluatorTest.kt
git commit -m "feat(sigma): evaluate ALL modifier + allRequired quantifier"
```

---

## Task 4: Python validator — support `all` modifier + chained modifier validation

**Files:**
- Modify: `third-party/android-sigma-rules/validation/validate-rule.py:22-25, 83-98`

- [ ] **Step 1: Add `all` to `VALID_MODIFIERS`**

In `third-party/android-sigma-rules/validation/validate-rule.py`, change:
```python
VALID_MODIFIERS = {
    "contains", "startswith", "endswith", "re",
    "gte", "lte", "gt", "lt", "ioc_lookup",
}
```
to:
```python
VALID_MODIFIERS = {
    "contains", "startswith", "endswith", "re",
    "gte", "lte", "gt", "lt", "ioc_lookup", "all",
}
```

- [ ] **Step 2: Fix the modifier parsing loop to validate every chained token**

Replace the block starting at `for sel_name, sel_value in detection.items():` (lines 83-98) with:

```python
    for sel_name, sel_value in detection.items():
        if sel_name == "condition" or not isinstance(sel_value, dict):
            continue
        for field_key in sel_value:
            if "|" not in field_key:
                continue
            tokens = field_key.split("|")
            # tokens[0] is the field name; tokens[1:] are modifiers (chain).
            for modifier in tokens[1:]:
                if modifier not in VALID_MODIFIERS:
                    errors.append(f"Invalid modifier '{modifier}' in field '{field_key}'")
            # Regex length check applies when the final modifier is 're'.
            if tokens[-1] == "re":
                values = sel_value[field_key]
                if isinstance(values, list):
                    for v in values:
                        if isinstance(v, str) and len(v) > MAX_REGEX_LENGTH:
                            errors.append(f"Regex pattern exceeds {MAX_REGEX_LENGTH} chars in '{field_key}'")
                elif isinstance(values, str) and len(values) > MAX_REGEX_LENGTH:
                    errors.append(f"Regex pattern exceeds {MAX_REGEX_LENGTH} chars in '{field_key}'")
```

- [ ] **Step 3: Smoke-test the validator against bundled rules**

The submodule is pinned, so validate a sample rule from `app/src/main/res/raw/` to confirm nothing regresses:

```bash
cd third-party/android-sigma-rules
python3 validation/validate-rule.py \
  ../../app/src/main/res/raw/sigma_androdr_001.yml
```

Expected: `PASS: sigma_androdr_001.yml` (or similar — any rule file that exists in `res/raw`).

- [ ] **Step 4: Smoke-test rejection of the hallucinated modifier**

Create a temp file `/tmp/bad-rule.yml`:

```yaml
title: Hallucinated modifier
id: androdr-999
status: experimental
logsource:
    product: androdr
    service: app_scanner
detection:
    selection:
        permissions|contains_all:
            - android.permission.READ_SMS
    condition: selection
level: medium
```

Run: `python3 third-party/android-sigma-rules/validation/validate-rule.py /tmp/bad-rule.yml`
Expected: exits with status 1 and prints `Invalid modifier 'contains_all' in field 'permissions|contains_all'` (plus any other schema complaints; that specific error must appear).

- [ ] **Step 5: Commit**

```bash
git add third-party/android-sigma-rules/validation/validate-rule.py
git commit -m "feat(validator): add |all modifier + validate every chained modifier token"
```

(Note: the `third-party/android-sigma-rules` submodule points to its own repo. If the submodule's working tree is clean and the validator lives inside it, this commit lands in the submodule repo first. After committing in the submodule, also bump the submodule pointer in the parent repo with `git add third-party/android-sigma-rules && git commit -m "build: bump sigma-rules submodule for |all modifier"`. Push the submodule commit too, otherwise CI cannot check out the updated pointer. If the reviewer prefers a single cross-repo PR flow, coordinate the submodule merge first.)

---

## Task 5: Rule Author skill — explicit modifier enumeration

**Files:**
- Modify: `.claude/commands/update-rules-author.md:78-82`

- [ ] **Step 1: Replace the template placeholder with enumerated modifiers**

In `.claude/commands/update-rules-author.md`, find the `## Rule Template` section (starts around line 64). The current detection block in the template looks like:

```yaml
detection:
    selection:
        [field_name|modifier: value]
    condition: selection
```

Replace that template snippet with:

```yaml
detection:
    selection:
        [field_name|modifier: value]    # see "Supported modifiers" below
    condition: selection
```

Then, immediately after the ```yaml block that contains the template (look for the line `## Severity Assignment` and insert before it), add a new subsection:

```markdown
### Supported modifiers

Use ONLY these modifiers. Any other modifier name will be rejected by the parser (Gate 1) and fail the build.

- `|contains` — substring match (case-insensitive)
- `|startswith` — prefix match (case-insensitive)
- `|endswith` — suffix match (case-insensitive)
- `|re` — regex match (max 500 chars; use sparingly)
- `|gte`, `|lte`, `|gt`, `|lt` — numeric comparison
- `|all` — combiner; "every value in the list must match" (e.g., `permissions|contains|all: [A, B, C]` requires the record's permissions to contain ALL of A, B, and C, not just ANY)
- `|ioc_lookup` — AndroDR extension; reference a named IOC database

**Do NOT use** upstream SIGMA HQ modifiers not listed above (e.g., `base64`, `base64offset`, `utf16`, `utf16le`, `utf16be`, `wide`, `cidr`, `windash`, `expand`, `fieldref`, `contains_all`). If a rule needs one, record a `telemetry_gap` decision instead of inventing syntax.

**List-field defaults (no `|all` suffix):** `field|contains: [A, B, C]` on a list-valued field matches if ANY element of the field contains ANY of [A, B, C]. Add `|all` to require every listed value.
```

- [ ] **Step 2: Commit**

```bash
git add .claude/commands/update-rules-author.md
git commit -m "docs(rule-author): enumerate supported modifiers, forbid hallucinations"
```

---

## Task 6: Compliance test suite (SIGMA HQ dialect pin)

**Files:**
- Create: `app/src/test/java/com/androdr/sigma/SigmaModifierComplianceTest.kt`

- [ ] **Step 1: Write the compliance test file**

Create `app/src/test/java/com/androdr/sigma/SigmaModifierComplianceTest.kt`:

```kotlin
package com.androdr.sigma

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/**
 * Executable documentation of AndroDR's SIGMA dialect.
 *
 * The SUPPORTED group asserts which modifiers parse AND evaluate correctly.
 * Adding a new modifier MUST come with a new test here.
 *
 * The DELIBERATELY ABSENT group asserts which upstream SIGMA HQ modifiers
 * are rejected. Promoting one to "supported" requires moving its test from
 * the absent group to the supported group in the same PR.
 *
 * See GitHub issue #120 for background.
 */
class SigmaModifierComplianceTest {

    private fun ruleWithModifier(modifier: String, value: String = "\"test\""): String = """
        title: Compliance probe
        id: test-compliance
        category: incident
        logsource:
            product: androdr
            service: app_scanner
        detection:
            selection:
                package_name|$modifier: $value
            condition: selection
        level: medium
    """.trimIndent()

    // ------------------------- SUPPORTED MODIFIERS -------------------------

    @Test
    fun `contains modifier parses and matches substring`() {
        val yaml = ruleWithModifier("contains", "\"spyware\"")
        val rule = SigmaRuleParser.parse(yaml)!!
        val record = mapOf("package_name" to "com.evil.spyware.client")
        val findings = SigmaRuleEvaluator.evaluate(listOf(rule), listOf(record), "app_scanner")
        assertEquals(1, findings.size)
    }

    @Test
    fun `startswith modifier parses and matches prefix`() {
        val yaml = ruleWithModifier("startswith", "\"com.evil\"")
        val rule = SigmaRuleParser.parse(yaml)!!
        val record = mapOf("package_name" to "com.evil.client")
        assertEquals(1, SigmaRuleEvaluator.evaluate(listOf(rule), listOf(record), "app_scanner").size)
    }

    @Test
    fun `endswith modifier parses and matches suffix`() {
        val yaml = ruleWithModifier("endswith", "\".spyware\"")
        val rule = SigmaRuleParser.parse(yaml)!!
        val record = mapOf("package_name" to "com.evil.spyware")
        assertEquals(1, SigmaRuleEvaluator.evaluate(listOf(rule), listOf(record), "app_scanner").size)
    }

    @Test
    fun `re modifier parses and matches regex`() {
        val yaml = ruleWithModifier("re", "\"^com\\\\.evil\\\\..*\"")
        val rule = SigmaRuleParser.parse(yaml)!!
        val record = mapOf("package_name" to "com.evil.anything")
        assertEquals(1, SigmaRuleEvaluator.evaluate(listOf(rule), listOf(record), "app_scanner").size)
    }

    @Test
    fun `numeric comparison modifiers parse and evaluate`() {
        val yaml = """
            title: Numeric probe
            id: test-numeric-compliance
            category: device_posture
            logsource:
                product: androdr
                service: device_auditor
            detection:
                too_old:
                    patch_age_days|gte: 90
                too_new:
                    patch_age_days|lt: 1
                between:
                    patch_age_days|gt: 30
                bounded:
                    patch_age_days|lte: 365
                condition: too_old
            level: medium
        """.trimIndent()
        val rule = SigmaRuleParser.parse(yaml)!!
        val record = mapOf("patch_age_days" to 120)
        val findings = SigmaRuleEvaluator.evaluate(listOf(rule), listOf(record), "device_auditor")
        assertEquals(1, findings.size)
    }

    @Test
    fun `all modifier standalone requires every value present in list field`() {
        val yaml = """
            title: All standalone
            id: test-all-standalone
            category: incident
            logsource:
                product: androdr
                service: app_scanner
            detection:
                selection:
                    permissions|all:
                        - android.permission.READ_SMS
                        - android.permission.SEND_SMS
                condition: selection
            level: medium
        """.trimIndent()
        val rule = SigmaRuleParser.parse(yaml)!!
        val matching = mapOf("permissions" to listOf(
            "android.permission.READ_SMS", "android.permission.SEND_SMS", "android.permission.INTERNET"
        ))
        val partial = mapOf("permissions" to listOf("android.permission.READ_SMS"))
        assertEquals(1, SigmaRuleEvaluator.evaluate(listOf(rule), listOf(matching), "app_scanner").size)
        assertTrue(SigmaRuleEvaluator.evaluate(listOf(rule), listOf(partial), "app_scanner").isEmpty())
    }

    @Test
    fun `contains plus all combining modifier requires all values to contain-match`() {
        val yaml = """
            title: Contains + all
            id: test-contains-all
            category: incident
            logsource:
                product: androdr
                service: app_scanner
            detection:
                selection:
                    permissions|contains|all:
                        - READ_SMS
                        - SEND_SMS
                condition: selection
            level: medium
        """.trimIndent()
        val rule = SigmaRuleParser.parse(yaml)!!
        val matching = mapOf("permissions" to listOf(
            "android.permission.READ_SMS", "android.permission.SEND_SMS"
        ))
        val partial = mapOf("permissions" to listOf("android.permission.READ_SMS"))
        assertEquals(1, SigmaRuleEvaluator.evaluate(listOf(rule), listOf(matching), "app_scanner").size)
        assertTrue(SigmaRuleEvaluator.evaluate(listOf(rule), listOf(partial), "app_scanner").isEmpty())
    }

    @Test
    fun `ioc_lookup modifier parses and evaluates with registered database`() {
        val yaml = """
            title: IOC lookup probe
            id: test-ioc-compliance
            category: incident
            logsource:
                product: androdr
                service: app_scanner
            detection:
                selection:
                    package_name|ioc_lookup: malware_packages
                condition: selection
            level: high
        """.trimIndent()
        val rule = SigmaRuleParser.parse(yaml)!!
        val record = mapOf("package_name" to "com.evil.client")
        val lookups = mapOf<String, (Any) -> Boolean>(
            "malware_packages" to { v -> v.toString() == "com.evil.client" }
        )
        assertEquals(1, SigmaRuleEvaluator.evaluate(
            listOf(rule), listOf(record), "app_scanner", iocLookups = lookups
        ).size)
    }

    // ----------------------- DELIBERATELY ABSENT --------------------------

    private fun assertRejected(modifier: String) {
        val yaml = ruleWithModifier(modifier, "\"x\"")
        try {
            SigmaRuleParser.parse(yaml)
            fail("Modifier '$modifier' should be rejected but parsed successfully")
        } catch (e: SigmaRuleParseException) {
            assertTrue(
                "Exception message should mention the modifier name. Got: ${e.message}",
                e.message!!.contains(modifier)
            )
        }
    }

    @Test fun `base64 modifier is rejected`() = assertRejected("base64")
    @Test fun `base64offset modifier is rejected`() = assertRejected("base64offset")
    @Test fun `utf16 modifier is rejected`() = assertRejected("utf16")
    @Test fun `utf16le modifier is rejected`() = assertRejected("utf16le")
    @Test fun `utf16be modifier is rejected`() = assertRejected("utf16be")
    @Test fun `wide modifier is rejected`() = assertRejected("wide")
    @Test fun `cidr modifier is rejected`() = assertRejected("cidr")
    @Test fun `windash modifier is rejected`() = assertRejected("windash")
    @Test fun `expand modifier is rejected`() = assertRejected("expand")
    @Test fun `fieldref modifier is rejected`() = assertRejected("fieldref")

    @Test fun `contains_all hallucinated modifier is rejected`() = assertRejected("contains_all")

    @Test
    fun `unknown modifier emits parse error, not silent EQUALS fallback`() {
        // Guards against regression of the silent `EQUALS` fallback.
        val yaml = ruleWithModifier("nosuchmodifier", "\"x\"")
        try {
            SigmaRuleParser.parse(yaml)
            fail("Unknown modifier must raise SigmaRuleParseException, not silently map to EQUALS")
        } catch (e: SigmaRuleParseException) {
            assertTrue(e.message!!.contains("Unknown modifier"))
        }
    }
}
```

- [ ] **Step 2: Run the compliance suite**

Run: `./gradlew :app:testDebugUnitTest --tests com.androdr.sigma.SigmaModifierComplianceTest`
Expected: ALL tests PASS (supported modifiers parse and match; absent modifiers raise `SigmaRuleParseException`).

- [ ] **Step 3: Run the full SIGMA test suite to confirm nothing else regressed**

Run: `./gradlew :app:testDebugUnitTest --tests "com.androdr.sigma.*"`
Expected: all tests in `com.androdr.sigma.*` PASS, including `BundledRulesSchemaCrossCheckTest` (which cross-validates every bundled rule through both the Kotlin parser and the Python schema). If any bundled rule uses an unknown modifier today, this will surface it — investigate and fix the rule rather than weakening strict mode.

- [ ] **Step 4: Commit**

```bash
git add app/src/test/java/com/androdr/sigma/SigmaModifierComplianceTest.kt
git commit -m "test(sigma): compliance suite pinning supported + deliberately-absent modifiers"
```

---

## Task 7: Full verification + PR

**Files:** (verification only)

- [ ] **Step 1: Full unit test run**

Run: `./gradlew :app:testDebugUnitTest`
Expected: BUILD SUCCESSFUL, zero test failures.

- [ ] **Step 2: Lint**

Run: `./gradlew :app:lintDebug`
Expected: no new lint errors introduced by changes.

- [ ] **Step 3: Validate all bundled rules through the updated Python validator**

```bash
cd third-party/android-sigma-rules
for rule in ../../app/src/main/res/raw/sigma_androdr_*.yml; do
  python3 validation/validate-rule.py "$rule" || echo "FAILED: $rule"
done
cd ../..
```

Expected: every rule prints `PASS`. If any rule fails (because it used an unknown modifier that silently worked as EQUALS), open a sub-issue to fix that rule — do NOT weaken the validator.

- [ ] **Step 4: Push and open PR**

```bash
git push -u origin <branch-name>
gh pr create --title "fix(sigma): modifier spec compliance (|all, strict fallback, tests) — #120" \
  --body "$(cat <<'EOF'
## Summary

- Implements the `|all` quantifier modifier (standalone and combining forms with `contains`/`startswith`/`endswith`).
- Replaces silent unknown-modifier → `EQUALS` fallback with `SigmaRuleParseException`.
- Validator: parses every chained modifier token, not only the last; accepts `all`.
- Rule Author skill prompt: enumerates supported modifiers and forbids hallucinated names (e.g., `contains_all`).
- New `SigmaModifierComplianceTest` pins the dialect — supported modifiers must parse AND evaluate; deliberately-absent modifiers must be rejected.

Closes #120.

## Test plan

- [ ] `./gradlew :app:testDebugUnitTest` passes locally
- [ ] `./gradlew :app:lintDebug` — no new warnings
- [ ] Manually verified rejection of `permissions|contains_all:` matches the Mamont regression case
- [ ] Every bundled rule in `app/src/main/res/raw/` validates through updated `validate-rule.py`
EOF
)"
```

Expected: PR opened against `main`.

---

## Self-Review Checklist

- **Spec coverage:** all four fixes in issue #120 have tasks — `|all` (Task 1+3), strict fallback (Task 2), modifier enumeration in skill prompt (Task 5), compliance tests (Task 6). Validator update (Task 4) keeps Python and Kotlin in sync so `BundledRulesSchemaCrossCheckTest` remains green.
- **Placeholder scan:** no `TBD` / `...` / vague steps; every code block shows the exact change.
- **Type consistency:** `SigmaFieldMatcher` gains `allRequired: Boolean = false` in Task 1 and every subsequent reference uses that name. `SigmaModifier.ALL` is introduced in Task 1 and referenced consistently in Tasks 3 and 6. `SigmaRuleParseException` (existing class from `SigmaRuleParser.kt:15`) is reused; no new exception type introduced.
- **Existing constraints honored:** bundled rules only use `contains/endswith/gte/ioc_lookup/startswith` today (verified by grep), so strict mode will not break any. `BundledRulesSchemaCrossCheckTest` enforces Kotlin↔Python agreement post-merge.
