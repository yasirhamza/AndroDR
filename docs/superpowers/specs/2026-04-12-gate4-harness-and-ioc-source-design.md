# Gate 4 Programmatic Test Harness + IOC Source Validation

**Issue:** #106
**Date:** 2026-04-12
**Status:** Approved

## Summary

Turn Gate 4 (dry-run evaluation) from a manual hand-trace into a programmatic
Kotlin test harness, and enforce IOC data `source` field validation so polluted
or test-origin data cannot reach production IOC files.

## Deliverables

1. Gate 4 Kotlin test harness
2. IOC source validation (Python + JSON enum)
3. Skill update (`update-rules-validate.md`)

---

## 1. Gate 4 Test Harness

### Files

- `app/src/test/java/com/androdr/sigma/GateFourTestHarness.kt`
- `app/src/test/java/com/androdr/sigma/GateFourFixtureTest.kt`
- `app/src/test/resources/gate4-fixtures/sideloaded-app.yml`
- `app/src/test/resources/gate4-fixtures/package-ioc.yml`
- `app/src/test/resources/gate4-fixtures/accessibility-atom.yml`

### API

```kotlin
object GateFourTestHarness {
    fun runGate4(
        rule: SigmaRule,
        truePositives: List<Map<String, Any?>>,
        trueNegatives: List<Map<String, Any?>>,
        iocStubs: Map<String, Set<String>> = emptyMap()
    ): Gate4Result
}

data class Gate4Result(
    val pass: Boolean,
    val tpFired: Boolean,
    val tnClean: Boolean,
    val errors: List<String>
)
```

### Logic

1. Build `iocLookups: Map<String, (Any) -> Boolean>` from `iocStubs` — each
   key maps to a lambda that returns `true` if the value (as string) is in the
   stub set.
2. For each TP record: call `SigmaRuleEvaluator.evaluate(listOf(rule),
   listOf(record), rule.service, iocLookups)`. Expect >= 1 finding.
3. For each TN record: same call. Expect 0 findings.
4. `tpFired` = all TP records produced findings. `tnClean` = all TN records
   produced zero findings. `pass` = tpFired && tnClean.
5. Collect error strings for any failures (which record failed, what was
   expected vs actual).
6. Warn (include in errors) if any `iocStubs` key is not referenced by the
   rule's detection (catches fixture authoring typos).

### IOC Lookup Handling

Rules using `ioc_lookup` (e.g. `package_name|ioc_lookup: package_ioc_db`) are
tested with **stubbed lookups**. The fixture declares which indicators the stub
DB should contain. This tests rule condition wiring in isolation — Gate 2
separately verifies that the real IOC data contains the indicators.

### Fixture Format

Each fixture is a YAML file in `app/src/test/resources/gate4-fixtures/`:

```yaml
rule_file: sigma_androdr_010_sideloaded_app.yml
service: app_scanner
ioc_stubs:
  package_ioc_db:
    - "com.malware.test"
true_positives:
  - package_name: "com.malware.test"
    is_sideloaded: true
    is_system_app: false
true_negatives:
  - package_name: "com.google.android.gm"
    is_sideloaded: false
    is_system_app: false
```

Fields:
- `rule_file`: filename of the bundled rule in `res/raw/` (the test reads it
  from disk at the project root path)
- `service`: logsource service to pass to the evaluator
- `ioc_stubs`: optional map of IOC DB name -> list of indicators that should
  "exist" in the stub
- `true_positives`: list of telemetry records that must trigger the rule
- `true_negatives`: list of telemetry records that must NOT trigger the rule

### Fixture-Driven Test

`GateFourFixtureTest.kt` uses JUnit `@ParameterizedTest` with a
`@MethodSource` that discovers all `*.yml` files in `gate4-fixtures/`. Each
fixture file becomes one test case. The test:

1. Reads the rule YAML from `app/src/main/res/raw/{rule_file}`
2. Parses it with `SigmaRuleParser.parse()`
3. Parses fixture YAML for TP/TN records and IOC stubs
4. Asserts `rule.service == fixture.service` (catches fixture/rule mismatch)
5. Calls `GateFourTestHarness.runGate4()`
6. Asserts `result.pass == true`

### Representative Fixtures

| Fixture | Rule | Tests |
|---------|------|-------|
| `sideloaded-app.yml` | androdr-010 | Simple selection with boolean + field match |
| `package-ioc.yml` | androdr-001 | `ioc_lookup` modifier with stubbed package DB |
| `accessibility-atom.yml` | androdr-060 | Atom rule (accessibility service detection) |

---

## 2. IOC Source Validation

### Allowed Sources Registry

**File:** `third-party/android-sigma-rules/validation/allowed-sources.json`

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

### New: validate-ioc-data.py

**File:** `third-party/android-sigma-rules/validation/validate-ioc-data.py`

**Usage:** `python3 validate-ioc-data.py <ioc-data-file.yml>`

**Validation checks:**

1. **Source field present** — every entry must have `source`
2. **Source in allowed set** — read from `allowed-sources.json` (id field only)
3. **Blocked categories** — reject `TEST`, `FIXTURE`, `SIMULATION`, `DEBUG`
4. **Blocked family patterns** — reject entries where family/familyName contains
   "test", "fixture", "simulation", "sample", "example" (case-insensitive)
5. **Cert hash format** — if entry has `indicator` that looks like a hash (in
   `cert-hashes.yml`), must be exactly 64 lowercase hex chars
6. **No duplicates** — no repeated `indicator` values within the same file

**Exit codes:** 0 = valid, 1 = validation errors, 2 = file not found / parse error

### Modified: merge-ioc-data.py

Add a validation pass before merging:

1. Load `allowed-sources.json` from the submodule path
   (`third-party/android-sigma-rules/validation/allowed-sources.json`)
2. For each entry being merged, check `source` is present and in allowed set
3. If any entry fails, print errors and exit non-zero (no partial merge)

---

## 3. Skill Update

**File:** `.claude/commands/update-rules-validate.md`

Gate 4 section rewritten from:
> "Write a temporary JUnit test or manually trace the evaluation logic"

To:
> "Create a fixture YAML and run the harness test"

Updated content describes:
- The fixture format (rule_file, service, ioc_stubs, true_positives,
  true_negatives)
- How to run: `./gradlew testDebugUnitTest --tests
  "com.androdr.sigma.GateFourFixtureTest"`
- That IOC lookups are stubbed (not real DB)

IOC Data Validation section updated to reference `validate-ioc-data.py` with
usage instructions.

---

## Out of Scope

- Fixture-file-based runner for human developers (no dual-use mode)
- Real IOC data loading in Gate 4 (stubs only; Gate 2 covers IOC presence)
- Correlation rule evaluation in the harness (only atom/detection rules)
- Changes to `rule-schema.json` (handled by sub-plan 1a)

## Dependencies

- PR #110 (sub-plan 1a) merged — provides `SigmaRuleParser` stability and
  `BundledRulesSchemaCrossCheckTest` as the build-time gate
- Submodule initialized with `allowed-sources.json` pushed to remote
