# Privacy Scan Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A user-started privacy scan that reads the class-name tables of every installed app's code, correlates 30 days of attributed DNS lookups, matches both against a mirrored Exodus tracker registry, and shows precise per-app facts ranked against the user's own refused-category threshold, on its own screen.

**Architecture:** Two new facts (an app's distinct Java packages; its tracker-domain lookups) joined on-device with a tracker registry that lives in the rules repo as `ioc-data/trackers.yml` (manifest-verified, 12 h refresh, bundled snapshot for cold start). Results live in dedicated `privacy_*` Room tables outside the security scan store; nothing here raises alerts or touches the security verdict. UI: a Dashboard card → `privacy` route with By-app / By-tracker views and a threshold setting.

**Tech Stack:** Kotlin, Jetpack Compose (Material 3), Hilt, Room 2.x (schema export on), DataStore preferences, snakeyaml-engine 2.7, kotlinx.coroutines; JUnit4 + MockK + Robolectric for tests; Python 3 + PyYAML + jsonschema in the rules repo.

**Spec:** `docs/superpowers/specs/2026-11-06-privacy-scan-design.md`

## Global Constraints

- Rules-repo changes follow CLAUDE.md "Safe ordering": rules branch → AndroDR submodule bump to that branch commit → AndroDR CI green → merge rules branch → re-point submodule at main.
- Any edit under `ioc-data/` regenerates `ioc-data.sha256` (CLAUDE.md recipe); `IocDataManifestIntegrityTest` must stay green.
- Emitters emit facts only; no tracker name, category or threshold is hard-coded in Kotlin (spec §5.4).
- Privacy results are never a security finding, never a `ScanResult`, never `source = LIVE_SCAN`, never in History or the exported security report (spec §3, §5.4).
- No blocking/disabling of trackers; no AndroDR-authored score (spec §3).
- The privacy scan runs only when the user starts it; it runs under `ScanLock.withWriter` (spec §5.5).
- Tracker categories are exactly: Advertisement, Profiling, Identification, Location, Analytics, Crash reporting (spec §4.1). Default threshold: all refused except Crash reporting.
- Every finding states its evidence source: "found in code", "seen on network", or both (spec §2 goal 2).
- UI copy per spec §4.3: facts, not judgements; the obfuscation caveat sentence; "none from the registry found", never "no trackers".
- Attribution: "Tracker data: Exodus Privacy (ODbL 1.0)" on the privacy screen; ODbL notice in the rules-repo file and README (spec §5.3).
- Regression policy (CLAUDE.md): every behaviour ships with a deterministic test; network bodies read through `readTextCapped`/`IocDataManifest` only (`NetworkBodyReadGateTest`).
- detekt: max line length 120, `ReturnCount` max 3, `TooManyFunctions` 15 per class; lint warnings are errors in release.
- Gradle invocations use the Temurin 21 env form: `JAVA_HOME=/home/yasir/.gradle/jdks/eclipse_adoptium-21-amd64-linux.2 ANDROID_HOME=/home/yasir/Android/Sdk ./gradlew …`. Delete `app/build/test-results/testDebugUnitTest` before parsing results.

## Review Focus

1. An app whose code is fully obfuscated (no registry prefix matches, no network evidence) must render as "none from the registry found", never "no trackers" — test in Task 10.
2. An APK the app cannot open (permission denied, missing file, truncated dex) must become a visible per-app `COULD_NOT_INSPECT` outcome, never a silent omission or a scan abort — tests in Tasks 5 and 6.
3. A registry file that is malformed, over the cap, or nested too deeply must leave the previous (or bundled) registry in place — tests in Task 4.
4. DNS events with no attribution (`appName` null / `appUid` −1) and events for apps no longer installed must not crash correlation or attach to the wrong app — test in Task 9.
5. Usage-access not granted must yield "background: unknown", not 0 — test in Task 9.

---

### Task 1: Rules repo — Exodus mirror script and `ioc-data/trackers.yml`

**Files:**
- Create: `third-party/android-sigma-rules/validation/mirror-exodus-trackers.py`
- Create: `third-party/android-sigma-rules/ioc-data/trackers.yml` (generated)
- Create: `third-party/android-sigma-rules/validation/test_mirror_exodus_trackers.py`
- Modify: `third-party/android-sigma-rules/README.md` (ODbL notice paragraph)

Work on a rules-repo branch `feat/tracker-registry` inside the submodule checkout (`cd third-party/android-sigma-rules && git checkout -b feat/tracker-registry origin/main`).

**Interfaces:**
- Produces: `ioc-data/trackers.yml` with this shape (consumed by Tasks 2, 3, 4):

```yaml
version: 1
source: exodus-privacy
source_url: https://reports.exodus-privacy.eu.org/api/trackers
license: ODbL-1.0
attribution: "Exodus Privacy — https://exodus-privacy.eu.org — Open Database License 1.0"
generated_at: "2026-11-06"
trackers:
  - id: 49                       # Exodus id, integer, unique, ascending
    name: "Google Firebase Analytics"
    website: "https://firebase.google.com/"
    categories: [Analytics]      # subset of the six spec labels, exact spelling
    code_prefixes:               # from code_signature split on "|", trimmed, non-empty, unique, sorted
      - com.google.android.gms.measurement
      - com.google.firebase.analytics
    domain_patterns:             # from network_signature split on "|", trimmed, non-empty; regex text
      - "firebase\\.google\\.com"
```
- Produces: `mirror-exodus-trackers.py` CLI: `python3 validation/mirror-exodus-trackers.py --out ioc-data/trackers.yml [--from-json FILE]` (`--from-json` reads a saved API response instead of the network; used by tests and offline runs). Exit 1 if fewer than 300 trackers or any category outside the six.

- [ ] **Step 1: Write the failing tests** in `validation/test_mirror_exodus_trackers.py`

```python
def test_render_normalises_signatures(tmp_path):
    api = {"trackers": {"7": {"id": 7, "name": "T", "website": "https://t", "categories": ["Analytics", "Profiling"],
                              "code_signature": "com.b.|com.a.| ", "network_signature": "a\\.com|b\\.com"}}}
    doc = render(api)                       # pure function, returns the YAML dict
    t = doc["trackers"][0]
    assert t["code_prefixes"] == ["com.a", "com.b"]          # trailing dots stripped, sorted, blanks dropped
    assert t["domain_patterns"] == ["a\\.com", "b\\.com"]
    assert doc["license"] == "ODbL-1.0" and doc["version"] == 1

def test_render_rejects_unknown_category():
    api = {"trackers": {"1": {"id": 1, "name": "X", "categories": ["Malware"], "code_signature": "x.y", "network_signature": ""}}}
    with pytest.raises(SystemExit): render(api)

def test_render_is_deterministic_by_id():
    api = {"trackers": {"9": {"id": 9, "name": "B", "categories": ["Location"], "code_signature": "b.", "network_signature": ""},
                        "2": {"id": 2, "name": "A", "categories": ["Location"], "code_signature": "a.", "network_signature": ""}}}
    assert [t["id"] for t in render(api)["trackers"]] == [2, 9]

def test_main_from_json_writes_file(tmp_path):
    ...  # write a 300-entry synthetic API JSON, run main(["--from-json", str(f), "--out", str(out)]), assert out exists and yaml.safe_load(out)["trackers"] has 300 entries
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd third-party/android-sigma-rules && python3 -m pytest validation/test_mirror_exodus_trackers.py -q`
Expected: FAIL with "No module named 'mirror_exodus_trackers'" (import error for the script module; load it via `importlib` from the file path as the sibling tests do).

- [ ] **Step 3: Implement `render(api: dict) -> dict` and `main(argv) -> int` in `validation/mirror-exodus-trackers.py`**

Normalisation rules in `render`: split `code_signature`/`network_signature` on `|`; strip whitespace; drop empty; strip trailing `.` from code prefixes; de-duplicate; sort; require each code prefix length ≥ 3; categories must be a subset of the six exact labels else `sys.exit(1)` naming the tracker; output sorted by integer id; `generated_at` is today's UTC date. Network fetch (no `--from-json`) uses `urllib.request` with a 60 s timeout. Write YAML with `yaml.safe_dump(sort_keys=False, allow_unicode=True, width=120)`.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `python3 -m pytest validation/test_mirror_exodus_trackers.py -q`
Expected: 4 passed

- [ ] **Step 5: Generate the real file and add the licence notice**

Run: `python3 validation/mirror-exodus-trackers.py --out ioc-data/trackers.yml` then `python3 -c "import yaml;d=yaml.safe_load(open('ioc-data/trackers.yml'));print(len(d['trackers']))"`
Expected: a number ≥ 400. Add to README.md under the ioc-data section: one paragraph stating `ioc-data/trackers.yml` is a mirror of the Exodus Privacy tracker database, licensed ODbL 1.0 (link), that derived copies must stay under ODbL, and that it is regenerated by `validation/mirror-exodus-trackers.py`.

- [ ] **Step 6: Commit (rules repo)**

```bash
git add validation/mirror-exodus-trackers.py validation/test_mirror_exodus_trackers.py ioc-data/trackers.yml README.md
git commit -m "feat(ioc-data): mirror the Exodus Privacy tracker registry (ODbL)"
```

---

### Task 2: Rules repo — structural validator, manifest, CI

**Files:**
- Modify: `third-party/android-sigma-rules/validation/validate-ioc-data.py` (dispatch block before the `entries` fallback, after the brand-file block)
- Modify: `third-party/android-sigma-rules/validation/test_validate_ioc_data.py`
- Modify: `third-party/android-sigma-rules/ioc-data.sha256` (regenerated)

**Interfaces:**
- Produces: `validate_trackers_file(data: dict, filename: str) -> list[str]` in `validate-ioc-data.py`; `main()` routes `trackers.yml` to it.

- [ ] **Step 1: Write the failing tests** (add to `test_validate_ioc_data.py`, following its existing helper style for brand files)

```python
def test_trackers_file_valid_passes():
    assert validate_trackers_file(_trackers_doc(), "trackers.yml") == []

def test_trackers_file_rejects_unknown_category():
    d = _trackers_doc(); d["trackers"][0]["categories"] = ["Malware"]
    assert any("category" in e for e in validate_trackers_file(d, "trackers.yml"))

def test_trackers_file_rejects_duplicate_id_and_short_prefix():
    d = _trackers_doc(); d["trackers"].append(dict(d["trackers"][0])); d["trackers"][0]["code_prefixes"] = ["ab"]
    errs = validate_trackers_file(d, "trackers.yml")
    assert any("duplicate id" in e for e in errs) and any("prefix" in e for e in errs)

def test_trackers_file_requires_license_and_version():
    d = _trackers_doc(); d.pop("license")
    assert any("license" in e for e in validate_trackers_file(d, "trackers.yml"))

def test_trackers_file_rejects_invalid_regex():
    d = _trackers_doc(); d["trackers"][0]["domain_patterns"] = ["("]
    assert any("domain_patterns" in e for e in validate_trackers_file(d, "trackers.yml"))
```
`_trackers_doc()` returns a two-tracker document in the Task 1 shape.

- [ ] **Step 2: Run to verify failure**

Run: `python3 -m pytest validation/test_validate_ioc_data.py -q -k trackers`
Expected: FAIL, `validate_trackers_file` not defined.

- [ ] **Step 3: Implement `validate_trackers_file` and the `main()` dispatch**

Rules: top-level `version == 1`, `license == "ODbL-1.0"`, non-empty `attribution`, `trackers` list; per tracker: integer `id` unique and ascending, non-empty `name`, `categories` non-empty subset of the six labels, `code_prefixes` list of strings each ≥ 3 chars matching `^[A-Za-z0-9_.]+$` (may be empty list only if `domain_patterns` non-empty), `domain_patterns` each compiles with `re.compile` and length ≤ 200. Dispatch: `if ioc_path.name == "trackers.yml": errors = validate_trackers_file(data, ioc_path.name)` with the same PASS/FAIL printing as the brand block.

- [ ] **Step 4: Run the validator tests and the validator on the real file**

Run: `python3 -m pytest validation/test_validate_ioc_data.py -q -k trackers && python3 validation/validate-ioc-data.py ioc-data/trackers.yml`
Expected: tests pass; `PASS: trackers.yml`

- [ ] **Step 5: Regenerate the ioc-data manifest and run the full rules-repo test suite**

Run: `for f in $(ls ioc-data/*.yml | sort); do printf '%s  %s\n' "$(sha256sum "$f" | cut -d' ' -f1)" "$f"; done > ioc-data.sha256 && python3 -m pytest validation -q`
Expected: manifest has a `trackers.yml` line; all tests pass (the complementarity validator ignores a file with no `entries`; if it does not, add `trackers.yml` to its skip list and say so in the commit).

- [ ] **Step 6: Commit and push the rules branch (do NOT merge yet — safe ordering)**

```bash
git add validation/validate-ioc-data.py validation/test_validate_ioc_data.py ioc-data.sha256
git commit -m "feat(validation): structural validator for ioc-data/trackers.yml"
git push -u origin feat/tracker-registry
```

---

### Task 3: AndroDR — submodule bump, bundled snapshot, cross-check gate

**Files:**
- Modify: `third-party/android-sigma-rules` (submodule pointer → the Task 2 commit)
- Modify: `scripts/merge-ioc-data.py` (copy `ioc-data/trackers.yml` → `app/src/main/res/raw/trackers.yml`, with `--check` coverage)
- Create: `app/src/main/res/raw/trackers.yml` (generated)
- Create: `app/src/test/java/com/androdr/privacy/TrackerRegistryBundleCrossCheckTest.kt`
- Modify: `scripts/test_merge_ioc_data.py`

**Interfaces:**
- Produces: `res/raw/trackers.yml` byte-identical to the submodule's `ioc-data/trackers.yml`.

- [ ] **Step 1: Write the failing tests**

`scripts/test_merge_ioc_data.py` — add: `test_trackers_yml_is_copied_verbatim(tmp_path)`: create a fake repo dir with `ioc-data/trackers.yml` containing `version: 1\n`, run `generate(repo, raw)`, assert `raw/trackers.yml` bytes equal; and `test_check_reports_stale_trackers_yml` asserting `check()` names `trackers.yml` when the raw copy differs.

`TrackerRegistryBundleCrossCheckTest.kt`:
```kotlin
@Test fun `bundled trackers_yml equals the pinned submodule file`() {
    val bundled = listOf(File("src/main/res/raw/trackers.yml"), File("app/src/main/res/raw/trackers.yml")).first { it.isFile }
    val repo = listOf(File("../third-party/android-sigma-rules/ioc-data/trackers.yml"),
        File("third-party/android-sigma-rules/ioc-data/trackers.yml")).first { it.isFile }
    assertEquals(repo.readText(), bundled.readText())
}
```

- [ ] **Step 2: Run to verify failure**

Run: `python3 -m pytest scripts/test_merge_ioc_data.py -q -k trackers` → FAIL (no copy); the Kotlin test fails because `res/raw/trackers.yml` does not exist (run it after Step 3's bump: `./gradlew :app:testDebugUnitTest --tests com.androdr.privacy.TrackerRegistryBundleCrossCheckTest`).

- [ ] **Step 3: Bump the submodule and implement the copy**

```bash
cd third-party/android-sigma-rules && git fetch origin && git checkout feat/tracker-registry && cd ../..
git add third-party/android-sigma-rules
```
In `merge-ioc-data.py` add `COPIED_FILES = {"trackers.yml": "trackers.yml"}` (ioc-data name → raw name) handled in both `generate()` and `check()` as verbatim byte copies. Run `python3 scripts/merge-ioc-data.py` to generate `res/raw/trackers.yml`.

- [ ] **Step 4: Run both tests**

Run: `python3 -m pytest scripts/test_merge_ioc_data.py -q && JAVA_HOME=… ANDROID_HOME=… ./gradlew :app:testDebugUnitTest --tests com.androdr.privacy.TrackerRegistryBundleCrossCheckTest --tests com.androdr.ioc.IocDataManifestIntegrityTest -q`
Expected: all pass (manifest integrity confirms the regenerated `ioc-data.sha256`).

- [ ] **Step 5: Commit**

```bash
git add third-party/android-sigma-rules scripts/merge-ioc-data.py scripts/test_merge_ioc_data.py app/src/main/res/raw/trackers.yml app/src/test/java/com/androdr/privacy/TrackerRegistryBundleCrossCheckTest.kt
git commit -m "build: bundle the Exodus tracker registry from ioc-data/trackers.yml (submodule → rules feat/tracker-registry)"
```

---

### Task 4: `TrackerRegistry` — parse, index, refresh

**Files:**
- Create: `app/src/main/java/com/androdr/privacy/TrackerCategory.kt`
- Create: `app/src/main/java/com/androdr/privacy/TrackerRegistry.kt`
- Modify: `app/src/main/java/com/androdr/ioc/FeedHealthRecorder.kt` (`FEED_TRACKER_REGISTRY = "tracker_registry"`)
- Modify: `app/src/main/java/com/androdr/ioc/IntelRefresher.kt` (`refreshTrackerRegistry()` step, reported in `RefreshReport` like `refreshOemPrefixes`)
- Modify: `app/src/main/res/values/strings.xml` (`settings_update_tracker_registry` = "Tracker registry")
- Modify: `app/src/test/java/com/androdr/ioc/IntelRefresherTest.kt`, `app/src/test/java/com/androdr/ioc/FeedHealthRecorderTest.kt` (add the id to their feed lists)
- Create: `app/src/test/java/com/androdr/privacy/TrackerRegistryTest.kt`

**Interfaces:**
- Produces:
```kotlin
enum class TrackerCategory(val label: String) {
    ADVERTISEMENT("Advertisement"), PROFILING("Profiling"), IDENTIFICATION("Identification"),
    LOCATION("Location"), ANALYTICS("Analytics"), CRASH_REPORTING("Crash reporting");
    companion object { fun fromLabel(label: String): TrackerCategory? }
}
data class Tracker(val id: Int, val name: String, val website: String, val categories: Set<TrackerCategory>,
    val codePrefixes: List<String>, val domainPatterns: List<Regex>)
class TrackerSet(trackers: List<Tracker>) {
    val size: Int
    val byId: Map<Int, Tracker>
    /** Trackers whose code prefix is a dotted-path prefix of any of [packages]. */
    fun matchPackages(packages: Collection<String>): Set<Tracker>
    /** The first tracker whose domain pattern finds a match in [host] (lower-cased, trailing dot removed). */
    fun matchDomain(host: String): Tracker?
}
@Singleton class TrackerRegistry @Inject constructor(@ApplicationContext context: Context, manifest: IocDataManifest = IocDataManifest()) {
    fun current(): TrackerSet                 // bundled until a verified refresh replaced it
    suspend fun refresh(): Int                // trackers accepted (0 = kept previous), for FeedHealthRecorder.recordCount
    companion object {
        const val PATH = "ioc-data/trackers.yml"; const val MAX_RESPONSE_CHARS = 2_000_000
        const val MAX_TRACKERS = 2_000; const val MIN_PREFIX_LENGTH = 3; const val MAX_PATTERN_LENGTH = 200
        internal fun parse(yaml: String): TrackerSet?   // null when unusable (structure, caps, StackOverflowError)
    }
}
```
"Dotted-path prefix": `com.a` matches `com.a` and `com.a.b`, not `com.ab`. Implementation: sorted prefix list + binary search per package (no O(packages × prefixes)).

- [ ] **Step 1: Write the failing tests** in `TrackerRegistryTest.kt`

```kotlin
@Test fun `parse reads the bundled file and every category label is known`()   // parse(rawFile("trackers.yml")) non-null, size >= 400, all categories mapped
@Test fun `matchPackages honours dotted boundaries and uses the longest match`() // set with prefixes com.a, com.a.b: packages [com.ab] -> empty; [com.a.b.c] -> both trackers? (expected: both, since both prefixes match) ; [com.a] -> tracker of com.a only
@Test fun `matchDomain lower-cases and strips a trailing dot`()                 // pattern "firebase\\.google\\.com": "Firebase.GOOGLE.com." -> tracker
@Test fun `parse refuses a file over the tracker cap`()                         // 2001 trackers -> null
@Test fun `parse refuses an unknown category, a short prefix, an over-long pattern`()
@Test fun `parse survives deep nesting`()                                       // 5000 nested "[" inside a field -> null, no throw (StackOverflowError caught)
@Test fun `refresh keeps the previous set when the manifest refuses the file`() // IocDataManifest(RemoteText { null }) -> refresh() == 0 and current() unchanged
@Test fun `refresh replaces the set when a verified file parses`()              // RemoteText serving ioc-data.sha256 with the file's real hash + the file -> refresh() == size, current().size == size
```
Use `rawFile(name)` from `com.androdr.data.store` (test source set) to read `res/raw`.

- [ ] **Step 2: Run to verify failure**

Run: `./gradlew :app:testDebugUnitTest --tests com.androdr.privacy.TrackerRegistryTest -q` → FAIL: unresolved `TrackerRegistry`.

- [ ] **Step 3: Implement** `TrackerCategory`, `Tracker`, `TrackerSet`, `TrackerRegistry` per the Interfaces block

`parse` uses snakeyaml-engine `Load(LoadSettings.builder().setMaxAliasesForCollections(10).build())` and catches `Exception` and `StackOverflowError` → null. Bundled load from `R.raw.trackers` at construction (`AtomicReference<TrackerSet>`). `refresh()` mirrors `OemPrefixResolver.refresh()`: `manifest.verified(PATH, MAX_RESPONSE_CHARS)` → `parse` → caps → `set`. Compile domain patterns with `Regex(pattern, RegexOption.IGNORE_CASE)`; a pattern that fails to compile drops that tracker's pattern, not the file.

- [ ] **Step 4: Wire the feed id** — `FeedHealthRecorder.FEED_TRACKER_REGISTRY`, `IntelRefresher.refreshTrackerRegistry()` called in `refreshAll` after `refreshOemPrefixes()`, counted in the report; add the id to the two tests' feed lists and the settings label string (find where `settings_update_oem_prefixes` is used and add the sibling).

- [ ] **Step 5: Run the tests**

Run: `./gradlew :app:testDebugUnitTest --tests com.androdr.privacy.TrackerRegistryTest --tests com.androdr.ioc.IntelRefresherTest --tests com.androdr.ioc.FeedHealthRecorderTest -q` → all pass.

- [ ] **Step 6: Commit**

```bash
git add app/src/main/java/com/androdr/privacy app/src/main/java/com/androdr/ioc/FeedHealthRecorder.kt app/src/main/java/com/androdr/ioc/IntelRefresher.kt app/src/main/res/values/strings.xml app/src/test/java/com/androdr/privacy/TrackerRegistryTest.kt app/src/test/java/com/androdr/ioc
git commit -m "feat(privacy): tracker registry — parse, prefix index, manifest-verified refresh"
```

---

### Task 5: `DexPackageReader` — class-name tables → package set

**Files:**
- Create: `app/src/main/java/com/androdr/privacy/DexPackageReader.kt`
- Create: `app/src/test/java/com/androdr/privacy/DexPackageReaderTest.kt`
- Create: `app/src/test/java/com/androdr/privacy/SyntheticDex.kt` (test helper: builds a minimal valid dex)

**Interfaces:**
- Produces:
```kotlin
object DexPackageReader {
    data class Result(val packages: Set<String>, val dexFiles: Int, val classes: Int, val truncated: Boolean)
    class DexReadException(message: String, cause: Throwable? = null) : Exception(message, cause)
    /** Reads only string_ids/type_ids of every root-level classes*.dex in [apk]; packages = class descriptors minus the simple class name. */
    fun read(apk: File, maxDexBytes: Int = MAX_DEX_BYTES, maxPackages: Int = MAX_PACKAGES): Result
    const val MAX_DEX_BYTES = 64 * 1024 * 1024      // per dex entry, inflated
    const val MAX_PACKAGES = 20_000                  // per app; beyond → truncated = true
}
```
Package of `Lcom/a/b/C;` is `com.a.b`; of `LFoo;` (default package) nothing. Inner classes `Lcom/a/B$C;` → `com.a`.

- [ ] **Step 1: Write `SyntheticDex`** — `fun dex(classDescriptors: List<String>): ByteArray` producing: 0x70-byte header (`dex\n035\0`, header_size 0x70, endian tag 0x12345678, `string_ids_size/off` at 0x38/0x3C, `type_ids_size/off` at 0x40/0x44, other sizes 0), string_ids table, type_ids table (one per descriptor), string data (uleb128 length + MUTF-8 + NUL). `fun apk(vararg dex: ByteArray, extra: Map<String, ByteArray> = emptyMap()): File` zipping them as `classes.dex`, `classes2.dex`, … into a temp file.

- [ ] **Step 2: Write the failing tests** in `DexPackageReaderTest.kt`

```kotlin
@Test fun `packages are class descriptors without the simple name, de-duplicated across dex files`()
   // dex1: Lcom/a/B;, Lcom/a/C$D;  dex2: Lcom/x/Y;, LTop;  -> packages == {com.a, com.x}, dexFiles 2, classes 4
@Test fun `a dex entry over the byte cap is skipped and reported, the rest still read`()
   // maxDexBytes = 100 with one 1 KB dex and one small dex -> packages from the small one, truncated true
@Test fun `the package cap marks the result truncated`()        // 25 classes in 25 packages, maxPackages 20 -> 20 packages, truncated
@Test fun `a zip that is not an apk throws DexReadException`()  // random bytes file
@Test fun `a dex with an out-of-range offset throws DexReadException, not IndexOutOfBounds`()
@Test fun `non-root and non-classes entries are ignored`()      // "lib/classes.dex" and "assets/x.dex" not read
```

- [ ] **Step 3: Run to verify failure** → FAIL: unresolved `DexPackageReader`.

- [ ] **Step 4: Implement `read`** — `ZipFile(apk)`, iterate entries whose name matches `^classes\d*\.dex$`; skip (and set `truncated`) when `entry.size > maxDexBytes`; read bytes; parse header with `ByteBuffer.order(LITTLE_ENDIAN)`; validate `magic`, that offsets + sizes lie within the array (else `DexReadException`); for each type id read the string, keep descriptors starting with `L`, derive the package; stop adding past `maxPackages`. Wrap `IOException`/`BufferUnderflowException`/`IndexOutOfBoundsException` into `DexReadException`.

- [ ] **Step 5: Run the tests** → all pass. Also run `detekt`.

- [ ] **Step 6: Commit**

```bash
git add app/src/main/java/com/androdr/privacy/DexPackageReader.kt app/src/test/java/com/androdr/privacy/DexPackageReaderTest.kt app/src/test/java/com/androdr/privacy/SyntheticDex.kt
git commit -m "feat(privacy): DexPackageReader — package set from an APK's class-name tables, capped"
```

---

### Task 6: `ApkPackageInspector` — every installed app, every split

**Files:**
- Create: `app/src/main/java/com/androdr/privacy/ApkPackageInspector.kt`
- Create: `app/src/test/java/com/androdr/privacy/ApkPackageInspectorTest.kt` (Robolectric, `ShadowPackageManager`)

**Interfaces:**
- Produces:
```kotlin
enum class InspectOutcome { INSPECTED, COULD_NOT_INSPECT }
data class AppInspection(val packageName: String, val versionCode: Long, val appLabel: String, val isSystemApp: Boolean,
    val packages: Set<String>, val outcome: InspectOutcome, val failureReason: String?, val truncated: Boolean)
data class InstalledApp(val packageName: String, val versionCode: Long, val appLabel: String, val isSystemApp: Boolean,
    val apkPaths: List<String>)      // base + splits
@Singleton class ApkPackageInspector @Inject constructor(@ApplicationContext context: Context) {
    fun installedApps(): List<InstalledApp>                    // pm.getInstalledPackages(0); sourceDir + splitSourceDirs; sorted by packageName
    fun inspect(app: InstalledApp): AppInspection              // union of DexPackageReader.read over apkPaths; any DexReadException/IOException → COULD_NOT_INSPECT with reason
}
```

- [ ] **Step 1: Write the failing tests** (Robolectric; install packages via `shadowOf(pm).installPackage(packageInfo)` with `applicationInfo.sourceDir` / `splitSourceDirs` pointing at `SyntheticDex.apk(...)` temp files)

```kotlin
@Test fun `installedApps lists base and split apk paths and the system flag`()
@Test fun `inspect unions packages across base and split apks`()           // base {com.a}, split {com.b} -> {com.a, com.b}, INSPECTED
@Test fun `inspect reports an unreadable apk as COULD_NOT_INSPECT with a reason, not an exception`()  // sourceDir = "/nonexistent/base.apk"
@Test fun `inspect of a truncated apk reports truncated true`()
```

- [ ] **Step 2: Run to verify failure** → FAIL: unresolved `ApkPackageInspector`.

- [ ] **Step 3: Implement** per Interfaces. `versionCode` via `PackageInfoCompat.getLongVersionCode`; label via `pm.getApplicationLabel(appInfo).toString()`; `isSystemApp = appInfo.flags and FLAG_SYSTEM != 0`.

- [ ] **Step 4: Run the tests** → pass. **Step 5: Commit** `feat(privacy): ApkPackageInspector — per-app package facts with visible failure outcomes`.

---

### Task 7: Room — `privacy_*` tables, DAO, migration 21 → 22

**Files:**
- Create: `app/src/main/java/com/androdr/data/model/PrivacyScan.kt` (entities `PrivacyScan`, `PrivacyAppFact`, `PrivacyTrackerEvidence`)
- Create: `app/src/main/java/com/androdr/data/db/PrivacyDao.kt`
- Modify: `app/src/main/java/com/androdr/data/db/AppDatabase.kt` (entities, `version = 22`, `abstract fun privacyDao(): PrivacyDao`)
- Modify: `app/src/main/java/com/androdr/data/db/Migrations.kt` (`MIGRATION_21_22`), and the place migrations are registered (grep `MIGRATION_20_21` in `di/AppModule.kt`)
- Create: `app/schemas/com.androdr.data.db.AppDatabase/22.json` (generated by the build)
- Create: `app/src/test/java/com/androdr/data/db/Migration21To22Test.kt`, `app/src/test/java/com/androdr/data/db/PrivacyDaoTest.kt`

**Interfaces:**
- Produces entities (table names in backticks):
```kotlin
@Entity(tableName = "privacy_scan") data class PrivacyScan(@PrimaryKey(autoGenerate = true) val id: Long = 0,
    val startedAt: Long, val finishedAt: Long?, val appsTotal: Int, val appsInspected: Int, val appsFailed: Int,
    val registrySize: Int, val dnsWindowStart: Long, val dnsEventsInWindow: Int, val usageAccessGranted: Boolean,
    /** Apps crossing the threshold as it stood at scan time, and how many of them did not cross in the previous scan (null when there was none). */
    val crossingCount: Int?, val newCrossing: Int?)
@Entity(tableName = "privacy_app_fact", primaryKeys = ["scanId", "packageName"],
    indices = [Index("packageName", "versionCode")])
data class PrivacyAppFact(val scanId: Long, val packageName: String, val versionCode: Long, val appLabel: String,
    val isSystemApp: Boolean, val outcome: String /* InspectOutcome.name */, val failureReason: String?,
    val truncated: Boolean, val packagesText: String /* "\n"-joined, sorted */)
@Entity(tableName = "privacy_tracker_evidence", primaryKeys = ["scanId", "packageName", "trackerId"])
data class PrivacyTrackerEvidence(val scanId: Long, val packageName: String, val trackerId: Int, val trackerName: String,
    val categories: String /* csv of TrackerCategory.name */, val inCode: Boolean, val networkLookups: Int,
    val networkBackground: Int? /* null = unknown */, val networkFirstSeen: Long?, val networkLastSeen: Long?)
```
- Produces `PrivacyDao`:
```kotlin
@Insert suspend fun insertScan(scan: PrivacyScan): Long
@Query("UPDATE privacy_scan SET finishedAt=:finishedAt, appsInspected=:inspected, appsFailed=:failed, dnsEventsInWindow=:dnsEvents, crossingCount=:crossing, newCrossing=:newCrossing WHERE id=:id")
suspend fun finishScan(id: Long, finishedAt: Long, inspected: Int, failed: Int, dnsEvents: Int, crossing: Int, newCrossing: Int?)
@Query("SELECT * FROM privacy_scan WHERE finishedAt IS NOT NULL AND id < :beforeId ORDER BY id DESC LIMIT 1") suspend fun previousCompleted(beforeId: Long): PrivacyScan?
@Insert(onConflict = REPLACE) suspend fun upsertFacts(facts: List<PrivacyAppFact>)
@Insert(onConflict = REPLACE) suspend fun upsertEvidence(rows: List<PrivacyTrackerEvidence>)
@Query("SELECT * FROM privacy_scan WHERE finishedAt IS NOT NULL ORDER BY id DESC LIMIT 1") fun latestCompleted(): Flow<PrivacyScan?>
@Query("SELECT * FROM privacy_app_fact WHERE packageName=:pkg AND versionCode=:version ORDER BY scanId DESC LIMIT 1") suspend fun cachedFact(pkg: String, version: Long): PrivacyAppFact?
@Query("SELECT * FROM privacy_app_fact WHERE scanId=:scanId") fun facts(scanId: Long): Flow<List<PrivacyAppFact>>
@Query("SELECT * FROM privacy_tracker_evidence WHERE scanId=:scanId") fun evidence(scanId: Long): Flow<List<PrivacyTrackerEvidence>>
@Query("DELETE FROM privacy_scan WHERE id < :keepFromId") suspend fun deleteScansBefore(keepFromId: Long)   // facts/evidence deleted by the same transaction (write the two companion DELETEs)
```
- Migration 21→22: `CREATE TABLE` ×3 + the index, DDL copied from the generated `22.json` (as `MIGRATION_19_20` does with `SCHEMA_20_DDL`).

- [ ] **Step 1: Write the failing tests**

`Migration21To22Test` (copy the `Migration19To20Test` skeleton): seed v21 with one `ScanResult` row; `runMigrationsAndValidate(name, 22, true, MIGRATION_21_22)`; assert the three tables exist (`SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'privacy_%'` → 3) and the `ScanResult` row survived.

`PrivacyDaoTest` (Robolectric, `Room.inMemoryDatabaseBuilder` as `StoreFixture` does): `latestCompleted ignores an unfinished scan`; `cachedFact returns the newest fact for a package version and null for another version`; `deleteScansBefore removes facts and evidence of older scans only`.

- [ ] **Step 2: Run to verify failure** → FAIL: unresolved entities / DAO.

- [ ] **Step 3: Implement** entities, DAO, `AppDatabase` v22, build once to export `22.json` (`./gradlew :app:kspDebugKotlin -q`), copy the three `CREATE` statements + index into `MIGRATION_21_22`, register it where `MIGRATION_20_21` is registered.

- [ ] **Step 4: Run** `--tests com.androdr.data.db.Migration21To22Test --tests com.androdr.data.db.PrivacyDaoTest` → pass; also the existing `*Migration*` tests.

- [ ] **Step 5: Commit** `feat(privacy): privacy_scan / privacy_app_fact / privacy_tracker_evidence tables (schema 22)` including `app/schemas/.../22.json`.

---

### Task 8: Threshold setting and ranking (pure)

**Files:**
- Modify: `app/src/main/java/com/androdr/data/repo/SettingsRepository.kt`
- Create: `app/src/main/java/com/androdr/privacy/PrivacyRanking.kt`
- Create: `app/src/test/java/com/androdr/privacy/PrivacyRankingTest.kt`, `app/src/test/java/com/androdr/data/repo/SettingsRepositoryPrivacyTest.kt` (Robolectric DataStore in a temp dir, as other settings tests do — find one with `PreferenceDataStoreFactory`)

**Interfaces:**
- `SettingsRepository`: `val refusedTrackerCategories: Flow<Set<TrackerCategory>>` (key `stringSetPreferencesKey("privacy_refused_categories")`, default = all except `CRASH_REPORTING`; unknown stored names ignored), `suspend fun setRefusedTrackerCategories(set: Set<TrackerCategory>)`, `val privacyShowSystemApps: Flow<Boolean>` (default false), `suspend fun setPrivacyShowSystemApps(v: Boolean)`.
- `PrivacyRanking`:
```kotlin
data class TrackerRow(val trackerId: Int, val name: String, val categories: Set<TrackerCategory>, val inCode: Boolean,
    val networkLookups: Int, val networkBackground: Int?, val networkFirstSeen: Long?, val networkLastSeen: Long?) {
    val evidence: Evidence get() = when { inCode && networkLookups > 0 -> Evidence.BOTH; inCode -> Evidence.CODE; else -> Evidence.NETWORK }
}
enum class Evidence { CODE, NETWORK, BOTH }
data class AppPrivacyRow(val packageName: String, val appLabel: String, val isSystemApp: Boolean, val outcome: InspectOutcome,
    val failureReason: String?, val trackers: List<TrackerRow>, val refusedCount: Int, val worstRefused: TrackerCategory?)
object PrivacyRanking {
    fun rows(facts: List<PrivacyAppFact>, evidence: List<PrivacyTrackerEvidence>, refused: Set<TrackerCategory>): List<AppPrivacyRow>
    // order: refusedCount desc, then worstRefused by SEVERITY_ORDER, then appLabel; trackers inside a row: refused first, then name
    fun byTracker(rows: List<AppPrivacyRow>): List<Pair<TrackerRow, List<AppPrivacyRow>>>  // tracker → apps carrying it, most apps first
    val SEVERITY_ORDER = listOf(LOCATION, PROFILING, IDENTIFICATION, ADVERTISEMENT, ANALYTICS, CRASH_REPORTING)
}
```

- [ ] **Step 1: Write the failing tests**

`PrivacyRankingTest`: `apps crossing the threshold rank above those that do not`; `worstRefused follows SEVERITY_ORDER`; `an app with no evidence has refusedCount 0 and empty trackers`; `evidence is CODE, NETWORK or BOTH`; `byTracker groups apps per tracker, most apps first`; `COULD_NOT_INSPECT apps keep their outcome in the row`.
`SettingsRepositoryPrivacyTest`: `default refuses every category except crash reporting`; `set and read round-trips`; `an unknown stored name is ignored`.

- [ ] **Step 2: Run to verify failure** → FAIL (unresolved).
- [ ] **Step 3: Implement** per Interfaces. **Step 4: Run** → pass. **Step 5: Commit** `feat(privacy): refused-category threshold setting and pure ranking`.

---

### Task 9: `PrivacyScanRunner` — orchestration, network correlation, cache, retention

**Files:**
- Create: `app/src/main/java/com/androdr/privacy/PrivacyScanRunner.kt`
- Create: `app/src/main/java/com/androdr/privacy/ForegroundIntervals.kt`
- Modify: `app/src/main/java/com/androdr/data/db/DnsEventDao.kt` (`@Query("SELECT * FROM DnsEvent WHERE timestamp >= :since AND appName IS NOT NULL ORDER BY timestamp") suspend fun eventsSince(since: Long): List<DnsEvent>`)
- Create: `app/src/test/java/com/androdr/privacy/PrivacyScanRunnerTest.kt` (Robolectric, in-memory db), `app/src/test/java/com/androdr/privacy/ForegroundIntervalsTest.kt`

**Interfaces:**
- Consumes: `ApkPackageInspector` (Task 6), `TrackerRegistry.current()` (Task 4), `PrivacyDao` (Task 7), `DnsEventDao.eventsSince`, `UsageStatsScanner.collectEvents(since, until)` + `UsageAccess.granted()`, `ScanLock.withWriter`.
- Produces:
```kotlin
sealed class PrivacyScanProgress { object Idle; data class Running(val done: Int, val total: Int); data class Finished(val scanId: Long) }
@Singleton class PrivacyScanRunner @Inject constructor(inspector: ApkPackageInspector, registry: TrackerRegistry, dao: PrivacyDao,
    dnsEvents: DnsEventDao, usage: UsageStatsScanner, usageAccess: UsageAccess, settings: SettingsRepository, scanLock: ScanLock,
    clock: () -> Long = System::currentTimeMillis) {
    val progress: StateFlow<PrivacyScanProgress>
    suspend fun run(): Long                     // scan id; throws only CancellationException
    companion object { const val DNS_WINDOW_MS = 30L * 24 * 3600 * 1000 }
}
object ForegroundIntervals {
    /** From usage events (app_foreground/app_background per package) → per package sorted (start, end) intervals; an open interval ends at [until]. */
    fun build(events: List<UsageEvent>, until: Long): Map<String, List<LongRange>>
    fun isForeground(intervals: Map<String, List<LongRange>>, pkg: String, at: Long): Boolean
}
```
Algorithm of `run()`: under `withWriter`: insert scan row (`dnsWindowStart = now − DNS_WINDOW_MS`, `usageAccessGranted`); `apps = inspector.installedApps()`; per app: `dao.cachedFact(pkg, version)` → reuse its packages, else `inspector.inspect(app)`; registry `matchPackages` → in-code trackers; DNS: `eventsSince(windowStart)` grouped by `appName`, each event `matchDomain(domain)` → per (pkg, tracker) counts, background counted when usage access granted and `!isForeground(...)`, else `networkBackground = null`; upsert facts and evidence per app; progress after each app. Then: `refused = settings.refusedTrackerCategories.first()`; `crossing` = apps with any evidence row whose categories intersect `refused` (via `PrivacyRanking.rows(...).count { it.refusedCount > 0 }`); `newCrossing` = those crossing now whose package did not cross in `dao.previousCompleted(scanId)` (computed with the same `refused`), or null when there is no previous scan; `finishScan(id, now, inspected, failed, dnsEventsInWindow, crossing, newCrossing)`; `deleteScansBefore(scanId)`; `Finished(scanId)`. `usage.collectEvents(windowStart, now)` yields a `UsageCollection`; anything but a successful collection means `networkBackground = null` for every row. A per-app `Exception` during inspection becomes a `COULD_NOT_INSPECT` fact; it never aborts the run. A `CancellationException` propagates after the scan row is left unfinished (the next run supersedes it).

- [ ] **Step 1: Write the failing tests**

`ForegroundIntervalsTest`: `pairs foreground and background events per package`; `an open foreground interval ends at until`; `isForeground is false outside intervals and for unknown packages`.
`PrivacyScanRunnerTest` (fake inspector returning two apps; registry from a 3-tracker YAML; in-memory DAO; DNS events seeded):
```kotlin
@Test fun `in-code trackers come from registry prefix matches on the inspected packages`()
@Test fun `network trackers come from attributed DNS lookups in the window and carry counts and first and last seen`()
@Test fun `a tracker seen both ways is one evidence row with inCode true and lookups set`()
@Test fun `events older than the window, unattributed events, and events for uninstalled apps are ignored`()   // Review Focus 4
@Test fun `background counts are null when usage access is not granted and computed from intervals when granted`()  // Review Focus 5
@Test fun `an unchanged app version reuses the cached fact and is not re-inspected`()   // inspector.inspect call count
@Test fun `an inspector failure becomes a COULD_NOT_INSPECT fact and the scan completes`()
@Test fun `completing a scan deletes older scans and their rows`()
@Test fun `crossingCount and newCrossing use the threshold at scan time and the previous scan`()   // first scan: newCrossing null; second scan with one more crossing app: newCrossing 1
@Test fun `dnsEventsInWindow is stored so the screen can say the monitor was off`()
@Test fun `progress goes Idle → Running(n,total) → Finished(id)`()
```

- [ ] **Step 2: Run to verify failure** → FAIL (unresolved).
- [ ] **Step 3: Implement** per Interfaces and algorithm. **Step 4: Run** → pass; run the full suite once here (`./gradlew :app:testDebugUnitTest -q`) since DAO and DNS code changed.
- [ ] **Step 5: Commit** `feat(privacy): PrivacyScanRunner — inspect, correlate DNS evidence, cache by version, keep last scan`.

---

### Task 10: Privacy screen, ViewModel, route, Dashboard card

**Files:**
- Create: `app/src/main/java/com/androdr/ui/privacy/PrivacyViewModel.kt`, `PrivacyScreen.kt`, `PrivacyThresholdSheet.kt`
- Modify: `app/src/main/java/com/androdr/MainActivity.kt` (`composable("privacy") { PrivacyScreen(onBack = { navController.popBackStack() }) }`; bottom bar unchanged)
- Modify: `app/src/main/java/com/androdr/ui/dashboard/DashboardScreen.kt` (`PrivacyCard` between `OpenAlertsCard` and the Run Scan block), `DashboardViewModel.kt` (`val privacySummary: StateFlow<PrivacySummary?>`)
- Modify: `app/src/main/res/values/strings.xml` (all copy below)
- Create: `app/src/test/java/com/androdr/ui/privacy/PrivacyViewModelTest.kt`, `app/src/test/java/com/androdr/ui/privacy/PrivacyCopyTest.kt`

**Interfaces:**
- `PrivacyViewModel` (@HiltViewModel; deps: `PrivacyDao`, `PrivacyScanRunner`, `SettingsRepository`, `TrackerRegistry`):
  `val state: StateFlow<PrivacyUiState>` where `PrivacyUiState(scan: PrivacyScan?, rows: List<AppPrivacyRow>, byTracker: …, refused: Set<TrackerCategory>, showSystemApps: Boolean, progress: PrivacyScanProgress, registrySize: Int, attribution: String)`; `fun runScan()`; `fun setRefused(set)`; `fun setShowSystemApps(v)`. Rows are filtered by `showSystemApps` before ranking; `registrySize` feeds the "none from the registry (N trackers) found" copy.
- `DashboardViewModel.privacySummary`: `PrivacySummary(crossing: Int, newSinceLast: Int?, scannedAt: Long)` read straight from `PrivacyDao.latestCompleted()` (`crossingCount`, `newCrossing`, `finishedAt`), or null when never scanned. The card shows `privacy_card_never` for null; `privacy_card_summary` otherwise (when `newSinceLast` is null, the middle clause is omitted — add `privacy_card_summary_first` "%1$d apps cross your threshold · scanned %2$s").
- `PrivacyUiState.monitorHadEvidence: Boolean` = `scan.dnsEventsInWindow > 0`; when false the screen shows `privacy_no_monitor`.

Strings (exact):
- `privacy_title` "Privacy scan"; `privacy_card_never` "Privacy scan not run yet"; `privacy_card_summary` "%1$d apps cross your threshold · %2$d new since last scan · scanned %3$s"; `privacy_run` "Run privacy scan"; `privacy_progress` "Inspecting %1$d of %2$d apps"; `privacy_tab_by_app` "By app"; `privacy_tab_by_tracker` "By tracker"; `privacy_none_from_registry` "None of the %1$d trackers in the registry were found"; `privacy_could_not_inspect` "Could not inspect: %1$s"; `privacy_evidence_code` "found in code"; `privacy_evidence_network` "seen on network — %1$d lookups, last %2$s"; `privacy_evidence_network_bg` "seen on network — %1$d lookups, %2$d in background, last %3$s"; `privacy_evidence_both` "found in code and seen on network"; `privacy_background_unknown` "background use unknown (usage access not granted)"; `privacy_obfuscation_caveat` "Code inspection can miss trackers whose code has been renamed by the app's build tools; network evidence does not depend on that."; `privacy_no_monitor` "Network evidence needs the network monitor; it was off during this period."; `privacy_system_toggle` "Include system apps (can only be disabled, not removed)"; `privacy_threshold_title` "What I refuse"; six `privacy_cat_*` labels with the §4.1 explanations; `privacy_attribution` "Tracker data: Exodus Privacy (ODbL 1.0)"; `privacy_last_scan` "Last scan: %1$s".

- [ ] **Step 1: Write the failing tests**

`PrivacyViewModelTest` (MockK DAO flows, fake runner): `state carries the latest completed scan's rows ranked against the refused set`; `toggling showSystemApps filters system rows`; `setRefused re-ranks without a new scan`; `runScan delegates to the runner once while idle`; `registrySize is exposed for the none-found copy`.
`PrivacyCopyTest` (source/strings assertions, same style as `HistoryViewModelTest`'s screen check): `strings.xml contains no "no trackers" copy and contains privacy_none_from_registry`; `PrivacyScreen.kt references privacy_obfuscation_caveat and privacy_attribution`; `MainActivity.kt has the privacy route and still five bottomNavDestinations`.

- [ ] **Step 2: Run to verify failure** → FAIL.

- [ ] **Step 3: Implement** ViewModel, screen (Scaffold with top bar + back; header: last-scan date, Run button / progress bar; two tabs; By-app row = label, package, "N trackers · worst: Location" and a chevron; detail sheet lists each tracker with categories and the evidence sentence; By-tracker list; the system-apps toggle; the threshold sheet with six checkboxes; caveat and attribution as footer text), the Dashboard card (tap → `onNavigate("privacy")`), the route.

- [ ] **Step 4: Run** the two test classes and `lintDebug` → pass. **Step 5: Commit** `feat(privacy): privacy screen, threshold sheet, dashboard card, route`.

---

### Task 11: Apps-tab crossover line

**Files:**
- Modify: `app/src/main/java/com/androdr/ui/apps/AppScanScreen.kt` (`AppGroupDetailSheet`: a line "Trackers: N (M cross your threshold)" when the latest privacy scan has evidence for `group.packageName`, tapping navigates to `privacy`), `AppScanViewModel.kt` (expose `privacyByPackage: StateFlow<Map<String, Pair<Int, Int>>>` from `PrivacyDao.latestCompleted` + ranking), `MainActivity.kt` (pass `onNavigateToPrivacy`).
- Modify: `app/src/test/java/com/androdr/ui/apps/AppScanViewModelTest.kt` (or create)

- [ ] **Step 1: Write the failing test** — `privacyByPackage counts trackers and refused trackers per package from the latest scan` and `is empty when no privacy scan exists`.
- [ ] **Step 2: Run → FAIL.** **Step 3: Implement.** **Step 4: Run → pass.** **Step 5: Commit** `feat(apps): tracker line on a flagged app's sheet, linking to the privacy screen`.

---

### Task 12: Documentation, safe-ordering close, gates

**Files:**
- Modify: `docs/ARCHITECTURE.md` (new §4.x "Privacy scan": the two facts, the registry, the threshold, the own-tables decision, the obfuscation limit, ODbL attribution; one row for `trackers.yml` in the ioc-data table if one exists)
- Modify: `third-party/android-sigma-rules` pointer (after the rules branch merges)

- [ ] **Step 1: Write the ARCHITECTURE.md section** (≤ 25 lines) and commit `docs: privacy scan architecture`.
- [ ] **Step 2: Full local gates** — `rm -rf app/build/test-results/testDebugUnitTest && ./gradlew :app:testDebugUnitTest detekt :app:lintDebug --continue -q`; expected: 0 failures, detekt and lint clean. Fix anything that fails in the task that owns it.
- [ ] **Step 3: Open the AndroDR PR** (branch `feat/privacy-scan`, body links the spec and plan, states "submodule points at rules `feat/tracker-registry` pending safe ordering"). Wait for `ci-success`.
- [ ] **Step 4: Safe-ordering close** — once AndroDR CI is green: open and merge the rules PR (`validate` green required); then `cd third-party/android-sigma-rules && git checkout main && git pull`, `git add third-party/android-sigma-rules`, commit `build: re-point submodule at rules main (tracker registry)`, push; CI green again; merge the AndroDR PR.
- [ ] **Step 5: Release battery** — per the standing policy before any release: emulator (API 36.1) + physical F916B clean install; run a privacy scan on each, confirm progress, a Google app shows Firebase Analytics "found in code", the obfuscation caveat and attribution are visible, and "Include system apps" toggles the list.
