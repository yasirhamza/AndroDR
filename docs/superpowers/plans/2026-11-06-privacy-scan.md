# Privacy Scan Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A user-started privacy scan that reads the class-name tables of every installed app's code, correlates 30 days of attributed DNS lookups, matches both against a mirrored Exodus tracker registry, and shows precise per-app facts ranked against the user's own refused-category threshold, on its own screen.

**Architecture:** Two facts (an app's distinct Java packages; its tracker-domain lookups) joined on-device with a tracker registry that lives in the rules repo as `ioc-data/trackers.yml` (manifest-verified, 12 h refresh, bundled snapshot). A dedicated `com.androdr.privacy` module with its own Room tables and its own lock, outside the security scan store; nothing here raises alerts, touches the security verdict, or takes the security writer lock. UI: Dashboard card → `privacy` route.

**Tech Stack:** Kotlin, Jetpack Compose (Material 3), Hilt, Room (schema export on), DataStore preferences, snakeyaml-engine 2.7, kotlinx.coroutines; JUnit4 + MockK + Robolectric; Python 3 + PyYAML + jsonschema + pytest in the rules repo.

**Spec:** `docs/superpowers/specs/2026-11-06-privacy-scan-design.md` (revised after the plan gate, 2026-11-06)

## Global Constraints

- Rules-repo changes follow CLAUDE.md "Safe ordering". During steps 2–4 of that ordering, AndroDR's `submodule-check` job — and therefore `ci-success` — is **red by design**; `build-and-test` and the other jobs are the gate until the submodule is re-pointed at rules main.
- Any edit under `ioc-data/` regenerates `ioc-data.sha256`; `IocDataManifestIntegrityTest` stays green.
- Emitters emit facts only. No tracker name or domain is hard-coded in Kotlin; the six category labels plus `Uncategorised` are a UI vocabulary (spec §4.1), and an unknown label maps to `OTHER`, never rejects a file. Default refused set: every category except Crash reporting and Other — **Uncategorised is refused by default (owner, plan gate round 2)**.
- Privacy results are never a `ScanResult`, never `LIVE_SCAN`, never in History, the exported report, alerts or the Timeline. The privacy scan never calls `ScanLock.withWriter`.
- Only **code** evidence makes an app cross the threshold; network-only evidence is listed, worded "looked up domains of X", with the content-caused caveat (spec §2 goal 2, §4.3).
- No AndroDR ranking of categories; apps order by refused-tracker count, then label (spec §3).
- An app that failed or was partly inspected never renders "none from the registry found"; the Dashboard card shows a failure clause whenever any app failed.
- Byte caps count bytes actually inflated, never zip-declared sizes; one byte budget and one deadline per **app**, shared by its base and split APKs and checked by the reader itself (`withTimeout` cannot interrupt a blocking read). Per-app isolation catches every `Throwable` except `CancellationException`; the whole scan body is also wrapped, so nothing escapes the app-wide scope.
- Domain-pattern regexes follow the restricted grammar (Task 2), identical in the mirror, the validator and the app; the three probe-confirmed backtracking bypasses `((a+))+$`, `(a+?)+$`, `(a{1,30}){1,30}$` are rejection fixtures in all three.
- minSdk 26 → SQLite's 999-variable limit: no `IN (:list)` over installed apps; use subqueries.
- Network bodies only via `IocDataManifest` / `readTextCapped` (`NetworkBodyReadGateTest`).
- detekt: max line 120, `ReturnCount` max 3, `TooManyFunctions` 15/class. Lint warnings are errors in release. Count strings use `<plurals>`.
- Gradle: `JAVA_HOME=/home/yasir/.gradle/jdks/eclipse_adoptium-21-amd64-linux.2 ANDROID_HOME=/home/yasir/Android/Sdk ./gradlew …`; delete `app/build/test-results/testDebugUnitTest` before parsing results.

## Review Focus

1. A crafted APK (lying zip sizes, `size = -1`, thousands of dex entries, out-of-range dex offsets, 20k junk class names, many splits, a read that never ends, an `OutOfMemoryError`) must cost that app only — within one byte budget and one deadline the reader itself checks — show it as could-not / partly inspected, and never abort the scan or hide trackers in the dex files that parsed — Tasks 5, 6, 9.
2. A first-party lookup (`www.google.com`, `www.facebook.com`, Microsoft sign-in, `hicloud.com`) must not attribute any tracker, and a class-name signature must never widen to a vendor root (`com.facebook`) — Tasks 1, 2, 4.
3. A system app's lookups and lookups older than usage history must read background "unknown", never "background" — Task 9.
4. Changing the threshold or the system-apps toggle must change the Dashboard card and the screen identically — Tasks 8, 10.
5. A registry file that is malformed, over cap, deeply nested, carries an unknown category, or carries a backtracking-prone pattern must keep the previous registry or degrade per entry, never freeze the app on bundled data silently or stall a scan — Tasks 2, 4.

---

### Task 1: Rules repo — Exodus mirror script and `ioc-data/trackers.yml`

**Files:**
- Create: `third-party/android-sigma-rules/validation/mirror-exodus-trackers.py`, `validation/test_mirror_exodus_trackers.py`
- Create: `validation/domain_grammar.py` (the grammar as specified under Task 2, implemented here because the mirror needs it first) with `validation/test_domain_grammar.py` driven by `validation/domain_grammar_fixtures.txt` (lines `ACCEPT <pattern>` / `REJECT <pattern>`: accepts the three real patterns; rejects the four backtracking fixtures listed in Task 2, `.*`, and samples with `(`, `|`, `{`, `^`, `$`, `\d`; Task 4's Kotlin port reads the same file); `validation/first_party_hosts.txt`
- Create (generated): `third-party/android-sigma-rules/ioc-data/trackers.yml`
- Modify: `third-party/android-sigma-rules/README.md` (ODbL paragraph)

Branch in the submodule: `cd third-party/android-sigma-rules && git checkout -b feat/tracker-registry origin/main`.

**Interfaces — produces `ioc-data/trackers.yml`:**
```yaml
version: 1
source: exodus-privacy
source_url: https://reports.exodus-privacy.eu.org/api/trackers
license: ODbL-1.0
attribution: "Exodus Privacy — https://exodus-privacy.eu.org — Open Database License 1.0"
trackers:
  - id: 49                          # Exodus id, int, unique, ascending
    name: "Google Firebase Analytics"
    website: "https://firebase.google.com/"
    categories: [Analytics]                          # Exodus labels verbatim; empty in Exodus -> [Uncategorised]
    code_prefixes: [com.google.firebase.analytics]   # dotted package prefixes, sorted, unique
    code_segments: []                                # from dot-led signatures: ".sizmek." -> "sizmek"
    domain_suffixes: [app-measurement.com]           # host suffixes, matched on label boundaries
    domain_labels: []                                # whole labels: "\.alimama\." -> "alimama"
    domain_patterns: []                              # restricted-grammar regexes, matched against host or a label-bounded suffix
    excluded_domains: []                             # original signatures dropped as over-broad (transparency; never matched)
```
No `generated_at` (keeps the manifest hash stable when Exodus is unchanged).

Create `validation/first_party_hosts.txt` (one host per line, read by both the mirror and the validator): `www.google.com mail.google.com accounts.google.com www.facebook.com m.facebook.com www.youtube.com www.instagram.com www.amazon.com www.microsoft.com www.apple.com login.microsoftonline.com www.hicloud.com`. Create `validation/domain_grammar.py` with `PATTERN_RE` and `is_restricted_pattern(p: str) -> bool` (Task 2 defines the grammar; Task 1 imports it).

CLI: `python3 validation/mirror-exodus-trackers.py --out ioc-data/trackers.yml [--from-json FILE] [--previous FILE]`. Exit 1 when: fewer than 300 trackers; the count shrinks by more than 10% versus `--previous`.

**Normalisation rules in `render(api: dict, previous: dict | None) -> tuple[dict, list[str]]`** (second value = human-readable drop report printed to stderr). Measured against the 2026-11-06 snapshot; the expected counts are test assertions in Step 5.
- **Code** signatures, split on `|`, stripped, trailing `.` removed:
  - dot-led: if the inner name matches `^[a-z0-9_]+$` → `code_segments`; else (upper-case, e.g. `.LigatusManager`) dropped and reported.
  - last segment starts upper-case (a class name): its package is kept only when it has **≥ 3 segments** and is **not a parent** of another plain signature of the same tracker; else dropped and reported (`com.facebook.CampaignTrackingReceiver` → `com.facebook` is a parent of `com.facebook.appevents`; `com.baidu.BaiduMap` → 2 segments).
  - otherwise must match `^[a-z0-9_]+(\.[A-Za-z0-9_]+)+$`, else dropped and reported (hyphens).
- **Network** signatures, split on `|`: unescape `\.` and `\-`; strip a leading `.*\.` or `.`; then
  - result matches `^[a-z0-9-]+(\.[a-z0-9-]+)+$` → `domain_suffixes` (a bare `.` between labels counts as literal: Exodus means `tag-mediation.supersonic.com`);
  - result is dot-bounded on both sides in the original (`\.alimama\.`) or a single label (`fidzup`) → `domain_labels`;
  - else the original, if `is_restricted_pattern` → `domain_patterns`; else dropped and reported (e.g. `54\.243\.73\.253:8080/SilverPush/`, `data.\altbeacon\.org`).
- **Broad**: any suffix, label or pattern that matches a first-party host (suffix: host equals it or ends with `.`+it; label: a label of the host; pattern: as on device) moves to `excluded_domains` — **per signature**, the tracker keeps its others.
- **Categories**: Exodus labels verbatim; an empty list becomes `["Uncategorised"]`.
- Trackers with no code prefix, segment, suffix, label or pattern left are dropped and reported.

- [ ] **Step 1: Write the failing tests** (load the script with `importlib.util.spec_from_file_location`, as sibling tests do)

```python
def test_class_name_signature_becomes_its_package():
    doc, _ = render(api(code="com.adobe.mobile.Analytics|com.adobe.mobile.Config."), None)
    assert doc["trackers"][0]["code_prefixes"] == ["com.adobe.mobile"]
def test_class_name_whose_package_is_a_parent_of_another_signature_is_dropped():
    doc, report = render(api(code="com.facebook.appevents|com.facebook.marketing.|com.facebook.CampaignTrackingReceiver"), None)
    assert doc["trackers"][0]["code_prefixes"] == ["com.facebook.appevents", "com.facebook.marketing"]
    assert any("CampaignTrackingReceiver" in r for r in report)
def test_class_name_with_a_two_segment_package_is_dropped():
    doc, report = render(api(code="com.baidu.BaiduMap|com.baidu.mapapi"), None)
    assert doc["trackers"][0]["code_prefixes"] == ["com.baidu.mapapi"] and report
def test_dot_led_signature_becomes_a_segment():
    doc, _ = render(api(code=".sizmek."), None)
    assert doc["trackers"][0]["code_segments"] == ["sizmek"]
def test_upper_case_dot_led_signature_is_dropped():
    doc, report = render(api(code=".LigatusManager|com.ligatus.sdk"), None)
    assert doc["trackers"][0]["code_segments"] == [] and report
def test_hyphenated_signature_is_dropped_and_reported():
    doc, report = render(api(code="com.github.backtrace-labs.|io.backtrace."), None)
    assert doc["trackers"][0]["code_prefixes"] == ["io.backtrace"] and any("backtrace-labs" in r for r in report)
def test_escaped_dots_and_hyphens_become_plain_suffixes():
    doc, _ = render(api(net="app-measurement\\.com|\\.flurry\\.com|cdn\\-lb\\.vungle\\.com|.*\\.estimote\\.com"), None)
    assert doc["trackers"][0]["domain_suffixes"] == ["app-measurement.com", "cdn-lb.vungle.com", "estimote.com", "flurry.com"]
def test_dot_bounded_and_single_label_signatures_become_labels():
    doc, _ = render(api(net="\\.alimama\\.|fidzup"), None)
    assert doc["trackers"][0]["domain_labels"] == ["alimama", "fidzup"]
def test_a_real_pattern_in_the_grammar_is_kept():
    doc, _ = render(api(net="mst[0-9]*\\.is\\.autonavi\\.com"), None)
    assert doc["trackers"][0]["domain_patterns"] == ["mst[0-9]*\\.is\\.autonavi\\.com"]
def test_a_url_signature_is_dropped():
    doc, report = render(api(code="com.x.y", net="54\\.243\\.73\\.253:8080/SilverPush/"), None)
    assert doc["trackers"][0]["domain_patterns"] == [] and report
def test_broad_signatures_are_excluded_per_signature():
    doc, _ = render(api(net="\\.google\\.com|googleadservices\\.com"), None)
    t = doc["trackers"][0]
    assert t["domain_suffixes"] == ["googleadservices.com"] and t["excluded_domains"] == ["\\.google\\.com"]
def test_microsoft_sign_in_and_hicloud_are_broad():
    doc, _ = render(api(code="com.x.y", net="login\\.microsoftonline\\.com|hicloud\\.com"), None)
    assert doc["trackers"][0]["domain_suffixes"] == [] and len(doc["trackers"][0]["excluded_domains"]) == 2
def test_backtracking_patterns_are_dropped():                     # the three probe-confirmed bypasses
    for p in ["((a+))+$", "(a+?)+$", "(a{1,30}){1,30}$"]:
        doc, report = render(api(code="com.x.y", net=p), None)
        assert doc["trackers"][0]["domain_patterns"] == [] and report
def test_empty_category_becomes_uncategorised():
    doc, _ = render(api(code="com.x.y", cats=[]), None)
    assert doc["trackers"][0]["categories"] == ["Uncategorised"]
def test_tracker_with_nothing_left_is_dropped():
    doc, report = render(api(code="com.github.a-b.", net=""), None)
    assert doc["trackers"] == [] and report
def test_output_sorted_by_id_and_has_licence(): ...      # ids [9, 2] in -> [2, 9] out; license == "ODbL-1.0"
def test_main_refuses_a_large_shrink(tmp_path): ...       # previous 400 trackers, new 300 -> exit 1
def test_main_from_json_writes_file(tmp_path): ...        # 320 synthetic trackers -> file with 320 entries
```
`api(code=..., net=..., cats=["Analytics"], id=1)` builds a one-tracker Exodus API dict.

- [ ] **Step 2: Run to verify failure** — `cd third-party/android-sigma-rules && python3 -m pytest validation/test_mirror_exodus_trackers.py -q` → FAIL with `FileNotFoundError` (script absent).
- [ ] **Step 3: Implement `render` and `main(argv) -> int`** per the rules above; network fetch via `urllib.request` (60 s timeout); YAML via `yaml.safe_dump(sort_keys=False, allow_unicode=True, width=120)`.
- [ ] **Step 4: Run tests** → all pass.
- [ ] **Step 5: Generate the real file** — `python3 validation/mirror-exodus-trackers.py --out ioc-data/trackers.yml`. Against the 2026-11-06 snapshot (`/tmp/claude-1000/-home-yasir-AndroDR/eac36e08-8c3e-4ac8-b444-91bf05923e7d/scratchpad/exodus/trackers.json`, via `--from-json`) the drop report must show: 16 class-name signatures dropped, 3 upper-case segments dropped, 3 trackers dropped entirely (429 kept), 116 `Uncategorised`, 10 excluded broad signatures, exactly 3 `domain_patterns` in the file (`adservice\.google\..*`, `mst[0-9]*\.is\.autonavi\.com`, `mt[0-9]*\.google\.cn`). A live fetch may differ slightly; investigate any large difference. Spot-check: Google Ads has `\.google\.com` under `excluded_domains`; Facebook Analytics has no `com.facebook` prefix. Then run Task 2's validator on the file before committing (the two must agree). Add the README ODbL paragraph (mirror of Exodus, ODbL 1.0 link, derived copies stay ODbL, regenerated by this script).
- [ ] **Step 6: Commit** `feat(ioc-data): mirror the Exodus Privacy tracker registry (ODbL)`.

---

### Task 2: Rules repo — validators, manifest, CI

**Files:**
- Modify: `validation/validate-ioc-data.py` (+ `validate_trackers_file`, dispatch after the brand block)
- Modify: `validation/validate-ioc-complementarity.py` (`NON_IOC_FILES = {"campaigns.yml", "trackers.yml"}`)
- Modify: `validation/test_validate_ioc_data.py`, `validation/test_validate_ioc_complementarity.py`
- Modify: `ioc-data.sha256` (regenerated)

**Interfaces:** `validate_trackers_file(data: dict, filename: str) -> list[str]`.

**Restricted pattern grammar** (`validation/domain_grammar.py`, created in Task 1, ported line-for-line to Kotlin in Task 4): a pattern is a sequence of atoms, each optionally followed by one of `*`, `+`, `?`; an atom is a lower-case letter, digit or `-`, an escaped `\.` or `\-`, a bare `.`, or a class `[...]` whose content matches `^[a-z0-9-]+$` or ranges `a-z`/`0-9` only. Nothing else: no `(`, `)`, `|`, `{`, `}`, `^`, `$`, backslash-letter, lazy `*?`/`+?`. At most **two** quantifiers per pattern; ≤ 200 chars; must not match the empty string. Implement as a hand-written tokenizer (not a meta-regex), so the Kotlin port is line-for-line.

Rules: `version == 1`; `license == "ODbL-1.0"`; non-empty `attribution`; ≥ 300 trackers; per tracker: int `id` unique ascending; non-empty `name`; `website` empty or starting `http://`/`https://`; `categories` non-empty subset of `{"Advertisement","Profiling","Identification","Location","Analytics","Crash reporting","Uncategorised"}`; `code_prefixes` each `^[a-z0-9_]+(\.[A-Za-z0-9_]+)+$` (shape only: two-segment prefixes such as Exodus's own `com.flurry` are legitimate; the ≥ 3-segment rule applies to class-name conversion in the mirror, which the validator cannot see); `code_segments` each `^[a-z0-9_]+$`; `domain_suffixes` each `^[a-z0-9-]+(\.[a-z0-9-]+)+$`; `domain_labels` each `^[a-z0-9-]+$`; `domain_patterns` each `is_restricted_pattern`; no suffix, label or pattern matches a host in `first_party_hosts.txt`; `excluded_domains` a list of strings; at least one of the five matchable lists non-empty. (The mirror's outputs are exactly what these rules accept — Task 1 Step 5 runs this validator before committing.)

- [ ] **Step 1: Write failing tests** — in `test_validate_ioc_data.py`: `test_trackers_valid_passes`, `test_trackers_unknown_category_fails`, `test_trackers_uncategorised_passes`, `test_trackers_duplicate_id_fails`, `test_trackers_hyphen_prefix_fails`, `test_trackers_single_label_suffix_fails` (`fidzup` belongs in `domain_labels`), `test_trackers_upper_case_segment_fails`, `test_trackers_empty_matching_pattern_fails`, `test_trackers_backtracking_patterns_fail` (parametrised over `((a+))+$`, `(a+?)+$`, `(a{1,30}){1,30}$`, `a*b*c*d`), `test_trackers_grammar_accepts_the_three_real_patterns`, `test_trackers_first_party_suffix_fails` (`google.com` in `domain_suffixes`), `test_trackers_javascript_website_fails`, `test_trackers_missing_license_fails`, `test_trackers_tracker_with_no_signatures_fails` (helper `_trackers_doc(n=300)`). In `test_validate_ioc_complementarity.py`: `test_trackers_yml_is_skipped` (copy `test_campaigns_yml_is_skipped`).
- [ ] **Step 2: Run** `python3 -m pytest validation/test_validate_ioc_data.py validation/test_validate_ioc_complementarity.py -q -k "trackers"` → FAIL.
- [ ] **Step 3: Implement** the validator, the dispatch (`if ioc_path.name == "trackers.yml": …` with the brand block's PASS/FAIL printing), and the `NON_IOC_FILES` addition.
- [ ] **Step 4: Run** the two test files, then `python3 validation/validate-ioc-data.py ioc-data/trackers.yml` → `PASS: trackers.yml`, and `python3 validation/validate-ioc-complementarity.py --file ioc-data/trackers.yml --mode strict` exits 0.
- [ ] **Step 5: Regenerate the manifest and run the whole suite** — the CLAUDE.md loop into `ioc-data.sha256`; `python3 -m pytest validation -q` → all pass.
- [ ] **Step 6: Commit and push the branch, do not merge** — `feat(validation): trackers.yml validator; complementarity skips it`; `git push -u origin feat/tracker-registry`.

---

### Task 3: AndroDR — submodule bump, bundled snapshot, cross-checks

**Files:**
- Modify: submodule pointer; `scripts/merge-ioc-data.py` (`COPIED_FILES = {"trackers.yml": "trackers.yml"}` handled by `generate` and `check` as byte copies); `scripts/test_merge_ioc_data.py`; `.github/workflows/ci.yml` (add `app/src/main/res/raw/trackers.yml` to the `bundle` path filter); `app/src/test/java/com/androdr/ioc/OemPrefixMirrorParityTest.kt` (doc comment: wholesale mirrors use `COPIED_FILES`)
- Create: `app/src/main/res/raw/trackers.yml` (generated); `app/src/test/java/com/androdr/privacy/TrackerRegistryBundleCrossCheckTest.kt`

- [ ] **Step 1: Write failing tests** — Python, using the existing `_repo` helper: `test_trackers_yml_is_copied_verbatim`, `test_check_names_a_stale_trackers_yml`. Kotlin:
```kotlin
@Test fun `bundled trackers_yml equals the pinned submodule file`() {
    val bundled = firstExisting("src/main/res/raw/trackers.yml", "app/src/main/res/raw/trackers.yml")
    val repo = firstExisting("../third-party/android-sigma-rules/ioc-data/trackers.yml", "third-party/android-sigma-rules/ioc-data/trackers.yml")
    assertNotNull("bundled trackers.yml missing", bundled); assertEquals(repo!!.readText(), bundled!!.readText())
}
```
(`firstExisting` returns the first `File` that `isFile`, else null — so a missing file is an assertion failure, not `NoSuchElementException`.)
- [ ] **Step 2: Run** the Python tests → FAIL; bump the submodule to `feat/tracker-registry` (`git -C third-party/android-sigma-rules fetch && git -C third-party/android-sigma-rules checkout feat/tracker-registry && git add third-party/android-sigma-rules`), run the Kotlin test → FAIL (bundled file missing).
- [ ] **Step 3: Implement** `COPIED_FILES`; run `python3 scripts/merge-ioc-data.py`.
- [ ] **Step 4: Run** `python3 -m pytest scripts/test_merge_ioc_data.py -q` and `./gradlew :app:testDebugUnitTest --tests com.androdr.privacy.TrackerRegistryBundleCrossCheckTest --tests com.androdr.ioc.IocDataManifestIntegrityTest -q` → pass.
- [ ] **Step 5: Commit** `build: bundle the tracker registry (submodule -> rules feat/tracker-registry)`.

---

### Task 4: `TrackerRegistry` — parse, index, verified refresh, feed health

**Files:**
- Create: `app/src/main/java/com/androdr/privacy/TrackerCategory.kt`, `TrackerRegistry.kt`
- Modify: `ioc/FeedHealthRecorder.kt` (`FEED_TRACKER_REGISTRY = "tracker_registry"` + `FEED_LABELS` entry "Tracker registry"); `ioc/IntelRefresher.kt` (`refreshTrackerRegistry()` called **last** in `refreshAll`, reported in `RefreshReport`); `ui/settings/SettingsViewModel.kt` (`UpdateResult` field, `ALL_FEEDS_FAILED` includes it); `ui/settings/SettingsScreen.kt` (`UpdateStatusRow`); `res/values/strings.xml` (`settings_update_tracker_registry` "Tracker registry")
- Modify tests: `ioc/IntelRefresherTest.kt`, `ioc/FeedHealthRecorderTest.kt`, `ioc/ResolverIocDataVerificationTest.kt` (tracker case: verified accepted, tampered ignored)
- Create: `app/src/test/java/com/androdr/privacy/TrackerRegistryTest.kt`

**Interfaces:**
```kotlin
enum class TrackerCategory(val label: String) {
    ADVERTISEMENT("Advertisement"), PROFILING("Profiling"), IDENTIFICATION("Identification"),
    LOCATION("Location"), ANALYTICS("Analytics"), CRASH_REPORTING("Crash reporting"),
    UNCATEGORISED("Uncategorised"), OTHER("Other");
    companion object { fun fromLabel(label: String): TrackerCategory = entries.firstOrNull { it.label == label } ?: OTHER }
}
data class Tracker(val id: Int, val name: String, val website: String, val categories: Set<TrackerCategory>,
    val rawCategories: List<String>, val codePrefixes: List<String>, val codeSegments: List<String>,
    val domainSuffixes: List<String>, val domainLabels: List<String>, val domainPatterns: List<Regex>)
class TrackerSet(val trackers: List<Tracker>, val sourceSha256: String) {
    val size: Int
    /** Trackers with a code prefix that is a dotted-path prefix of some package (`com.a` ⊂ `com.a.b`, not `com.ab`),
     *  or a code segment equal to some dotted segment of some package. Index: sorted prefixes + binary search. */
    fun matchPackages(packages: Collection<String>): Set<Tracker>
    /** Every tracker with a suffix equal to [host] or a `.`-bounded suffix of it, a label equal to one of its labels,
     *  or a pattern that `matches()` the host or one of its label-bounded suffixes.
     *  [host] lower-cased, trailing dot removed; longer than MAX_HOST_CHARS -> empty set. */
    fun matchDomain(host: String): Set<Tracker>
}
object DomainGrammar { fun isRestrictedPattern(p: String): Boolean }   // line-for-line port of validation/domain_grammar.py
@Singleton class TrackerRegistry @Inject constructor(@ApplicationContext context: Context,
    manifest: IocDataManifest = IocDataManifest()) {
    /** Lazily loads the bundled file on first call, never on construction. null = no usable registry
     *  (bundled file corrupt and no verified refresh yet); the privacy scan cannot run. */
    fun current(): TrackerSet?
    suspend fun refresh(): Int         // trackers accepted; 0 = previous kept
    companion object {
        const val PATH = "ioc-data/trackers.yml"; const val MAX_RESPONSE_CHARS = 2_000_000
        const val MIN_TRACKERS = 300; const val MAX_TRACKERS = 2_000; const val MAX_HOST_CHARS = 253
        internal fun parse(yaml: String): TrackerSet?   // null = structurally unusable; per-entry problems drop the entry
    }
}
```
Per-entry policy: an entry with a bad prefix, segment, suffix or label, or a pattern that fails `DomainGrammar.isRestrictedPattern`, drops **that** item; an entry left empty is dropped; a file with fewer than `MIN_TRACKERS` usable entries, more than `MAX_TRACKERS`, wrong `version`, or that throws (incl. `StackOverflowError`) → null. `excluded_domains` is read and ignored. `sourceSha256` = SHA-256 of the parsed text (`ManifestVerifier.sha256`), recorded on each privacy scan. The rule engine's timed regex helper is **not** reused (private; shared ForkJoinPool flagged by PASTA F-007): the restricted grammar (no groups, ≤ 2 quantifiers) plus the 253-char host bound makes the worst case polynomial and small; only 3 real patterns exist.

- [ ] **Step 1: Write failing tests** in `TrackerRegistryTest.kt`:
```kotlin
@Test fun `the bundled file parses with at least 400 trackers`()
@Test fun `matchPackages respects dotted boundaries`()           // prefix com.a: [com.ab] -> {}, [com.a] -> {T}, [com.a.b.c] -> {T}
@Test fun `matchPackages returns every tracker whose prefix matches`() // prefixes com.a (T1), com.a.b (T2): [com.a.b.c] -> {T1, T2}
@Test fun `a code segment matches a package containing it`()       // segment sizmek: [net.sizmek.sdk] -> {T}; [net.sizmekx] -> {}
@Test fun `matchDomain matches suffixes on label boundaries and returns all owners`() // suffix doubleclick.net owned by T1 and T2: "ad.doubleclick.net" -> {T1, T2}; "notdoubleclick.net" -> {}
@Test fun `a domain label matches only a whole label`()            // label alimama: "x.alimama.com" -> {T}; "xalimama.com" -> {}
@Test fun `a pattern matches the host or a label-bounded suffix`() // mst[0-9]*\.is\.autonavi\.com: "mst3.is.autonavi.com", "a.mst3.is.autonavi.com" -> {T}; "xmst3.is.autonavi.com" -> {}
@Test fun `first-party hosts match nothing in the bundled registry`() // every host in first_party_hosts.txt (read from the submodule) -> {}
@Test fun `an unknown category maps to OTHER and Uncategorised maps to UNCATEGORISED`()
@Test fun `a bad pattern drops the pattern, not the file`()
@Test fun `too few, too many, wrong version, deep nesting -> null`()
@Test fun `the grammar rejects the probe-confirmed backtracking patterns`()  // ((a+))+$, (a+?)+$, (a{1,30}){1,30}$, a*b*c*d, .* -> false; the 3 real patterns -> true
@Test fun `DomainGrammar agrees with domain_grammar_py on the shared fixture list`() // fixture file validation/domain_grammar_fixtures.txt in the submodule ("ACCEPT <p>"/"REJECT <p>"), also read by test_domain_grammar.py
@Test fun `a host longer than 253 chars matches nothing`()
@Test fun `refresh keeps the previous set when the manifest refuses`()
@Test fun `refresh replaces the set when a verified file parses`()
@Test fun `construction does not parse`()                           // a context whose raw resource throws: constructing succeeds
@Test fun `a corrupt bundled file gives null until a verified refresh succeeds`()
```
- [ ] **Step 2: Run** `./gradlew :app:testDebugUnitTest --tests com.androdr.privacy.TrackerRegistryTest -q` → FAIL (unresolved).
- [ ] **Step 3: Implement** per Interfaces; `refresh()` mirrors `OemPrefixResolver.refresh()` (`manifest.verified(PATH, MAX_RESPONSE_CHARS)`, parse, swap atomically).
- [ ] **Step 4: Wire feed health and settings** as listed under Files.
- [ ] **Step 5: Run** `TrackerRegistryTest`, `IntelRefresherTest`, `FeedHealthRecorderTest`, `ResolverIocDataVerificationTest`, `SettingsViewModel*Test` → pass.
- [ ] **Step 6: Commit** `feat(privacy): tracker registry — per-entry parse, prefix/segment/suffix index, verified refresh`.

---

### Task 5: `DexPackageReader` — hardened class-name table reader

**Files:**
- Create: `app/src/main/java/com/androdr/privacy/DexPackageReader.kt`
- Create: `app/src/test/java/com/androdr/privacy/SyntheticDex.kt`, `DexPackageReaderTest.kt`

**Interfaces:**
```kotlin
object DexPackageReader {
    enum class DexOutcome { READ, SKIPPED_OVER_CAP, MALFORMED, TIME_LIMIT }
    data class Result(val packages: Set<String>, val dexOutcomes: Map<String, DexOutcome>,
        val packageCapHit: Boolean, val bytesRead: Long) {
        val partial: Boolean get() = packageCapHit || dexOutcomes.values.any { it != DexOutcome.READ }
    }
    /** One per app, shared by its base and split APKs. [nanoTime] is injectable for tests. */
    class ReadBudget(val deadlineNanos: Long, var remainingAppBytes: Long = MAX_APP_BYTES,
        var remainingPackages: Int = MAX_PACKAGES, val nanoTime: () -> Long = System::nanoTime) {
        fun expired(): Boolean = nanoTime() >= deadlineNanos
    }
    class ApkUnreadableException(message: String, cause: Throwable? = null) : Exception(message, cause)
    /** Reads only the dex files Android loads: classes.dex, then classes2.dex, classes3.dex, … stopping at the first gap. */
    fun read(apk: File, budget: ReadBudget, maxDexBytes: Int = MAX_DEX_BYTES, maxDexFiles: Int = MAX_DEX_FILES): Result
    const val MAX_DEX_BYTES = 32 * 1024 * 1024   // largest real dex measured: 9.7 MB
    const val MAX_APP_BYTES = 256L * 1024 * 1024
    const val MAX_PACKAGES = 20_000              // largest real app measured: 2,724 packages
    const val MAX_DEX_FILES = 100
    const val MAX_DESCRIPTOR_CHARS = 512
}
```
Reading rules: open with `ZipFile`; for each loaded dex name, read through the entry's stream in 64 KiB chunks with a counting loop that stops and marks `SKIPPED_OVER_CAP` once `maxDexBytes` or `budget.remainingAppBytes` is exceeded — never consult `entry.size`; decrement the budget by bytes actually read. **Deadline:** check `budget.expired()` before each dex, after each chunk, and every 4,096 descriptors; when expired, mark the current and all remaining loaded dex `TIME_LIMIT`, keep the packages already stored, and return. An `IOException`/`ZipException` while reading an entry's stream (e.g. a corrupt or path-traversal entry) marks that dex `MALFORMED`; one opening the zip → `ApkUnreadableException`. Header: magic `dex\n03[5-9]\0` or `dex\n04[01]\0`; all offset/size arithmetic in `Long`, every table bounded by the array; uleb128 at most 5 bytes; string data must end with NUL inside the array — violating any of these makes the dex `MALFORMED` (its packages discarded; other dex files still count). **Descriptors are not structure:** a type descriptor that is not a class (`[I`, `J`), longer than `MAX_DESCRIPTOR_CHARS`, or whose package part has a segment not matching `^[\p{L}\p{N}_$-]+$` is skipped silently — it never marks the dex `MALFORMED`; the class-name part is not validated (`-$$Lambda$Foo`, non-ASCII names are fine). Packages from `Lcom/a/b/C;` → `com.a.b`; default package ignored. When `budget.remainingPackages` reaches 0, stop **storing** new packages (set `packageCapHit`) — the cap exceeds real apps 7×.

- [ ] **Step 1: Write `SyntheticDex`** — `dex(descriptors: List<String>, version: String = "035"): ByteArray` (valid header, string_ids, type_ids, string data with correct multi-byte uleb128 and MUTF-8); `apk(entries: Map<String, ByteArray>, stored: Boolean = true): File`; `bomb(declaredSize: Long, realSize: Int): File` (writes a zip whose central-directory size is `declaredSize` while the deflated stream inflates to `realSize`; for `declaredSize = -1` use a streamed entry with data descriptor).
- [ ] **Step 2: Write failing tests** in `DexPackageReaderTest.kt`:
```kotlin
@Test fun `packages come from loaded dex files and are de-duplicated`()            // classes.dex {Lcom/a/B;, Lcom/a/C$D;}, classes2.dex {Lcom/x/Y;, LTop;} -> {com.a, com.x}
@Test fun `dex versions 035 through 041 are accepted`()                           // 035, 039, 041 each read
@Test fun `a dex outside the load sequence is not read`()                         // classes.dex + classes3.dex (gap) + classes99.dex -> only classes.dex
@Test fun `a zip that lies about the entry size is capped by bytes actually read`() // bomb(declared=1_000, real=2_000_000) with maxDexBytes 400_000 -> SKIPPED_OVER_CAP, bytesRead <= 400_000 + 65_536
@Test fun `an entry with unknown size is capped the same way`()                   // bomb(declared=-1, ...)
@Test fun `the per-app byte budget is shared across APKs`()                       // one ReadBudget(remainingAppBytes = 1.5 dex) over base + split: the split's dex is SKIPPED_OVER_CAP
@Test fun `an expired deadline stops reading and marks the remaining dex TIME_LIMIT`() // fake nanoTime past the deadline after the first chunk: classes.dex packages kept, classes2.dex TIME_LIMIT, partial
@Test fun `a malformed dex costs that dex, the other dex files still count`()      // classes.dex valid {com.a}, classes2.dex out-of-range string_ids_off -> packages {com.a}, partial true
@Test fun `huge table counts do not overflow`()                                   // string_ids_size 0xFFFFFFF0 -> MALFORMED, no exception
@Test fun `a string without a terminator is malformed`()
@Test fun `multi-byte uleb128 and non-ASCII names are read`()                     // a 200-char package path; Lcom/ex/Café; -> com.ex; Lcom/ünï/A; -> com.ünï
@Test fun `odd descriptors are skipped without marking the dex malformed`()       // Lcom/a/-$$Lambda$Foo; -> com.a stored; 600-char descriptor and "Lcom/a b/C;" skipped; [I and J ignored; outcome READ
@Test fun `hitting the package cap marks the result partial`()                    // 30 packages, ReadBudget(remainingPackages = 20)
@Test fun `stored and deflated entries both read`()
@Test fun `a file that is not a zip throws ApkUnreadableException`()
```
- [ ] **Step 3: Run** → FAIL (unresolved).
- [ ] **Step 4: Implement** per the rules.
- [ ] **Step 5: Run** the class and `detekt` → pass.
- [ ] **Step 6: Commit** `feat(privacy): DexPackageReader — loaded-dex-only, byte-counted caps, per-dex isolation`.

---

### Task 6: `ApkPackageInspector` — every installed app, every split, isolated

**Files:**
- Create: `app/src/main/java/com/androdr/privacy/ApkPackageInspector.kt` (interface `AppInspector` + `ApkPackageInspector` implementation)
- Create: `app/src/test/java/com/androdr/privacy/ApkPackageInspectorTest.kt` (Robolectric `ShadowPackageManager`)

**Interfaces:**
```kotlin
enum class InspectOutcome { INSPECTED, PARTIAL, COULD_NOT_INSPECT }
data class InstalledApp(val packageName: String, val versionCode: Long, val lastUpdateTime: Long, val appLabel: String,
    val isSystemApp: Boolean, val apkPaths: List<String>)          // base + splitSourceDirs
data class AppInspection(val app: InstalledApp, val packages: Set<String>, val outcome: InspectOutcome, val reason: String?)
interface AppInspector {
    fun installedApps(): List<InstalledApp>                          // getInstalledPackages(0), sorted by packageName
    fun inspect(app: InstalledApp, budget: DexPackageReader.ReadBudget): AppInspection
}
@Singleton class ApkPackageInspector @Inject constructor(@ApplicationContext context: Context) : AppInspector
```
`inspect(app, budget: DexPackageReader.ReadBudget)` (the interface method takes the budget; the runner creates one per app) unions `DexPackageReader.read` over `apkPaths` with that **one** budget; any APK result `partial` → `PARTIAL` (reason lists skipped/malformed dex names, "package cap" or "time limit"); `ApkUnreadableException` on an APK → that APK contributes nothing, outcome `PARTIAL` if another APK read, else `COULD_NOT_INSPECT`; a `TIME_LIMIT` result with no packages at all → `COULD_NOT_INSPECT` "time limit". `reason` is short, report-safe text (`reportSafe`).

Hilt: create `di/PrivacyModule.kt` — `@Module @InstallIn(SingletonComponent::class) abstract class PrivacyModule { @Binds abstract fun appInspector(impl: ApkPackageInspector): AppInspector }` (plus the `@ApplicationScope` provider in Task 9's companion object section).

- [ ] **Step 1: Write failing tests**: `installedApps lists base and split paths, update time and the system flag`; `inspect unions base and split packages`; `a missing apk file is COULD_NOT_INSPECT with a reason`; `one unreadable split of two is PARTIAL and keeps the readable one`; `a partial dex result makes the app PARTIAL`; `base and split share one byte budget`; `a time limit before any package is COULD_NOT_INSPECT`.
- [ ] **Step 2: Run → FAIL. Step 3: Implement. Step 4: Run → pass.**
- [ ] **Step 5: Commit** `feat(privacy): ApkPackageInspector — per-app package facts with visible partial/failed outcomes`.

---

### Task 7: Room — privacy tables, DAO, migration 21 → 22

**Files:**
- Create: `app/src/main/java/com/androdr/data/model/PrivacyEntities.kt`; `app/src/main/java/com/androdr/data/db/PrivacyDao.kt`
- Modify: `data/db/AppDatabase.kt` (4 entities, `version = 22`, `privacyDao()`); `data/model/DnsEvent.kt` (`@Entity(indices = [Index(value = ["appName", "domain", "timestamp"])])` — the DNS table has no index today and Task 9 queries it per (app, domain)); `data/db/Migrations.kt` (`MIGRATION_21_22` with the 4 CREATE TABLEs **and** the `CREATE INDEX index_DnsEvent_appName_domain_timestamp`, all copied from the generated `22.json`); `di/AppModule.kt` (register it beside `MIGRATION_20_21`)
- Create: `app/schemas/com.androdr.data.db.AppDatabase/22.json` (build-generated); tests `data/db/Migration21To22Test.kt`, `data/db/PrivacyDaoTest.kt`

**Interfaces:**
```kotlin
@Entity(tableName = "privacy_scan") data class PrivacyScan(@PrimaryKey(autoGenerate = true) val id: Long = 0,
    val startedAt: Long, val finishedAt: Long?, val appsTotal: Int, val appsInspected: Int, val appsPartial: Int,
    val appsFailed: Int, val registrySize: Int, val registrySha256: String, val dnsWindowStart: Long,
    val dnsCoverageDays: Int,                                  // UTC calendar days in the window with ≥ 1 attributed lookup
    val usageCoverageFrom: Long?)                              // oldest usage event available; null = no usage access
@Entity(tableName = "privacy_app_result", primaryKeys = ["scanId", "packageName"])
data class PrivacyAppResult(val scanId: Long, val packageName: String, val versionCode: Long, val appLabel: String,
    val isSystemApp: Boolean, val outcome: String /* InspectOutcome.name */, val reason: String?)
@Entity(tableName = "privacy_tracker_evidence", primaryKeys = ["scanId", "packageName", "trackerId"])
data class PrivacyTrackerEvidence(val scanId: Long, val packageName: String, val trackerId: Int, val trackerName: String,
    val website: String, val categories: String /* raw labels, "\u001F"-joined */, val inCode: Boolean,
    val lookups: Int, val lookupDays: Int, val background: Int? /* null = unknown */, val firstSeen: Long?, val lastSeen: Long?,
    val newSinceLastScan: Boolean)
@Entity(tableName = "privacy_package_set", primaryKeys = ["packageName"])
data class PrivacyPackageSet(val packageName: String, val versionCode: Long, val lastUpdateTime: Long,
    val readerVersion: Int, val packagesText: String /* "\n"-joined; descriptors validated in Task 5 */)
```
`PrivacyDao`: `insertScan(PrivacyScan): Long`; `finishScan(id, finishedAt, inspected, partial, failed, dnsCoverageDays, usageFrom)`; `upsertResults(List<PrivacyAppResult>)`; `upsertEvidence(List<PrivacyTrackerEvidence>)`; `latestCompleted(): Flow<PrivacyScan?>`; `latestCompletedOnce(): PrivacyScan?` (`finishedAt IS NOT NULL ORDER BY id DESC LIMIT 1`); `results(scanId): Flow<List<PrivacyAppResult>>`; `resultsOnce(scanId): List<PrivacyAppResult>`; `evidence(scanId): Flow<List<PrivacyTrackerEvidence>>`; `evidenceOnce(scanId): List<PrivacyTrackerEvidence>`; `packageSet(pkg): PrivacyPackageSet?`; `upsertPackageSet(PrivacyPackageSet)`; `deletePackageSet(pkg)`; `@Query("DELETE FROM privacy_package_set WHERE packageName NOT IN (SELECT packageName FROM privacy_app_result WHERE scanId = :scanId)") pruneCacheTo(scanId: Long)` (a subquery, never a bound list: 999-variable limit); `@Transaction suspend fun deleteScansBefore(keepFromId: Long)` (three DELETEs: evidence, results, scans); `@Transaction suspend fun deleteAll()` (all four tables). The UI queries never select `privacy_package_set`.

- [ ] **Step 1: Write failing tests** — `Migration21To22Test` (skeleton of `Migration19To20Test`: seed v21 with a `ScanResult` and a `DnsEvent`, migrate, assert the 4 `privacy_%` tables, the `index_DnsEvent_appName_domain_timestamp` index, and both seeded rows). `PrivacyDaoTest`: `latestCompleted ignores an unfinished scan`; `latestCompletedOnce agrees with latestCompleted`; `deleteScansBefore removes older scans' results and evidence only`; `deleteAll empties all four tables`; `packageSet round-trips`; `pruneCacheTo keeps exactly the packages of that scan with 1,500 results` (proves no variable limit).
- [ ] **Step 2: Run → FAIL. Step 3: Implement; `./gradlew :app:kspDebugKotlin -q` exports `22.json`; copy its CREATE statements into `MIGRATION_21_22`; register.** Step 4: Run these plus existing `*Migration*Test` → pass.
- [ ] **Step 5: Commit** `feat(privacy): privacy tables and package-set cache (schema 22)` with `22.json`.

---

### Task 8: Threshold setting and ranking (pure, shared)

**Files:**
- Modify: `data/repo/SettingsRepository.kt`
- Create: `app/src/main/java/com/androdr/privacy/PrivacyRanking.kt`
- Create tests: `privacy/PrivacyRankingTest.kt`, `data/repo/SettingsRepositoryPrivacyTest.kt`

**Interfaces:**
- `SettingsRepository`: `refusedTrackerCategories: Flow<Set<TrackerCategory>>` (key `privacy_refused_categories`, default every category except `CRASH_REPORTING` and `OTHER` — so `UNCATEGORISED` **is** refused by default (owner); unknown stored names ignored); `setRefusedTrackerCategories(Set<TrackerCategory>)`; `privacyShowSystemApps: Flow<Boolean>` (default false); `setPrivacyShowSystemApps(Boolean)`.
```kotlin
enum class Evidence { CODE, NETWORK, BOTH }
data class TrackerRow(val trackerId: Int, val name: String, val website: String, val categories: Set<TrackerCategory>,
    val rawCategories: List<String>, val inCode: Boolean, val lookups: Int, val lookupDays: Int, val background: Int?,
    val firstSeen: Long?, val lastSeen: Long?, val newSinceLastScan: Boolean) { val evidence: Evidence }
data class AppPrivacyRow(val packageName: String, val versionCode: Long, val appLabel: String, val isSystemApp: Boolean, val outcome: InspectOutcome,
    val reason: String?, val trackers: List<TrackerRow>, val refusedInCode: Int, val refusedCategories: Set<TrackerCategory>,
    val newCrossing: Boolean)
enum class RowSection { NEEDS_ATTENTION /* PARTIAL or COULD_NOT_INSPECT */, CROSSING, OTHER }
data class PrivacySummary(val crossing: Int, val newCrossing: Int, val notInspected: Int, val scannedAt: Long)
object PrivacyRanking {
    fun rows(results: List<PrivacyAppResult>, evidence: List<PrivacyTrackerEvidence>, refused: Set<TrackerCategory>,
             showSystemApps: Boolean): List<Pair<RowSection, List<AppPrivacyRow>>>
    fun byTracker(rows: List<AppPrivacyRow>): List<Pair<TrackerRow, List<AppPrivacyRow>>>   // most apps first
    fun summary(scan: PrivacyScan, results: List<PrivacyAppResult>, evidence: List<PrivacyTrackerEvidence>,
                refused: Set<TrackerCategory>, showSystemApps: Boolean): PrivacySummary
}
```
Rules: `refusedInCode` counts trackers with `inCode` and a refused category (a tracker with several categories counts once); an app is CROSSING iff `refusedInCode > 0` (network-only never crosses); inside CROSSING order by `refusedInCode` desc, then `appLabel`; inside an app, trackers with refused categories first, then name; `newCrossing` = crossing and any refused in-code tracker has `newSinceLastScan`. **System apps:** the toggle hides system apps from CROSSING and OTHER only; NEEDS_ATTENTION (PARTIAL or COULD_NOT_INSPECT) lists every app regardless of the toggle, and `summary.notInspected` counts exactly that section — so the card's failure clause never disagrees with the screen and can never be hidden by the toggle. `summary` is computed from `rows` (one source of truth for the card, the screen and the Apps tab).

- [ ] **Step 1: Write failing tests** — `PrivacyRankingTest`: `network-only refused evidence does not make an app cross`; `code evidence of a refused category does`; `failed and partial apps are in NEEDS_ATTENTION, never OTHER`; `a failed system app is in NEEDS_ATTENTION and counted even when system apps are hidden`; `notInspected counts PARTIAL and COULD_NOT_INSPECT`; `crossing apps order by refused-in-code count then label`; `system apps are excluded from CROSSING and OTHER unless showSystemApps`; `summary equals the counts of rows for the same inputs`; `changing refused changes summary and rows identically`; `an Uncategorised tracker in code crosses under the default threshold`; `OTHER category is not refused by default`; `byTracker lists most apps first`; `evidence is CODE, NETWORK or BOTH`. `SettingsRepositoryPrivacyTest`: default (contains UNCATEGORISED, not CRASH_REPORTING or OTHER); round-trip; unknown stored name ignored.
- [ ] **Step 2: Run → FAIL. Step 3: Implement. Step 4: Run → pass.**
- [ ] **Step 5: Commit** `feat(privacy): threshold setting and the single ranking/summary function`.

---

### Task 9: Scan runner — inspection, network correlation, usage coverage, cache, retention

**Files:**
- Create: `privacy/PrivacyScanRunner.kt`, `privacy/NetworkEvidenceCorrelator.kt`, `privacy/ForegroundIntervals.kt`, `privacy/UsageIntervalReader.kt`, `di/ApplicationScope.kt`
- Modify: `data/db/DnsEventDao.kt`; `di/PrivacyModule.kt` (app scope provider)
- Create tests: `privacy/PrivacyScanRunnerTest.kt`, `privacy/NetworkEvidenceCorrelatorTest.kt`, `privacy/ForegroundIntervalsTest.kt`, `privacy/PrivacyBoundaryTest.kt`

**Interfaces:**
```kotlin
// DnsEventDao
data class DomainLookupCount(val appName: String, val domain: String, val lookups: Int, val days: Int, val first: Long, val last: Long)
@Query("SELECT appName, domain, COUNT(*) AS lookups, COUNT(DISTINCT timestamp / 86400000) AS days, MIN(timestamp) AS first, " +
       "MAX(timestamp) AS last FROM DnsEvent WHERE timestamp >= :since AND appName IS NOT NULL GROUP BY appName, domain")
suspend fun lookupCountsSince(since: Long): List<DomainLookupCount>
// served by index_DnsEvent_appName_domain_timestamp (Task 7)
@Query("SELECT timestamp FROM DnsEvent WHERE appName = :app AND domain = :domain AND timestamp >= :since ORDER BY timestamp")
suspend fun lookupTimes(since: Long, app: String, domain: String): List<Long>
@Query("SELECT COUNT(DISTINCT timestamp / 86400000) FROM DnsEvent WHERE timestamp >= :since AND appName IS NOT NULL")
suspend fun coverageDaysSince(since: Long): Int                // UTC days; 0 = the monitor recorded nothing attributable

class UsageIntervalReader @Inject constructor(@ApplicationContext context: Context, usageAccess: UsageAccess) {
    /** All ACTIVITY_RESUMED / ACTIVITY_PAUSED (and STOPPED) events in [since, until], every package, no cap, no minute collapse.
     *  null when usage access is not granted or the service is unavailable. */
    fun read(since: Long, until: Long): UsageIntervals?
}
data class UsageIntervals(val coverageFrom: Long, val byPackage: Map<String, List<LongRange>>)
object ForegroundIntervals { fun build(events: List<Pair<String, Pair<Long, Boolean>>> /* pkg, (time, isForeground) */, until: Long): Map<String, List<LongRange>> }

object NetworkEvidenceCorrelator {
    data class Key(val packageName: String, val trackerId: Int)
    data class NetworkEvidence(val lookups: Int, val days: Int, val background: Int?, val first: Long, val last: Long)
    /** Matches each distinct domain once; returns evidence per (app, tracker). [times] fetches timestamps only for matched
     *  (app, domain) pairs, at most MAX_TIMED_PAIRS of them (most lookups first); beyond that background = null. */
    suspend fun correlate(counts: List<DomainLookupCount>, registry: TrackerSet, installed: Set<String>,
        usage: UsageIntervals?, times: suspend (app: String, domain: String) -> List<Long>): Map<Key, NetworkEvidence>
    const val MAX_TIMED_PAIRS = 5_000
}

sealed class PrivacyScanProgress { object Idle : PrivacyScanProgress(); data class Running(val done: Int, val total: Int) : PrivacyScanProgress()
    data class Finished(val scanId: Long) : PrivacyScanProgress(); data class Failed(val message: String) : PrivacyScanProgress() }
@Singleton class PrivacyScanRunner @Inject constructor(inspector: AppInspector, registry: TrackerRegistry, dao: PrivacyDao,
    dnsEvents: DnsEventDao, usage: UsageIntervalReader, @ApplicationScope scope: CoroutineScope) {
    internal var clock: () -> Long = System::currentTimeMillis       // test seams (Hilt cannot inject function types)
    internal var nanoTime: () -> Long = System::nanoTime
    val progress: StateFlow<PrivacyScanProgress>
    /** Starts a scan on [scope] (Dispatchers.IO) unless one is running; returns false when one already is. */
    fun start(): Boolean
    suspend fun deleteAll(): Boolean                          // false (nothing deleted) while a scan runs
    companion object { const val DNS_WINDOW_MS = 30L * 24 * 3600 * 1000; const val PER_APP_TIMEOUT_MS = 30_000L
        const val READER_VERSION = 1; const val MAX_PACKAGES_TEXT_CHARS = 1_000_000 }
}
```
No application-wide scope exists today (checked 2026-11-06): in `di/PrivacyModule.kt` (Task 6) add a companion `@Provides @Singleton @ApplicationScope fun appScope(): CoroutineScope = CoroutineScope(SupervisorJob() + Dispatchers.IO + CoroutineExceptionHandler { _, t -> Log.e("AppScope", "uncaught", t) })` and `@Qualifier annotation class ApplicationScope` in `di/ApplicationScope.kt`. Moving other app-lifetime scopes onto it is a follow-up.

Correlation rules: a lookup counts toward background only when `usage != null`, the lookup time ≥ `usage.coverageFrom`, and it lies in no foreground interval of that package; lookups before `coverageFrom` or with `usage == null` make `background = null` for that pair. Packages not in `installed` are ignored. Domains are lower-cased and the trailing dot removed before `matchDomain`.

Run algorithm (own `Mutex`, `tryLock`; never `ScanLock`). The whole launched body is `try { … } catch (c: CancellationException) { throw c } catch (t: Throwable) { progress = Failed(reportSafe(t)) } finally { mutex.unlock() }` — nothing escapes to the scope.
1. `set = registry.current()`; null → `Failed("tracker registry unavailable")`, no scan row.
2. `previous = dao.latestCompletedOnce()`; insert scan row (`registrySize = set.size`, `registrySha256 = set.sourceSha256`); `apps = inspector.installedApps()`.
3. Per app, inside `try { … } catch (c: CancellationException) { throw c } catch (t: Throwable) { COULD_NOT_INSPECT "resource limit: ${t.javaClass.simpleName}" }` — no `withTimeout`; the time limit is `ReadBudget(deadlineNanos = nanoTime() + PER_APP_TIMEOUT_MS * 1_000_000, nanoTime = nanoTime)` passed to `inspect`:
   - cache: `runCatching { dao.packageSet(pkg) }` — a throw (e.g. an oversized row) → `deletePackageSet(pkg)` and treat as a miss; a hit is used only when versionCode, lastUpdateTime and `READER_VERSION` all match;
   - miss → `inspect(app, budget)`; cache only when `INSPECTED` and the joined text ≤ `MAX_PACKAGES_TEXT_CHARS`;
   - in-code trackers = `set.matchPackages`; write the result row; progress.
4. Network: `lookupCountsSince(windowStart)` → `correlate(...)`; merge with in-code into evidence rows.
5. `newSinceLastScan`: false for every row when `previous == null` (first scan) **or** the app's result in `previous` was not `INSPECTED`; otherwise true when (pkg, trackerId) is absent from `evidenceOnce(previous.id)`.
6. Upsert evidence; `finishScan(..., dnsCoverageDays = coverageDaysSince(windowStart), usageFrom)`; `deleteScansBefore(scanId)`; `pruneCacheTo(scanId)`; `Finished`.

- [ ] **Step 1: Write failing tests**
  - `ForegroundIntervalsTest`: pairs resume/pause per package; an open interval ends at `until`; system packages are kept.
  - `NetworkEvidenceCorrelatorTest` (a counting fake for `times` and a counting wrapper on the registry): `each distinct domain is matched once`; `timestamps are fetched only for matched pairs`; `a domain owned by two trackers yields two evidence rows`; `www.google.com yields no evidence with the bundled registry`; `uninstalled apps are ignored`; `background is null without usage`; `background is null for lookups older than usage coverage`; `background counts lookups outside foreground intervals within coverage`; `a system app's foreground use is honoured`.
  - `NetworkEvidenceCorrelatorTest` also: `beyond MAX_TIMED_PAIRS, background is null and counts are still exact`.
  - `PrivacyScanRunnerTest` (fake `AppInspector`, in-memory DB, seeded DnsEvent rows; `registry.current()` mocked to return a small hand-built `TrackerSet` — the 300-tracker floor applies to `parse`, not to `TrackerSet`): `in-code trackers come from matchPackages`; `an inspector that throws OutOfMemoryError yields COULD_NOT_INSPECT and the scan finishes`; `the runner passes a deadline PER_APP_TIMEOUT_MS ahead and one budget per app` (fake inspector records the budget); `a PARTIAL inspection is recorded and not cached`; `an over-size package text is not cached`; `a cache row that throws on read is deleted and the app re-inspected`; `an unchanged app (version, update time, reader version) reuses the cached package set`; `a changed lastUpdateTime re-inspects`; `the first scan marks nothing new`; `newSinceLastScan marks pairs absent from the previous completed scan`; `an app not INSPECTED in the previous scan is not marked new`; `completing a scan deletes older scans and prunes package sets of uninstalled apps`; `a throw after the loop (dao fails in finishScan) gives Failed and releases the lock` (a second `start()` returns true); `a null registry gives Failed without a scan row`; `start returns false while a scan runs`; `the scan never touches ScanLock` (a `ScanLock` held by the test does not block completion); `a registry refresh during the scan does not change the set used`; `the scan row records the registry hash and coverage days`; `deleteAll empties the tables and returns false while running`.
  - `PrivacyBoundaryTest` (source scan): no file under `reporting/`, `sigma/`, `ui/history/`, `data/repo/ScanWriteRepository.kt`, `data/store/` references `com.androdr.privacy` or `privacy_`; no file under `privacy/` references `ScanLock` or `ScanResult`.
- [ ] **Step 2: Run → FAIL. Step 3: Implement** per Interfaces and rules. **Step 4: Run** these classes, then the full suite once (`./gradlew :app:testDebugUnitTest -q`) → pass.
- [ ] **Step 5: Commit** `feat(privacy): scan runner — isolated per-app inspection, distinct-domain correlation, usage coverage, own lock`.

---

### Task 10: Privacy screen, ViewModel, route, Dashboard card

**Files:**
- Create: `ui/privacy/PrivacyViewModel.kt`, `PrivacyScreen.kt`, `PrivacyThresholdSheet.kt`, `PrivacyEvidenceText.kt` (pure formatter)
- Modify: `MainActivity.kt` (`composable("privacy")`, bottom bar unchanged); `ui/dashboard/DashboardScreen.kt` (`PrivacyCard` after `OpenAlertsCard`); `ui/dashboard/DashboardViewModel.kt` (new constructor parameter `privacyDao: PrivacyDao`; `privacySummary: StateFlow<PrivacySummary?>` via `PrivacyRanking.summary` over `latestCompleted` + results + evidence + both settings); `app/src/test/java/com/androdr/data/repo/FindingReadersLowHeapTest.kt` (the only test constructing `DashboardViewModel`: pass `privacyDao = mockk { every { latestCompleted() } returns flowOf(null) }`); `res/values/strings.xml` (new strings below; `history_clear_credential_description` gains "Privacy scan results are kept; delete them from the privacy screen.")
- Create tests: `ui/privacy/PrivacyViewModelTest.kt`, `ui/privacy/PrivacyEvidenceTextTest.kt`, `ui/dashboard/DashboardPrivacySummaryTest.kt`, `ui/privacy/PrivacyCopyTest.kt`

**Interfaces:**
- `PrivacyViewModel(dao, runner, settings, registry)`: `state: StateFlow<PrivacyUiState>`; `runScan()` → `runner.start()`; `setRefused(Set<TrackerCategory>)`; `setShowSystemApps(Boolean)`; `deleteResults()` → `runner.deleteAll()`.
- `PrivacyUiState(scan: PrivacyScan?, sections: List<Pair<RowSection, List<AppPrivacyRow>>>, byTracker: List<Pair<TrackerRow, List<AppPrivacyRow>>>, refused: Set<TrackerCategory>, showSystemApps: Boolean, progress: PrivacyScanProgress, registrySizeAtScan: Int?, networkDays: Int?, registryAvailable: Boolean)` — `registrySizeAtScan = scan.registrySize`; `networkDays = scan.dnsCoverageDays` (0 → the no-monitor line); `registryAvailable = registry.current() != null` (false → Run disabled, `privacy_registry_unavailable` shown). A tracker's website renders as a link only when it starts with `https://`; otherwise as plain text.
- `object PrivacyEvidenceText { fun line(row: TrackerRow, res: Resources): String; fun appStatus(row: AppPrivacyRow, registrySize: Int, res: Resources): String }` — `appStatus` returns `privacy_none_from_registry` only for `INSPECTED` apps with no trackers; `PARTIAL` → `privacy_partial`; `COULD_NOT_INSPECT` → `privacy_could_not_inspect`.

Strings (exact; counts are `<plurals>`):
- `privacy_title` "Privacy scan"; `privacy_card_never` "Privacy scan not run yet"
- plurals `privacy_card_crossing` "%d app crosses your threshold" / "%d apps cross your threshold"; `privacy_card_new` "%d new since last scan"; plurals `privacy_card_failed` "%d could not be inspected"; `privacy_card_scanned` "scanned %s"; the card joins present clauses with " · "
- `privacy_run` "Run privacy scan"; `privacy_progress` "Inspecting %1$d of %2$d apps"; `privacy_running_elsewhere` "A privacy scan is already running"
- `privacy_tab_by_app` "By app"; `privacy_tab_by_tracker` "By tracker"; `privacy_section_attention` "Could not be fully inspected"; `privacy_section_crossing` "Cross your threshold"; `privacy_section_other` "Other apps"
- `privacy_none_from_registry` "None of the %1$d trackers in the registry were found in its code"; `privacy_partial` "Partly inspected: %1$s"; `privacy_could_not_inspect` "Could not inspect: %1$s"
- `privacy_evidence_code` "found in code"; `privacy_evidence_network` "looked up domains of this tracker — %1$s"; `privacy_evidence_both` "found in code; also looked up its domains — %1$s"; network detail plurals `privacy_lookups` "%d lookup"/"%d lookups", `privacy_days` "on %d day"/"on %d days", `privacy_background` "%d in background", `privacy_background_unknown` "background use unknown", `privacy_last_seen` "last %s"
- `privacy_network_caveat` "Lookups can be caused by links, web pages or emails the app displays, so they never count toward your threshold on their own."
- `privacy_network_coverage` plurals "Network evidence covers %d day" / "covers %d days"; `privacy_no_monitor` "The network monitor recorded no lookups in the last 30 days, so there is no network evidence."
- `privacy_limits` "Code inspection can miss trackers whose code has been renamed by the app's build tools, or code loaded at runtime. Apps using encrypted DNS, or reporting through Google Play services, are not visible on the network. Domains a tracker shares with its company's ordinary services (such as google.com) are not used as evidence. Tracking by the app's own developer is not covered."
- `privacy_registry_unavailable` "The tracker registry could not be loaded, so a privacy scan cannot run. It will be retried at the next intelligence update."
- `privacy_system_toggle` "Include system apps (can only be disabled, not removed)"; `privacy_threshold_title` "What I refuse"; six `privacy_cat_*` labels + explanations from spec §4.1; `privacy_cat_uncategorised` "Uncategorised" with explanation "Exodus lists it as a tracker but gives no purpose; many are ad networks"; `privacy_cat_other` "Other (new category from the registry)"
- `privacy_delete` "Delete privacy results"; `privacy_delete_confirm` "Delete the stored list of every app's code packages and tracker findings?"
- `privacy_attribution` "Tracker data: Exodus Privacy (ODbL 1.0)"; `privacy_last_scan` "Last scan: %1$s"

- [ ] **Step 1: Write failing tests**
  - `PrivacyEvidenceTextTest`: `a network-only row never says carries or found in code`; `both shows code and the network detail`; `background null renders unknown`; `an INSPECTED app with no trackers renders none-from-registry with the scan's registry size`; `PARTIAL and COULD_NOT_INSPECT never render none-from-registry` (Review Focus 1).
  - `DashboardPrivacySummaryTest`: `null when never scanned`; `failed clause present when notInspected > 0`; `changing the refused set or the system toggle changes the summary exactly as the screen rows` (Review Focus 4).
  - `PrivacyViewModelTest`: `sections come from PrivacyRanking with the current settings`; `runScan when one is running exposes privacy_running_elsewhere`; `deleteResults delegates to the runner`.
  - `PrivacyCopyTest`: `strings contain no "no trackers" and no "carries" in network strings`; `PrivacyScreen references privacy_limits, privacy_network_caveat and privacy_attribution`; `MainActivity has the privacy route and five bottom destinations`; `history clear-all text mentions that privacy results are kept`.
  - `PrivacyViewModelTest` also: `a null registry disables Run and exposes registry-unavailable`; `a non-https website is not a link` (pure helper `PrivacyEvidenceText.websiteLink(url): String?`).
- [ ] **Step 2: Run → FAIL. Step 3: Implement** the screen (top bar with back; header with last-scan date, network coverage line, Run button or progress; two tabs; By-app in the three sections; app detail sheet listing tracker rows via `PrivacyEvidenceText`; By-tracker list; system toggle; threshold sheet with eight checkboxes (six categories, Uncategorised, Other); footer with limits, network caveat and attribution; overflow menu with Delete, confirmed by dialog), the card (`onNavigate("privacy")`), the route.
- [ ] **Step 4: Run** the four classes and `:app:lintDebug` → pass.
- [ ] **Step 5: Commit** `feat(privacy): privacy screen, threshold sheet, dashboard card, delete action`.

---

### Task 11: Apps-tab crossover line

**Files:** `ui/apps/AppScanScreen.kt` (`AppGroupDetailSheet`: "Trackers: N · M refused, found in code" plus "as of <scan date>"; tap → `privacy`); `ui/apps/AppScanViewModel.kt` (`privacyByPackage: StateFlow<PrivacyCrossover>` where `data class PrivacyCrossover(val scannedAt: Long?, val byPackage: Map<String, AppPrivacyRow>)`, from `PrivacyRanking.rows` with `showSystemApps = true`, keeping only rows whose `versionCode` equals the installed version); `privacy/InstalledVersions.kt` (`@Singleton class InstalledVersions @Inject constructor(@ApplicationContext ctx: Context) { fun versionCode(pkg: String): Long? }`, `PackageInfoCompat.getLongVersionCode`, null when not installed — injected into `AppScanViewModel`); `MainActivity.kt` (`onNavigateToPrivacy`); test `ui/apps/AppScanViewModelPrivacyTest.kt`.

- [ ] **Step 1: Failing tests** — `privacyByPackage reflects the latest scan under the current threshold`; `empty without a privacy scan`; `an app updated since the privacy scan has no line`; `scannedAt is the scan's finish time`.
- [ ] **Step 2: Run → FAIL. Step 3: Implement. Step 4: Run → pass. Step 5: Commit** `feat(apps): tracker line on a flagged app's sheet`.

---

### Task 12: Documentation, gates, safe-ordering close, release battery

- [ ] **Step 1: ARCHITECTURE.md** — a new top-level section "Privacy scan" (not under Detection) plus a Module Map row for `com.androdr.privacy`: the two facts, the registry and its normalisation, code-only crossing, own tables and own lock, the hostile-APK rules, limits, ODbL. Commit `docs: privacy scan architecture`.
- [ ] **Step 2: Full local gates** — `rm -rf app/build/test-results/testDebugUnitTest && ./gradlew :app:testDebugUnitTest detekt :app:lintDebug --continue -q` → 0 failures, detekt and lint clean.
- [ ] **Step 3: Open the AndroDR PR** (`feat/privacy-scan`; body links spec and plan, states the submodule points at rules `feat/tracker-registry`). Wait for `build-and-test`, `lint-and-detekt`, `instrumented`, CodeQL — **expect `submodule-check` and therefore `ci-success` red** at this step.
- [ ] **Step 4: Safe-ordering close** — open the rules PR, wait for `validate` green, merge; re-point the submodule at rules main (`git -C third-party/android-sigma-rules checkout main && git -C third-party/android-sigma-rules pull`, `git add`, commit `build: re-point submodule at rules main (tracker registry)`, push); now wait for `ci-success` green; merge the AndroDR PR.
- [ ] **Step 5: Release battery** — emulator API 36.1 and the physical F916B, clean install: run a privacy scan; confirm progress, that Chrome or YouTube shows Firebase Analytics "found in code", that no app is attributed "Google Ads" from ordinary Google lookups, the limits/caveat/attribution are visible, the system toggle and threshold change the card and the screen alike, and Delete clears the screen. Hostile-APK fixture: `SyntheticDex.bomb` is not installable (unsigned, no manifest), so build an installable one with `test-adversary/fixtures/privacy/build-hostile-apk.sh` (create it): `aapt2 link` a minimal manifest (package `com.androdr.fixture.privacyhostile`) against the SDK's `android.jar`, add a `classes.dex` from a small Python generator (`gen_dex.py`, 40,000 distinct packages — valid dex, over `MAX_PACKAGES`) and a `classes2.dex` with an out-of-range `string_ids_off`, `zipalign -p 4`, `apksigner sign` with `~/.android/debug.keystore`. Install it (if Android refuses the malformed `classes2.dex` at install, drop it and keep the 40k-package variant), run the scan, and confirm the app shows under "Could not be fully inspected" as partly inspected while the scan completes; uninstall it afterwards.

## Follow-ups to file (not built here)

- Scheduled rules-repo workflow running the mirror script and opening a PR with a diff summary.
- A rules-repo lint for over-broad Exodus network signatures beyond the first-party host list.
- If a future SIGMA rule wants "carries a tracker of category X", that is its own design cycle (the facts are outside the telemetry store by owner ruling).
- Move the OEM/brand hand-copied bundles onto `merge-ioc-data.py` `COPIED_FILES`.
- Move other app-lifetime coroutine scopes onto `@ApplicationScope`.
- Ask Exodus upstream to categorise the 116 uncategorised trackers (or curate categories in the mirror, as its own decision).
