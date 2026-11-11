# Privacy Evidence Details (Part A) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Every tracker the privacy scan lists for an app can be tapped to see what was actually matched: the list signatures, the app's matching code packages, and the tracker domains the app looked up, with counts and times.

**Architecture:** The scan records the detail when it runs, as a dated snapshot in two new `privacy_*` tables (Room 22 → 23). Matching is not forked: `TrackerSet` gets one traversal per evidence kind, and both the old tracker-only functions and the new detailed ones are thin wrappers over it. The totals the lists rank and count from stay exactly as they are; the detail is read only when the details view opens, through a small reader in `privacy/`. The public privacy policy changes in the same pull request.

**Tech Stack:** Kotlin, Room (KSP, exported schemas), Hilt, Jetpack Compose + Navigation, Robolectric, MockK, pytest (policy check).

**Spec:** `docs/superpowers/specs/2026-11-10-privacy-details-timeline-pipeline-design.md` — sections 4 (Part A), 7, 8, 9 and 12. Wording rules: `docs/superpowers/specs/2026-11-06-privacy-scan-design.md` section 4.3.

## Global Constraints

- **Matching must not fork** (spec 4.2): one traversal, cross-checked on the real bundled list (`app/src/main/res/raw/trackers.yml`).
- **Totals stay authoritative** (4.2): nothing ranks, counts or crosses a threshold from the detail tables. `PrivacyEvidenceRows`, `PrivacyRanking` and `privacy_tracker_evidence` are not changed, and every existing test of them stays green unchanged.
- **Caps** (4.3): at most 200 matching packages stored per app + tracker, with the true number kept; domains bounded only by the correlator's existing limits (`MAX_MATCHED_PER_APP = 200`, `MAX_MATCHED_PAIRS = 20_000`), a domain stored only if it was counted; background per domain is a number only where the scan timed it, otherwise unknown (null), never zero.
- **Storage** (4.2): new `privacy_*` tables only; Room 22 → 23 with a migration test and the exported `23.json`; deleted when a newer scan completes and by "Delete privacy results"; never exported; `PrivacyBoundaryTest` holds as written (it is not edited).
- **Loading** (4.2): details for one app + tracker are read when the view opens, not with the lists. The list queries are not touched.
- **Old results** (4.1): totals as today plus the line "Run a new privacy scan to record the matching packages and domains." No back-fill. An absent detail never reads as "nothing matched".
- **Text** (4.3 + earlier design 4.3): package names and domains are shown through `displaySafe` with a length that fits a full domain; anything cut is visibly cut ("…"). Network evidence is worded "looked up domains of …", never "carries"; the note "Lookups can be caused by links, web pages or emails the app displays" stands beside it.
- **Source gates:** `PrivacyBoundaryTest`, `PrivacySourceStyleTest` (no named argument glued to a comma, no blank line before a closing brace, in privacy source and test directories), `PrivacyCopyTest`.
- **Policy** (8): changed in this pull request, rendered with `python3 scripts/render_privacy.py docs/PRIVACY_POLICY.md cloudflare-worker.js`, held by a check that runs in CI on a policy-only change. "AndroDR collects no data" stays.
- **Commands:** every command starts with `cd /home/yasir/AndroDR/.claude/worktrees/fix-pasta-audit-hardening`. Gradle runs as `JAVA_HOME=/home/yasir/.gradle/jdks/eclipse_adoptium-21-amd64-linux.2 ANDROID_HOME=/home/yasir/Android/Sdk ./gradlew testDebugUnitTest --tests <full class name> -q`, one `--tests` per class, no globs. Delete `app/build/test-results/testDebugUnitTest` before a run whose results are read.
- **Commits:** end every message with the two attribution lines of the session.

## Review Focus

Inputs the spec implies that are most likely to bite; each has its test in the task named.

1. A recorded domain spelled with capitals or a trailing dot: it is stored as recorded and "lookup times" finds it by that exact spelling (Task 5, `recent lookups are read by the recorded spelling`).
2. A scan that never finished (process killed) leaves detail rows behind: the next completed scan deletes them (Task 4, `detail rows of a scan that never finished are deleted by the next completed scan`).
3. The network step failed and the tracker was found in code only: the view says the domain list may be incomplete, it does not silently omit the section (Task 6, `a failed network step is stated even when no domain was recorded`).
4. The details view is open on a result that a newer scan has replaced or the person deleted: it says so, it does not crash or show an empty list (Task 6, `a result that is no longer stored says so`).
5. One tracker matched through several signatures with more than 200 packages in total: the 200 are shared across its signatures and each signature keeps its true number (Task 4, `the 200 package names of one tracker are shared across its signatures`).

---

### Task 1: Detailed matching in `TrackerSet`

**Files:**
- Modify: `app/src/main/java/com/androdr/privacy/model/TrackerSet.kt`
- Test: `app/src/test/java/com/androdr/privacy/model/TrackerSetTest.kt` (add), `app/src/test/java/com/androdr/privacy/model/TrackerSetDetailCrossCheckTest.kt` (create)

**Interfaces:**
- Produces (all in `com.androdr.privacy.model`):
  - `enum class SignatureKind { CODE_PREFIX, CODE_SEGMENT, DOMAIN_SUFFIX, DOMAIN_LABEL, DOMAIN_PATTERN }`
  - `data class CodeMatch(val tracker: Tracker, val kind: SignatureKind, val signature: String, val packages: List<String>)`
  - `data class DomainMatch(val tracker: Tracker, val kind: SignatureKind, val signature: String)`
  - `fun TrackerSet.matchPackagesDetailed(packages: Collection<String>): List<CodeMatch>` — one entry per (tracker, kind, signature) that matched; `packages` distinct and sorted; the list sorted by `tracker.id`, then `kind.ordinal`, then `signature`.
  - `fun TrackerSet.matchDomainDetailed(host: String): List<DomainMatch>` — at most one entry per tracker: its first hit in matcher order (longest matching tail first; at one tail: suffix, then label, then pattern). Empty for an empty host or one longer than `MAX_HOST_CHARS`.
  - `matchPackages` and `matchDomain` keep their signatures and results.
- Decision: a pattern's `signature` is `Regex.pattern`, the form the matcher runs. It differs from the list's text only where a hyphen inside a character class is written `\-`. `Tracker` is not changed.

- [ ] **Step 1: Write the failing tests** in `TrackerSetTest` (reuse its `tracker(...)`/`TrackerSet(...)` helpers):
  - `detailed code matching names the prefix and the packages under it` — prefix `com.a`, packages `com.a.y`, `com.a.x`, `com.ab` → exactly `CodeMatch(t, CODE_PREFIX, "com.a", listOf("com.a.x", "com.a.y"))`.
  - `detailed code matching names a package-name segment` — segment `sizmek`, packages `net.sizmek.sdk`, `net.sizmekx` → one `CODE_SEGMENT` match holding `net.sizmek.sdk`.
  - `a package under two signatures of one tracker is listed under each` — prefixes `com.a` and `com.a.b`, package `com.a.b.c` → two matches, each holding it.
  - `detailed domain matching names the suffix, the label and the pattern` — three trackers, hosts `x.doubleclick.net` (`DOMAIN_SUFFIX`, `doubleclick.net`), `alimama.example` (`DOMAIN_LABEL`, `alimama`), `mst01.is.autonavi.com` (`DOMAIN_PATTERN`, signature equal to the compiled pattern's `pattern`).
  - `a host gives one detailed match per tracker, the longest tail first` — one tracker with suffixes `b.a.com` and `a.com`, host `x.b.a.com` → one match, signature `b.a.com`.
  - `a host longer than 253 characters gives no detailed match`.
- [ ] **Step 2: Write the cross-check** `TrackerSetDetailCrossCheckTest` on the real list (load it the way `TrackerRegistryBundleCrossCheckTest` does):
  - `detailed and plain code matching name the same trackers on the real list` — corpus: for every tracker, each prefix `p` as `p` and `p.zz`, each segment `s` as `zz.s.zz`; assert `matchPackagesDetailed(corpus).map { it.tracker.id }.toSet() == matchPackages(corpus).map { it.id }.toSet()`, and that set holds every tracker that has a code signature.
  - `detailed and plain domain matching name the same trackers on the real list` — for every suffix `d`: hosts `d` and `zz.d`; every label `l`: `l.zz` and `zz.l.zz`; assert per host that the ids of `matchDomainDetailed(host)` equal the ids of `matchDomain(host)`, and are not empty.
  - `a pattern is shown as the list writes it apart from an escaped hyphen` — read every `domain_patterns` string from the YAML text with the snakeyaml-engine `Load` the registry uses; for each that compiles, `DomainGrammar.compilePattern(p)!!.pattern.replace("\\-", "-") == p.replace("\\-", "-")`.
- [ ] **Step 3: Run** `--tests com.androdr.privacy.model.TrackerSetTest --tests com.androdr.privacy.model.TrackerSetDetailCrossCheckTest`. Expected: compilation fails (`matchPackagesDetailed` unresolved).
- [ ] **Step 4: Implement.** Two private traversals in `TrackerSet`, each calling a callback per hit `(tracker, kind, signature)` (the code one also knows the package): the bodies of today's `matchPackages` and `matchDomain`, with the index maps changed to keep the signature beside its owners. `matchPackages`, `matchDomain` and the two detailed functions are built on those traversals and on nothing else.
- [ ] **Step 5: Run** the two classes plus `--tests com.androdr.privacy.NetworkEvidenceCorrelatorTest --tests com.androdr.privacy.PrivacyScanRunnerTest --tests com.androdr.privacy.PrivacyBoundaryTest --tests com.androdr.privacy.PrivacySourceStyleTest`. Expected: all pass.
- [ ] **Step 6: Commit** `feat(privacy): detailed tracker matching on the one traversal`.

### Task 2: Per-domain detail out of the correlator

**Files:**
- Modify: `app/src/main/java/com/androdr/privacy/NetworkEvidenceCorrelator.kt`, `app/src/main/java/com/androdr/privacy/CorrelationRun.kt`
- Test: `app/src/test/java/com/androdr/privacy/NetworkEvidenceCorrelatorTest.kt` (add)

**Interfaces:**
- Consumes: `TrackerSet.matchDomainDetailed`, `DomainMatch`, `SignatureKind` (Task 1).
- Produces, in `NetworkEvidenceCorrelator`:
  - `data class DomainEvidence(val key: Key, val domain: String, val kind: SignatureKind, val signature: String, val lookups: Int, val days: Int, val background: Int?, val first: Long, val last: Long)`
  - `Correlation` gains `val domains: List<DomainEvidence>` (third property; `evidence` and `truncated` unchanged).
- Rules: one `DomainEvidence` per counted (app, recorded domain) and per tracker that owns the domain. `domain` is the domain as recorded (not normalised). `background` is the per-domain background count where the run timed that domain, limited to `lookups`; null everywhere else. No new limit and no new query: the detail is the run's own `parts`, kept before they are summed.

- [ ] **Step 1: Write the failing tests** (use the file's `FakeSource.of(...)` and `correlate(...)` helper):
  - `each counted domain is reported with the signature that matched it` — two recorded domains under one suffix for one app → two `DomainEvidence` with `kind = DOMAIN_SUFFIX`, that suffix, and each domain's own lookups, days, first, last.
  - `a domain owned by two trackers is reported under each` — the file's shared-domain fixture → two entries, same domain and counts, different `key.trackerId`.
  - `the lookups of a key's domains add up to its total` — over a fixture with several apps, trackers and domains: for every key in `evidence`, the sum of its domains' `lookups` equals `evidence[key].lookups`, the smallest `first` and the largest `last` equal the total's, and the keys of `domains` are exactly `evidence.keys`.
  - `a domain is reported as recorded` — recorded `T.AppsFlyer.com.` → `domain == "T.AppsFlyer.com."`.
  - `per-domain background is a number only where it was timed` — with usage present: the timed pair's domains carry numbers; without usage: every `background` is null.
  - `a flood of junk subdomains cannot displace a real domain from the detail` — the file's ">20,000 tracker-matching subdomains" fixture: the real pair's domain is in `domains`, and `domains.size` is at most `MAX_MATCHED_PAIRS` times the number of trackers owning the flooded suffix.
- [ ] **Step 2: Run** `--tests com.androdr.privacy.NetworkEvidenceCorrelatorTest`. Expected: compilation fails (`domains` unresolved).
- [ ] **Step 3: Implement.** In `CorrelationRun`: the memo holds `List<DomainMatch>` per normalised host (from `matchDomainDetailed`) in place of ids; each key's list keeps, beside every part, the match that tied it to that tracker; `run` returns `Correlation(evidence, truncated, domains)`. The totals code path is not otherwise changed.
- [ ] **Step 4: Run** the class. Expected: all pass, the pre-existing tests unchanged.
- [ ] **Step 5: Commit** `feat(privacy): the correlator reports each counted domain`.

### Task 3: Detail tables, DAO and migration 22 → 23

**Files:**
- Modify: `app/src/main/java/com/androdr/data/model/PrivacyEntities.kt`, `app/src/main/java/com/androdr/data/db/PrivacyDao.kt`, `app/src/main/java/com/androdr/data/db/AppDatabase.kt`, `app/src/main/java/com/androdr/data/db/Migrations.kt`, `app/src/main/java/com/androdr/di/AppModule.kt`, every test that passes `MIGRATION_21_22` to `.addMigrations(` for a database opened at the current version
- Create: `app/schemas/com.androdr.data.db.AppDatabase/23.json` (generated by the build), `app/src/test/java/com/androdr/data/db/Migration22To23Test.kt`, `app/src/test/java/com/androdr/data/db/PrivacyDetailDaoTest.kt`

**Interfaces:**
- Produces:
  - `@Entity(tableName = "privacy_code_detail", primaryKeys = ["scanId", "packageName", "trackerId", "kind", "signature"]) data class PrivacyCodeDetail(val scanId: Long, val packageName: String, val trackerId: Int, val kind: String, val signature: String, val packageCount: Int, val packages: String)` — `packageCount` is the true number; `packages` the stored names joined by `"\n"`.
  - `@Entity(tableName = "privacy_domain_detail", primaryKeys = ["scanId", "packageName", "trackerId", "domain"]) data class PrivacyDomainDetail(val scanId: Long, val packageName: String, val trackerId: Int, val domain: String, val kind: String, val signature: String, val lookups: Int, val lookupDays: Int, val background: Int?, val firstSeen: Long, val lastSeen: Long)`
  - `PrivacyScan` gains a last property `@ColumnInfo(defaultValue = "0") val hasDetails: Boolean = false`.
  - `PrivacyDao`: `suspend fun upsertCodeDetail(rows: List<PrivacyCodeDetail>)`, `suspend fun upsertDomainDetail(rows: List<PrivacyDomainDetail>)` (both `REPLACE`); `suspend fun codeDetail(scanId: Long, packageName: String, trackerId: Int): List<PrivacyCodeDetail>` (ordered by `kind`, `signature`); `suspend fun domainDetail(scanId: Long, packageName: String, trackerId: Int): List<PrivacyDomainDetail>` (ordered by `lookups DESC`, `domain`); `suspend fun resultFor(scanId: Long, packageName: String): PrivacyAppResult?`; `suspend fun evidenceFor(scanId: Long, packageName: String, trackerId: Int): PrivacyTrackerEvidence?`. `deleteScansBefore` and `deleteAll` also delete from both new tables.
  - `val MIGRATION_22_23`, `AppDatabase` `version = 23`.

- [ ] **Step 1: Write the failing DAO tests** `PrivacyDetailDaoTest` (Robolectric, `RoomTestDb.inMemory()`):
  - `detail is read for one app and tracker only` — rows for two apps and two trackers; `codeDetail` and `domainDetail` return only the asked pair's rows; domains come most lookups first.
  - `deleting scans before an id deletes their detail` — detail under scans 1 and 2; `deleteScansBefore(2)` leaves only scan 2's rows in both tables.
  - `deleting everything deletes the detail` — after `deleteAll()` both tables are empty.
  - `a scan row keeps whether details were recorded` — insert with `hasDetails = true`, read back true; default false.
- [ ] **Step 2: Write the failing migration test** `Migration22To23Test`, shaped like `Migration21To22Test`: create at 22, insert one `privacy_scan`, one `privacy_app_result` and one `privacy_tracker_evidence` row by SQL, `runMigrationsAndValidate(name, 23, true, MIGRATION_22_23)`; assert the seeded rows survive, the scan's `hasDetails` is 0, and `privacy_code_detail` and `privacy_domain_detail` exist and are empty.
- [ ] **Step 3: Run** `--tests com.androdr.data.db.PrivacyDetailDaoTest --tests com.androdr.data.db.Migration22To23Test`. Expected: compilation fails.
- [ ] **Step 4: Implement** entities, DAO, version 23, registration in `AppModule`; build once so KSP writes `23.json`; write `MIGRATION_22_23` as `ALTER TABLE privacy_scan ADD COLUMN hasDetails INTEGER NOT NULL DEFAULT 0` plus the two `CREATE TABLE` statements copied verbatim from `23.json`.
- [ ] **Step 5: Run** the two classes plus `--tests com.androdr.data.db.Migration21To22Test --tests com.androdr.data.db.Migration20To21Test --tests com.androdr.privacy.PrivacyBoundaryTest --tests com.androdr.privacy.PrivacyScanRunnerTest`, then `python3 -m pytest scripts/ test-adversary/ -q`. Expected: all pass. A Python test pinned to the schema that fails is fixed here, in this commit.
- [ ] **Step 6: Commit** `feat(privacy): detail tables and migration 22 to 23` (includes `23.json`).

### Task 4: The scan records the detail

**Files:**
- Create: `app/src/main/java/com/androdr/privacy/PrivacyDetailRows.kt`, `app/src/test/java/com/androdr/privacy/PrivacyDetailRowsTest.kt`
- Modify: `app/src/main/java/com/androdr/privacy/PrivacyScanRunner.kt`
- Test: `app/src/test/java/com/androdr/privacy/PrivacyScanRunnerTest.kt` (add)

**Interfaces:**
- Consumes: `CodeMatch`, `matchPackagesDetailed` (Task 1); `DomainEvidence`, `Correlation.domains` (Task 2); entities and DAO functions (Task 3).
- Produces, `internal object PrivacyDetailRows` in `com.androdr.privacy`:
  - `const val MAX_PACKAGES_PER_TRACKER = 200`, `const val MAX_PACKAGES_PER_APP = 2_000`, `const val MAX_TEXT_CHARS = 254` (the longest host the matcher accepts, 253, plus the trailing dot the normaliser removes), `const val CUT_MARK = "…"`
  - `fun cut(text: String): String` — more than `MAX_TEXT_CHARS` code points → the first `MAX_TEXT_CHARS` followed by `CUT_MARK`; otherwise unchanged.
  - `fun code(scanId: Long, packageName: String, matches: List<CodeMatch>): List<PrivacyCodeDetail>` — one row per match, in the given order; `packageCount = match.packages.size`; names are stored (each through `cut`) until the tracker's 200 or the app's 2,000 are used up, signatures of one tracker sharing its 200 in order.
  - `fun domains(scanId: Long, domains: List<DomainEvidence>): List<PrivacyDomainDetail>` — one row each, `domain` through `cut`.
  - `fun packagesOf(row: PrivacyCodeDetail): List<String>`
- Runner: the tracker set of an app is the trackers of its `matchPackagesDetailed` result (one matching call per app, inside the existing per-app `try`, where the code rows are also built); code rows are written with the app's result row; domain rows after the correlation, before `finishScan`; a failed network step writes none; `insertScan` passes `hasDetails = true`.

- [ ] **Step 1: Write the failing pure tests** `PrivacyDetailRowsTest`:
  - `more than 200 matching packages are stored as 200 with the true number` — one match with 260 packages → `packageCount == 260`, `packagesOf(row).size == 200`.
  - `the 200 package names of one tracker are shared across its signatures` — tracker with two matches of 150 packages each → 150 and 50 stored, both `packageCount == 150`.
  - `one app stores at most 2000 package names across trackers` — 15 trackers × 200 → 2,000 stored in total, every `packageCount == 200`.
  - `a name longer than 254 characters is stored cut with a visible mark` — 400-character package → stored text is 254 characters + `…`; a 254-character one is unchanged.
  - `domain rows keep unknown background as null` — `DomainEvidence(background = null)` → row `background == null`.
- [ ] **Step 2: Write the failing runner tests** (the file's `FakeInspector`, `runner(...)`, `awaitIdle()`):
  - `a scan records the matching packages of each tracker found in code` — app with `com.flurry.sdk`, `com.flurry.android` → `codeDetail(scanId, app, FLURRY)` has one `CODE_PREFIX` row, `com.flurry`, both packages.
  - `a scan records each looked-up tracker domain` — DNS source with two `flurry.com` subdomains → two `domainDetail` rows with the correlator's counts.
  - `a scan marks that details were recorded` — `latestCompletedOnce()!!.hasDetails`.
  - `an app that could not be inspected has no code detail`.
  - `a failed network step leaves no domain detail`.
  - `details of the previous scan are deleted when a newer scan completes` — two scans; no detail row with the first scan's id remains.
  - `detail rows of a scan that never finished are deleted by the next completed scan` — insert a `privacy_scan` row with `finishedAt = null` and detail rows under it by DAO, run a scan → those rows are gone.
  - `Delete privacy results deletes the details` — `runner.deleteAll()` → both tables empty.
  - `the trackers found in code are the same with detail recorded` — the evidence rows of a mixed fixture equal the ones today's assertion in the file expects (existing tests staying green is the main guard; this one names it).
- [ ] **Step 3: Run** `--tests com.androdr.privacy.PrivacyDetailRowsTest --tests com.androdr.privacy.PrivacyScanRunnerTest`. Expected: compilation fails (`PrivacyDetailRows` unresolved).
- [ ] **Step 4: Implement** `PrivacyDetailRows` and the runner changes.
- [ ] **Step 5: Run** the two classes plus `--tests com.androdr.privacy.PrivacySourceStyleTest --tests com.androdr.privacy.PrivacyBoundaryTest`. Expected: all pass.
- [ ] **Step 6: Commit** `feat(privacy): the scan records matching packages and looked-up domains`.

### Task 5: Reading one app + tracker's detail, and the live lookup times

**Files:**
- Create: `app/src/main/java/com/androdr/privacy/PrivacyEvidenceReader.kt`, `app/src/test/java/com/androdr/privacy/PrivacyEvidenceReaderTest.kt`
- Modify: `app/src/main/java/com/androdr/data/db/DnsEventDao.kt`

**Interfaces:**
- Consumes: Task 3's DAO functions, `PrivacyDetailRows.packagesOf` (Task 4).
- Produces:
  - `DnsEventDao.recentLookupTimes(app: String, domain: String, limit: Int): List<Long>` — `SELECT timestamp FROM DnsEvent WHERE appName = :app AND domain = :domain ORDER BY timestamp DESC LIMIT :limit` (served by `index_DnsEvent_appName_domain_timestamp`).
  - `data class CodeSignature(val kind: SignatureKind, val signature: String, val packages: List<String>, val total: Int)`
  - `data class DomainLine(val domain: String, val kind: SignatureKind, val signature: String, val lookups: Int, val days: Int, val background: Int?, val first: Long, val last: Long)`
  - `data class EvidenceDetails(val scan: PrivacyScan, val app: PrivacyAppResult, val evidence: PrivacyTrackerEvidence, val code: List<CodeSignature>, val domains: List<DomainLine>)`
  - `class PrivacyEvidenceReader @Inject constructor(private val dao: PrivacyDao, private val dns: DnsEventDao)` with `suspend fun load(packageName: String, trackerId: Int): EvidenceDetails?` (null when there is no completed scan, or it holds no evidence row for that app + tracker; a detail row whose `kind` is not a `SignatureKind` name is left out) and `suspend fun recentLookups(packageName: String, domain: String): List<Long>` (newest first, at most `MAX_RECENT_LOOKUPS = 50`).

- [ ] **Step 1: Write the failing tests** `PrivacyEvidenceReaderTest` (Robolectric, in-memory database, real DAOs):
  - `details are loaded for the latest completed scan` — seeded scan, result, evidence, one code row, two domain rows → all present, domains most lookups first, packages split into a list, `total` the true number.
  - `nothing is loaded when the app and tracker are not in the latest scan` → null.
  - `a result from before details were recorded loads with no detail` — scan `hasDetails = false` → not null, `code` and `domains` empty, `scan.hasDetails` false.
  - `recent lookups are the newest 50, newest first` — 60 events → 50 timestamps, descending, the newest first.
  - `recent lookups are read by the recorded spelling` — events for `T.AppsFlyer.com.` and for `t.appsflyer.com` under one app → asking for the first returns only its own timestamps.
  - `recent lookups of another app are not returned`.
- [ ] **Step 2: Run** `--tests com.androdr.privacy.PrivacyEvidenceReaderTest`. Expected: compilation fails.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** the class plus `--tests com.androdr.privacy.PrivacyBoundaryTest --tests com.androdr.privacy.PrivacySourceStyleTest`. Expected: all pass.
- [ ] **Step 5: Commit** `feat(privacy): read one finding's detail and its recent lookups`.

### Task 6: The details view

**Files:**
- Create: `app/src/main/java/com/androdr/ui/privacy/PrivacyEvidenceViewModel.kt`, `PrivacyEvidenceScreen.kt`, `PrivacyEvidenceDetailText.kt` (same directory); tests `app/src/test/java/com/androdr/ui/privacy/PrivacyEvidenceViewModelTest.kt`, `PrivacyEvidenceScreenTest.kt`, `PrivacyEvidenceDetailTextTest.kt`, `PrivacyEvidenceTapTest.kt`
- Modify: `app/src/main/java/com/androdr/ui/privacy/PrivacyDetails.kt`, `PrivacyScreen.kt`, `app/src/main/java/com/androdr/MainActivity.kt`, `app/src/main/res/values/strings.xml`, `app/src/test/java/com/androdr/ui/privacy/PrivacyCopyTest.kt`

**Interfaces:**
- Consumes: `PrivacyEvidenceReader`, `EvidenceDetails`, `CodeSignature`, `DomainLine` (Task 5).
- Produces:
  - `const val PRIVACY_EVIDENCE_ROUTE = "privacy/evidence/{packageName}/{trackerId}"`, `fun privacyEvidenceRoute(packageName: String, trackerId: Int): String` (package name through `Uri.encode`).
  - `sealed interface EvidenceUiState { data object Loading; data object Gone; data class Loaded(val details: EvidenceDetails) }`, `data class LookupTimes(val domain: String, val times: List<Long>)`
  - `@HiltViewModel class PrivacyEvidenceViewModel @Inject constructor(reader: PrivacyEvidenceReader, handle: SavedStateHandle)` with `val state: StateFlow<EvidenceUiState>`, `val lookups: StateFlow<LookupTimes?>`, `fun openLookups(domain: String)`, `fun closeLookups()`. It loads once, when created.
  - `@Composable fun PrivacyEvidenceScreen(onBack: () -> Unit, viewModel: PrivacyEvidenceViewModel = hiltViewModel())` and the stateless `@Composable internal fun EvidenceContent(state: EvidenceUiState, lookups: LookupTimes?, onOpenLookups: (String) -> Unit, onCloseLookups: () -> Unit, onBack: () -> Unit)`.
  - `PrivacyScreen` gains `onOpenEvidence: (packageName: String, trackerId: Int) -> Unit`; `AppDetailSheet` and `TrackerCard` gain the same callback; `TrackerDetail` becomes `internal`.
- Layout decisions (spec 12 leaves these to the builder): a full screen on its own route, so Back returns to the privacy screen with the app's sheet still open (its state is saved). Dates are absolute (medium date, short time). The note beside the domains is the existing `privacy_network_caveat` string; unknown background is the existing `privacy_background_unknown`. The Exodus link is `https://reports.exodus-privacy.eu.org/en/trackers/<id>/`, built from the integer id, shown for ids above zero.
- What the screen shows, top to bottom:
  1. Tracker name, website and categories as the lists show them; "in *app name* (*package*)"; "Tracker list entry *id* (Exodus Privacy)" as a link; the totals line the lists show (`line(row, res, now)`).
  2. When `scan.hasDetails` is false: the line "Run a new privacy scan to record the matching packages and domains." and nothing of 3–4.
  3. "Found in code", only when the evidence row says in code: "Version inspected: *versionCode* · fully inspected / partly inspected"; when partly, "Only part of this app's code could be read, so this list may be incomplete."; per signature "Signature *text* (package prefix / package-name segment)", its stored packages, and "… and *N* more" when `total` exceeds the stored number.
  4. "Looked up domains of this tracker", when there is a domain row or the scan's network step was cut short or failed: "Recorded *window start* – *scan date*", the coverage line the privacy screen uses, the note; when cut short or failed, the existing notice plus "so this list may be incomplete"; per domain: the domain as recorded, "matched *signature* (domain suffix / label / pattern)", lookups, days, background or unknown, first, last; tapping a domain opens its lookup times.
  5. Lookup times (a dialog): the domain, "The most recent lookups of this domain by this app, read from the DNS log as it is now. They can differ from the scan's counts.", up to 50 date-times, or "The DNS log holds no lookups of this domain by this app now."
  6. Footer: "Privacy scan of *date time* · tracker list: *N* trackers (*a41c…9e*)" — the first four and last two characters of the list's hash; the bracket is left out when the hash is blank.
  7. `Gone`: "This result is no longer stored. Run a new privacy scan."
- Every package name, domain and signature goes to the screen through `displaySafe(text, 255)`; app name and tracker name through the existing `appName(...)`/`trackerName(...)`.
- `privacy_delete_confirm` becomes "Delete the stored list of every app's code packages, tracker findings and looked-up tracker domains?"

- [ ] **Step 1: Write the failing wording tests** `PrivacyEvidenceDetailTextTest` (Robolectric, real resources): kind labels for the five kinds; `shortHash("a41c" + "0".repeat(58) + "9e") == "a41c…9e"` and blank → null; "… and 9 more"; a domain line with `background = null` contains "background use unknown" and no "0 in background"; a 300-character package with a right-to-left override in it is shown without the override.
- [ ] **Step 2: Write the failing screen tests** `PrivacyEvidenceScreenTest` (Robolectric Compose, `EvidenceContent`, set up like `TelemetryBrowserScreensTest`):
  - `a finding with details shows the signature, its packages and its domains`
  - `packages beyond the stored ones are counted, not hidden`
  - `a result from before details were recorded says to run a new scan` — the line is shown; "Found in code" and "Looked up domains of this tracker" are not.
  - `a partly inspected app says the list may be incomplete`
  - `a failed network step is stated even when no domain was recorded`
  - `a result that is no longer stored says so`
  - `tapping a domain asks for its lookup times by the recorded spelling`
  - `lookup times are labelled as read from the DNS log now`
- [ ] **Step 3: Write the failing tap and view-model tests.** `PrivacyEvidenceTapTest`: tapping an app line of `TrackerCard` and tapping `TrackerDetail` each call the callback with that package name and tracker id. `PrivacyEvidenceViewModelTest` (MockK reader): loads the route's app + tracker when created; a null load is `Gone`; `openLookups` publishes the reader's times for that domain and `closeLookups` clears them.
- [ ] **Step 4: Extend `PrivacyCopyTest`:** `PrivacyEvidenceScreen.kt` references `privacy_network_caveat`; the "run a new scan" string has exactly the spec's text.
- [ ] **Step 5: Run** the four new classes and `--tests com.androdr.ui.privacy.PrivacyCopyTest`. Expected: compilation fails.
- [ ] **Step 6: Implement** strings, wording functions, view model, screen, tap targets, the route in `MainActivity` (`composable(PRIVACY_EVIDENCE_ROUTE, arguments = …)` with `trackerId` as an int), and the callback from the `privacy` destination.
- [ ] **Step 7: Run** the five classes plus `--tests com.androdr.ui.privacy.PrivacyViewModelTest --tests com.androdr.ui.privacy.PrivacyEvidenceTextTest --tests com.androdr.privacy.PrivacyBoundaryTest --tests com.androdr.privacy.PrivacySourceStyleTest`. Expected: all pass.
- [ ] **Step 8: Commit** `feat(privacy): tap a finding to see what was matched`.

### Task 7: Privacy policy, its render and its check

**Files:**
- Modify: `docs/PRIVACY_POLICY.md`, `cloudflare-worker.js` (by the renderer only), `scripts/render_privacy.py` (`EXPECTED_H2` 19 → 20), `.github/workflows/ci.yml` (the `python` path filter gains `docs/PRIVACY_POLICY.md`, with a comment naming the check; the `python-pipeline` job gains a step `python3 -m pytest scripts/test_privacy_policy_text.py -q` — that job runs test files by name, and only `ci-success` is a required check, so `check-privacy-sync.yml` cannot carry it)
- Create: `scripts/test_privacy_policy_text.py`

**Interfaces:**
- Produces: `scripts/test_privacy_policy_text.py` with `bare_thirty_day_lines(text: str) -> list[str]` — every line that mentions "30 days" and neither names the privacy scan (case-insensitive "privacy scan") nor contains one of `UNRELATED_30_DAY_MARKERS = ("| Forensic timeline events", "from the import")`.
- Policy text to write (wording is the builder's; these facts are fixed by spec 8):
  - `_Last updated: 2026-11-11_`.
  - "What AndroDR Does": a bullet for the privacy scan.
  - Data table: a row for privacy scan results — per app, the trackers found, the matching code packages, and the tracker domains the app looked up with counts and times; shown on the privacy screen; on the device only.
  - `PACKAGE_USAGE_STATS` row: usage access also lets a privacy scan tell whether a lookup happened while the app was in the background; the 30-day sentence gets the exception.
  - Network table, "Centralized IOC data" row: names the tracker list and the manifest and states the true number of requests (count the `ioc-data/` paths the app fetches before writing the number).
  - New section `## Privacy Scan` after "DNS Monitoring": what is stored; kept until the next privacy scan replaces it or the person chooses "Delete privacy results"; not covered by the 30-day deletion; never part of an exported report; never leaves the device; the DNS log itself is still deleted after 30 days.
  - "DNS Monitoring" bullet, "Data Retention and Deletion" bullet, both Play data-safety lines ("Data collected", "Data deletion"): the 30-day statement with the privacy-scan exception on the same line.
  - "What Exported Reports Contain": reports never contain privacy scan results.
  - "Since AndroDR collects no data, …" stays.

- [ ] **Step 1: Write the failing check** `scripts/test_privacy_policy_text.py`:
  - `test_the_policy_says_how_long_privacy_scan_results_are_kept` — the text between `## Privacy Scan` and the next `## ` contains, case-insensitively, "until the next privacy scan replaces", "Delete privacy results", "30 days", "exported report" and "never leave".
  - `test_every_30_day_statement_names_the_privacy_scan_exception` — `bare_thirty_day_lines(policy) == []`.
  - `test_a_bare_30_day_line_is_noticed` — `bare_thirty_day_lines("- DNS logs are deleted after 30 days\n")` has one line; the same line with "(a privacy scan's results are kept separately)" has none.
  - `test_the_play_summary_states_the_exception_twice` — within `## Google Play Data Safety Alignment`, both the "Data collected" and the "Data deletion" line contain "privacy scan".
- [ ] **Step 2: Run** `python3 -m pytest scripts/test_privacy_policy_text.py -q`. Expected: 3 failed, 1 passed (`test_a_bare_30_day_line_is_noticed` passes).
- [ ] **Step 3: Edit the policy**, set `EXPECTED_H2 = 20`, run `python3 scripts/render_privacy.py docs/PRIVACY_POLICY.md cloudflare-worker.js`, add the path to the CI filter and the test step to `python-pipeline`.
- [ ] **Step 4: Run** `python3 -m pytest scripts/ -q`. Expected: all pass. Then repeat the sync workflow's check by hand: copy `cloudflare-worker.js` to the scratchpad, render into the copy, `diff -q` → no difference.
- [ ] **Step 5: Commit** `docs(privacy): the policy says what a privacy scan stores and for how long`.

### Task 8: Architecture document and the full local gates

**Files:**
- Modify: `docs/ARCHITECTURE.md` (Chapter 12: schema 23 and the two detail tables in 12.3; a new 12.4 "Evidence details" — recorded at scan time, one traversal, totals authoritative, caps, read on open through `PrivacyEvidenceReader`, live lookup times, old results; the package-layering block gains the reader)

- [ ] **Step 1: Edit** the chapter; no other chapter changes.
- [ ] **Step 2: Run the full gates**, each to a file in the plan workspace, reading the tail: `rm -rf app/build/test-results/testDebugUnitTest` then `./gradlew testDebugUnitTest`; `./gradlew detekt`; `./gradlew lintDebug`; `python3 -m pytest scripts/ test-adversary/ -q`. Expected: all green; the new test classes appear in the results directory.
- [ ] **Step 3: Check on an emulator:** `./gradlew installDebug` on `Medium_Phone_API_36.1`, run a privacy scan, open an app's sheet, tap a tracker, confirm the details screen and Back; `adb logcat` shows no crash. If no emulator can be started, say so in the ledger and the final message.
- [ ] **Step 4: Commit** `docs(architecture): privacy evidence details`.
