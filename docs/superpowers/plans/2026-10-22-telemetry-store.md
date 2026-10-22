# Telemetry Store, Uncapped Timeline, Finding Lifecycle Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Persist every telemetry record a scan or import produces as facts observed by scans, remove every persistence cap, read the Timeline as a paged union with no duplicated event rows, give findings an alert lifecycle that outlives scans, and make the telemetry vocabulary precise and gated.

**Architecture:** Each emitter's output becomes a one-shot `ServiceRecords` sequence of field maps. A chunked single-pass writer handles 5,000 records per transaction: it persists them as content (`record_body`), facts (`telemetry_record`) and observations (`scan_record`), evaluates the same maps, and writes findings. The scan stays `IN_PROGRESS` and invisible until a final transaction runs correlation and commits it. Findings are per scan (`scan_finding`); incidents are `alert` rows that outlive scans. The Timeline is a keyset-paged union of event facts and `forensic_timeline` rows. Reports stream from one `ReportExporter` path.

**Tech Stack:** Kotlin 2.0, Room 2.6.1 (+ `room-paging` 2.6.1 for `InvalidationTracker` integration, `room-testing` on the unit-test classpath), AndroidX Paging 3.3.6 (+ `paging-compose`), Jetpack Compose, Hilt, kotlinx.serialization, `java.util.zip`, platform `BiometricPrompt`/`KeyguardManager`, Robolectric 4.14.1 (SDK 35) + `androidx.test:core` 1.6.1, snakeyaml-engine 2.7 (present).

**Spec:** `docs/superpowers/specs/2026-10-22-telemetry-store-design.md` (revised after plan-gate rounds 1–2; findings `docs/superpowers/plans/2026-10-22-telemetry-store-plan-gate-round{1,2}-findings.md`)

## Global Constraints

- JDK 21. Gates: `./gradlew testDebugUnitTest`, `./gradlew detekt`, `./gradlew lintDebug`; CI runs `assembleDebug test` and `lintDebug detekt`. Every gate is a JVM unit test.
- Every fix lands with a test that fails on the original mistake. Every commit compiles and passes the full unit suite.
- New dependencies pinned exactly; `gradle/verification-metadata.xml` regenerated and its diff reviewed in the same commit (confirm the resolved `androidx.paging` version is 3.3.6). No new native library, no SQLite build, no `androidx.biometric`.
- No `_PERSIST_CAP`, `_ROW_LIMIT`, literal `LIMIT <n>` or `limit: Int = <n>` default in any DAO outside the C1 allow-list (spec §5.5). No OFFSET paging.
- Event facts are never copied into `forensic_timeline`. No bound silently drops evidence. No full-import `List` is built anywhere (records, findings, ordinal maps, atoms outside bound categories, report text).
- `ReportFormatter` is called only from `ReportExporter`. Writers evaluate only through `evaluateRecords` on the chunk they persist.
- SQL (DAO, migration, timeline builders) uses only API 26 SQLite features; list parameters go through `chunkedIn(≤ 900)`.
- No source-named types or fields; taxonomy names `snake_case`. Shipped dictionaries are immutable.
- Taxonomy edits follow CLAUDE.md safe ordering.
- Phases 0, A, B, C, D, E are each one PR to `main` that leaves the app working. Branches `feat/telemetry-store-<phase>`.
- detekt: classes/objects ≤ 15 functions, interfaces ≤ 11, files ≤ 11 top-level functions, `LongParameterList` 13, `LongMethod` 60. New providers in `di/StoreModule.kt`.

## Review Focus

1. Envelope keys holding content (`"source" to "bugreport_import"` / `"adb_trusted_key"`) must survive storage unchanged; keys equal to the observation must restore exactly. Pinned in Task A5 (S1).
2. Usage access revoked between scans: collection fails and the watermark is unchanged. Access present with no events: the watermark advances to the scan's start. Pinned in Task C1.
3. A rules update ships a `dns_monitor` rule this binary can't evaluate. The watermark still advances and observation count stays linear over 10 scans. Pinned in Task C1.
4. A `ScanResult.findings` value over 2 MB, or corrupt, during migration 19→20: the migration completes and the scan survives. Pinned in Task D2.
5. The app is killed mid-import: nothing of the import is visible after restart, and the startup sweep removes its rows. Pinned in Task A7.

---

## Phase 0 — Taxonomy first (rules PR + AndroDR PR 0)

### Task 0.1: Rules-repo taxonomy change (safe ordering steps 1–2)

**Files (rules repo, branch `feat/taxonomy-emitter-services`):**
- Modify: `validation/logsource-taxonomy.yml` per spec §4.2 exactly, covering:
  - `emitter_only` services `usage_stats` (fields `timestamp, package_name, app_name, event_type, source, captured_at`) and `system_property` (`key, value, source, captured_at`);
  - `adb_audit` and `activity_audit` documented from the modules' current record keys;
  - `event_time_field` on the nine listed services, not on `db_info`;
  - `battery_daily.time_precision_field: timestamp_precision`;
  - `key_fields`;
  - `package_field`;
  - new fields with `positive_only` / `optional` as listed;
  - `db_info.db_path` and `db_info.recent_query_count`.
- Modify: `validation/validate-rule.py` — accept the new keys; generalise the negation guard (~line 517) from `requested_permissions` to every field flagged `positive_only` or `optional`; the existing non-active-service rejection (~line 492) covers `emitter_only`.

- [ ] **Step 1:** Edit; run the validator locally; push; open the rules PR; wait for green `validate`; do not merge.
- [ ] **Step 2:** Point the AndroDR submodule at the branch commit; commit `build: bump android-sigma-rules to taxonomy emitter-services branch`.

### Task 0.2: Kotlin contract, field maps, cross-checks

**Files:**
- Modify:
  - `data/model/DnsEvent.kt:24`: add `"timestamp"`.
  - `data/model/ImportedDnsEvent.kt`: add `toFieldMap()` = `event.toFieldMap() + ("resolved_ips" to resolvedIps)`.
  - `data/model/FileArtifactTelemetry.kt:11-16`: add `"accessible"`.
  - `data/model/SystemPropertySnapshot.kt`: add `toFieldMap()`.
  - `scanner/IntrusionLogAnalyzer.kt`: evaluate imported DNS through `ImportedDnsEvent.toFieldMap()`.
- Create: `data/model/UsageEvent.kt`, `sigma/TaxonomyContract.kt`, `sigma/TimelineCategories.kt`
- Modify tests:
  - `LogsourceTaxonomyCrossCheckTest.kt`: new services; `optional` honoured; reuse `TestRuleRepo.loadTaxonomy`.
  - `ServiceActivationCrossCheckTest.kt`: accept `emitter_only` and assert those services have no evaluate path.
- Test: `sigma/TaxonomyContractTest.kt`, `sigma/TimelineCategoriesAtomTest.kt` (K1, first half), `data/model/FieldMapCompletenessTest.kt` (E2), `scanner/DnsFindingTimestampTest.kt` (D1)

**Interfaces:**
```kotlin
data class UsageEvent(val timestamp: Long, val packageName: String, val appName: String,
    val eventType: String, val source: TelemetrySource, val capturedAt: Long) { fun toFieldMap(): Map<String, Any?> }
object TaxonomyContract {
    fun eventTimeField(service: String): String?
    fun precisionField(service: String): String?
    fun keyFields(service: String): List<String>
    fun packageField(service: String): String?
    fun fieldOrder(service: String): List<String>
    fun description(service: String, field: String): String?
    fun eventTimeOf(service: String, fields: Map<String, Any?>): Long?          // present and > 0, else null
    fun precisionOf(service: String, fields: Map<String, Any?>): TimePrecision  // EXACT unless the precision field says "day"
    val contractHash: String                                                    // hash of the inputs to computed columns (X1)
}
enum class TimePrecision { EXACT, DAY }
object TimelineCategories { fun categoryOf(service: String, fields: Map<String, Any?>): String }  // values per spec §4.3
```
`TaxonomyContract` is a hand-written Kotlin table; `TaxonomyContractTest` is its only cross-check, against the taxonomy, in both directions.

- [ ] **Step 1: Write the failing tests**
  - `TaxonomyContractTest`: every accessor equals the taxonomy entry in both directions. Live `AppOpsTelemetry` map → `eventTimeOf` null. Bug-report app-ops map with `event_time_ms > 0` → event. `db_info` has no event-time field. `contractHash` equals a pinned constant, and the failure message says "add a recompute migration".
  - K1 (part 1): every `selection.category` in `res/raw/sigma_androdr_atom_*.yml` is produced by `TimelineCategories` or is a `forensic_timeline` row category (`ioc_match`, `device_admin_grant`, `package_install`).
  - E2: constructor properties (snake-cased) ⊆ field-map keys ∪ a commented `ALLOWED_OMISSIONS`. `accessible` and `resolved_ips` present.
  - D1: an imported DNS finding's timeline row carries the record's `timestamp`, today, through the existing `buildIntrusionLogTimelineEvents` path.
- [ ] **Step 2: Run to verify they fail.**
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run to verify they pass**; the taxonomy cross-checks are green on the bumped submodule.
- [ ] **Step 5: Commit** — `feat(sigma): taxonomy contract, complete field maps, imported DNS time`
- [ ] **Step 6 (safe ordering 3–5):**
  1. Push and confirm `build-and-test` is green.
  2. Merge the rules PR.
  3. Re-point the submodule at rules `main`; commit `build: bump android-sigma-rules submodule`.
  4. Open PR `feat/telemetry-store-0`; wait for `ci-success`; merge.

---

## Phase A — Store and chunked writers (PR 1)

After Phase A every scan and import writes facts and observations through the chunked writer. Findings still go to `ScanResult.findings` with today's cap behaviour until Phase D, so there is no regression. Retention runs.

### Task A1: JVM Room harness and SQL gates

**Files:**
- Modify: `gradle/libs.versions.toml`:
  - versions `robolectric = "4.14.1"`, `androidxTestCore = "1.6.1"`, `paging = "3.3.6"`;
  - libraries `robolectric`, `androidx-test-core`, `androidx-room-paging`, `androidx-paging-runtime`, `androidx-paging-compose`, and the Robolectric `android-all-instrumented` jar for SDK 35 (the exact coordinates Robolectric 4.14.1 requests).
- Modify: `app/build.gradle.kts`:
  - `testImplementation(libs.robolectric, libs.androidx.test.core, libs.androidx.room.testing)`;
  - `testRuntimeOnly(<android-all jar>)`;
  - `implementation(libs.androidx.room.paging, libs.androidx.paging.runtime, libs.androidx.paging.compose)`;
  - `getByName("test") { assets.srcDirs("schemas") }`;
  - `testOptions.unitTests.isIncludeAndroidResources = true`;
  - a `Test` task property `robolectric.dependency.dir` pointing at a directory where a small Gradle `Copy` task places the resolved jar.
- Create: `app/src/test/resources/robolectric.properties` (`sdk=35`, `offline=true`), `app/src/test/java/com/androdr/data/db/RoomTestDb.kt`, `app/src/main/java/com/androdr/data/db/ChunkedIn.kt`
- Test: `data/db/RoomJvmHarnessTest.kt`, `data/db/SqlCompatibilityGateTest.kt` (Q1), `data/db/ChunkedInTest.kt`

**Interfaces:**
- `object RoomTestDb { fun inMemory(): AppDatabase; fun migrationHelper(): MigrationTestHelper }`. The in-memory builder sets direct query and transaction executors.
- `suspend fun <K, R> chunkedIn(keys: Collection<K>, size: Int = 900, query: suspend (List<K>) -> List<R>): List<R>`.

- [ ] **Step 1: Write the failing tests**
  - Harness:
    - An in-memory DB round-trips a `ScanResult`.
    - `MigrationTestHelper` opens version 18 from the exported schema. If Robolectric cannot see the test assets, the test fails with the asset path. The fallback is a `copySchemas` task into `src/test/resources/`.
  - Q1:
    - Scan string literals in `data/db/*.kt` (DAOs, `Migrations.kt`, `TimelineQueries.kt` once it exists) for `ON CONFLICT`, `RETURNING`, `OVER (`, `NULLS LAST`, `NULLS FIRST`, `DROP COLUMN`, `RENAME COLUMN`, `IIF(`, `->>`, `FILTER (`.
    - Every DAO function with a `List`/`Collection` parameter is called only through `chunkedIn` (source scan of call sites).
  - `chunkedIn` over 5,000 keys issues ≤ 900 keys per call.
- [ ] **Step 2–4: fail → implement → pass.**
- [ ] **Step 5: Commit** — `test: JVM Room harness; SQLite compatibility and parameter-limit gates`

### Task A2: `ServiceRecords` and `evaluateRecords`

**Files:**
- Create: `sigma/ServiceRecords.kt`, `sigma/RecordBuilders.kt`. One `object RecordBuilders` per family, split so no file exceeds 11 functions: `LiveRecordBuilders`, `BugReportRecordBuilders`, `IntrusionLogRecordBuilders`.
- Modify:
  - `sigma/SigmaRuleEvaluator.kt:23-45,135-215`: `Finding.service`, `Finding.ordinal`; `evaluate` takes `firstOrdinal: Int` and `include: (Int) -> Boolean`.
  - `sigma/SigmaRuleEngine.kt:249-358`: `evaluateRecords`. Typed `evaluate*` build a batch through `RecordBuilders` and delegate. `evaluateFiles` includes only records with `accessible == true`, keeping the stored ordinal.
  - `ServiceActivationCrossCheckTest.kt`: derive WIRED/CALLED from `RecordBuilders` service literals and `evaluateRecords` call sites; keep the vacuity guard.
- Test: `sigma/EvaluateRecordsTest.kt` (E1, engine half), `sigma/OneShotSequenceTest.kt` (S7)

**Interfaces:**
```kotlin
data class StoreRecord(val fields: Map<String, Any?>, val sourceEventKey: String? = null)
class ServiceRecords(val service: String, val source: TelemetrySource, val capturedAt: Long, records: Sequence<StoreRecord>) {
    val records: Sequence<StoreRecord> = records.constrainOnce() }
fun SigmaRuleEngine.evaluateRecords(service: String, chunk: List<StoreRecord>, firstOrdinal: Int): List<Finding>
```

- [ ] **Step 1: Write the failing tests**
  - E1 (engine half): for each typed entry point, the maps reaching the evaluator equal `RecordBuilders` output element-wise, with matching ordinals. `file_scanner` with an inaccessible record at index 0 and a match at index 1 → the finding has `ordinal == 1`.
  - S7: iterating `ServiceRecords.records` twice throws `IllegalStateException`.
- [ ] **Step 2–4: fail → implement → pass**; `PureEmitterContractTest` stays green.
- [ ] **Step 5: Commit** — `refactor(sigma): one-shot ServiceRecords; evaluateRecords with stored ordinals`

### Task A3: Codec and immutable dictionaries

**Files:**
- Create: `data/store/TelemetryRecordCodec.kt`, `data/store/TelemetryDictionaries.kt`, `data/store/HashKeys.kt`, `scripts/build_telemetry_dictionaries.py`, `res/raw/telemetry_dict_*_v1.txt`
- Test: `data/store/TelemetryRecordCodecTest.kt`, `data/store/TelemetryDictionariesTest.kt` (S5, S6)

**Interfaces:**
```kotlin
object HashKeys { fun h128(bytes: ByteArray): ByteArray; fun h128(s: String): ByteArray }   // SHA-256 truncated to 16 bytes
class TelemetryRecordCodec(private val dictionaries: TelemetryDictionaries) {
    fun strip(fields: Map<String, Any?>, source: TelemetrySource, capturedAt: Long): Stripped   // removes source/captured_at only when equal
    fun canonicalJson(fields: Map<String, Any?>): String       // recursive key sort; tagged long/int/double/nan/bytes/set
    fun encode(service: String, canonical: String, isEvent: Boolean, deflater: Deflater): EncodedBody
    fun decode(body: ByteArray, encoding: Int, dictVersion: Int, rawBytes: Int, strippedKeys: Int,
               source: TelemetrySource, capturedAt: Long): Map<String, Any?>?   // null = unreadable; own Inflater
}
data class Stripped(val fields: Map<String, Any?>, val strippedKeys: Int)      // bit 1 = source, bit 2 = captured_at
data class EncodedBody(val encoding: Int, val dictVersion: Int, val body: ByteArray, val rawBytes: Int)
class TelemetryDictionaries(load: (String) -> ByteArray) {
    fun current(service: String): Pair<Int, ByteArray>; fun byVersion(v: Int): ByteArray
    companion object { val PINNED_SHA256: Map<Int, String> }   // append-only
}
```

- [ ] **Step 1: Write the failing tests**
  - Stripping:
    - Stripping keeps `"source" to "bugreport_import"` and `"source" to "adb_trusted_key"`.
    - It strips `"source" to "BUGREPORT_IMPORT"` only when the observation's source is `BUGREPORT_IMPORT`.
    - It strips `captured_at` only when equal; `decode` restores exactly the stripped keys.
  - Canonical JSON:
    - Int vs Long, NaN, ByteArray, nested Map and Set round-trip to equal maps.
    - Different map orders give the same hash.
  - Compression: event encoding of 1,000 real `NetworkTelemetry` maps is ≥ 2.5× smaller.
  - S5:
    - Shipped dictionaries match their pinned hashes.
    - A v1 fixture body decodes.
    - Every event body's zlib header has FDICT set and a DICTID equal to the dictionary's Adler-32.
    - If builder output differs from the newest shipped version, the test fails with "add a new version".
  - S6: a truncated, bit-flipped or over-`rawBytes` body decodes to null.
- [ ] **Step 2–4: fail → implement (generate v1 once; commit it) → pass.**
- [ ] **Step 5: Commit** — `feat(store): codec with conditional envelope stripping and immutable dictionaries`

### Task A4: Entities, DAOs, migration 18→19

**Files:**
- Create: `data/model/{RecordBody,TelemetryFact,ScanObservation,EventWatermark,TelemetryState,ScanState}.kt`, `data/db/{RecordBodyDao,TelemetryFactDao,ScanObservationDao,EventWatermarkDao}.kt`, `di/StoreModule.kt`
- Modify:
  - `data/db/Migrations.kt`: `MIGRATION_18_19`.
  - `AppDatabase.kt`: `version = 19`.
  - `data/model/ScanResult.kt`: add `state: ScanState = COMPLETE`, `telemetryState: TelemetryState = NONE`.
  - `data/model/ForensicTimelineEvent.kt`: add `recordId: Long? = null`, `sourceEventKey: String? = null`; indices `recordId`, `sourceEventKey`, `scanResultId`.
  - `ScanResultDao.kt`: add `updateSummary(...)`; every list query filters `state = 'COMPLETE'`.
  - DI: register the migration; `onOpen` runs `PRAGMA journal_size_limit = 67108864`.
  - Commit `schemas/…/19.json`.
- Test: `data/db/Migration18To19Test.kt`, `data/db/StoreDaoTest.kt`

**Interfaces:**
- Entities exactly as spec §5.1. Keys are `ByteArray`. Entities holding `ByteArray` are plain classes (not data classes) or override `equals`/`hashCode` via `contentEquals`. `AUTOINCREMENT` on `telemetry_record.id`.
- DAOs (each ≤ 11 functions; every list parameter is reached through `chunkedIn`):
  - `RecordBodyDao`: `insertIgnore(List<RecordBody>)`, `deleteIfUnreferenced(hashes: List<ByteArray>)`, `distinctBytesByKind(): StorageSummary`.
  - `TelemetryFactDao`: `insertIgnore(List<TelemetryFact>): List<Long>`, `idsFor(service, factKeys: List<ByteArray>): List<FactIdRow>`, `history(service, subjectKey): Flow<List<ObservedFact>>`, `deleteIfUnobservedAndUnpinned(ids: List<Long>)`, `bodyHashesOf(ids: List<Long>): List<ByteArray>`, `hasLiveObservation(ids: List<Long>): List<Long>`.
  - `ScanObservationDao`: `insertIgnore(List<ScanObservation>): List<Long>`, `pageAfter(scanId, service, afterOrdinal: Int, size: Int): List<ObservedFact>` (keyset), `servicesForScan(scanId): List<ServiceSummary>`, `recordIdsAfter(scanId, afterRowId: Long, size: Int): List<RowIdRecord>` (deletion candidates, keyset), `deleteForScan(scanId)`, `deleteSnapshotsForScans(scanIds)`, `deleteLiveEventsBefore(cutoff)`, `factIdsForOrdinals(scanId, service, ordinals: List<Int>): List<OrdinalFact>`.
  - `EventWatermarkDao`: `get(service)`, `put(EventWatermark)`.
- Pins: `deleteIfUnobservedAndUnpinned` excludes ids referenced by `forensic_timeline.recordId`. The Phase D migration extends this to `scan_finding.recordId` (triggered) and `alert.recordId`.

- [ ] **Step 1: Write the failing tests**
  - Migration 18→19: the new tables, columns and indices exist; `validateMigration` passes.
  - Fact insert:
    - A duplicate fact key returns `-1`; `idsFor` finds it.
    - Unique `(scanId, recordId)` drops a duplicate observation.
  - Keyset and storage queries:
    - `pageAfter` pages by ordinal.
    - `distinctBytesByKind` counts a shared body once.
    - Every DAO SQL statement captured by a Room query callback contains no `OFFSET`.
  - Deletes:
    - A fact pinned by a `forensic_timeline.recordId` survives `deleteIfUnobservedAndUnpinned`.
    - `EXPLAIN QUERY PLAN` of each delete uses an index.
- [ ] **Step 2–4: fail → implement → pass.**
- [ ] **Step 5: Commit** — `feat(db): content, facts, observations, watermarks; scan state (schema 19)`

### Task A5: `TelemetryStore` and `TelemetryReader`

**Files:**
- Create: `data/store/TelemetryStore.kt`, `data/store/TelemetryReader.kt`, `data/store/OccurrenceCounter.kt`, `data/store/KeysetPagingSource.kt`, `data/store/EventDisplay.kt`, `res/raw/event_display.yml`
- Test: `data/store/TelemetryStoreTest.kt` (S1, S2, S4), `data/store/KeysetPagingSourceTest.kt`, `data/store/EventDisplayTest.kt`

**Interfaces:**
```kotlin
class OccurrenceCounter { fun next(hash: ByteArray): Int }      // primitive long→int on the first 8 bytes
data class ChunkResult(val observed: Int, val newFacts: Int, val duplicatesDropped: Int, val factIdByOrdinal: LongArray /* index = ordinal - firstOrdinal */)
data class DecodedRecord(val factId: Long, val scanId: Long, val service: String, val ordinal: Int, val source: TelemetrySource,
    val capturedAt: Long, val eventTime: Long?, val precision: TimePrecision, val category: String?, val fields: Map<String, Any?>?, val summary: String?)
data class RecordChange(val subjectKey: String, val before: DecodedRecord?, val after: DecodedRecord?)

class TelemetryStore @Inject constructor(bodies: RecordBodyDao, facts: TelemetryFactDao, obs: ScanObservationDao, codec: TelemetryRecordCodec) {
    suspend fun persistChunk(scanId: Long, service: String, source: TelemetrySource, capturedAt: Long,
        chunk: List<StoreRecord>, firstOrdinal: Int, counter: OccurrenceCounter, deflater: Deflater, liveEvents: Boolean): ChunkResult
    suspend fun deleteScan(scanId: Long)    // keyset candidates → observations → unobserved, unpinned facts → unreferenced bodies
}
class TelemetryReader @Inject constructor(...) {
    suspend fun services(scanId: Long): List<ServiceSummary>
    fun page(scanId: Long, service: String): Flow<PagingData<DecodedRecord>>
    suspend fun forEach(scanId: Long, service: String, block: suspend (DecodedRecord) -> Unit)
    fun history(service: String, subjectKey: String): Flow<List<DecodedRecord>>
    suspend fun changedBetween(scanA: Long, scanB: Long, service: String): List<RecordChange>
    suspend fun latestLive(service: String, maxAgeMs: Long): List<DecodedRecord>?
    companion object { const val APP_ENRICHMENT_MAX_AGE_MS = 5L * 60_000L }
}
abstract class KeysetPagingSource<K : Any, V : Any>(db: RoomDatabase, tables: Array<String>) : PagingSource<K, V>()   // registers an InvalidationTracker.Observer
```
Fact rules are per spec §5.1:
- `factKey` = `h128("src:" + key + "#" + bodyHashHex)` when `sourceEventKey` is set, else `h128(bodyHashHex + "#" + counter.next(bodyHash))`.
- `liveEvents = true` → no observation for a fact whose insert returned `-1` and that already has a live observation.
- Computed columns come from `TaxonomyContract`/`TimelineCategories`. Summaries are computed at read time.

- [ ] **Step 1: Write the failing tests**
  - S1 per service: the decoded map equals the original map, keys included, for live and bug-report records.
  - S2:
    - Two imports of 1,000 real `NetworkTelemetry` with different `capturedAt` → the second has `newFacts == 0` and both scans count 1,000.
    - Two identical-content DNS maps in one batch → 2 facts.
    - The same source key with a different `app_uid` → 2 facts.
    - 400 identical app records over two live scans → 400 facts and 800 observations.
    - A duplicated line in one import → `duplicatesDropped == 1`.
    - A re-collected live event → no second observation.
  - S4: deleting import A keeps B's records and pinned facts.
  - `changedBetween` keys on `subjectKey`.
  - The keyset paging source pages 10,000 records with no `OFFSET` in captured SQL and refreshes on an insert.
  - `EventDisplay` has a template for every event service.
- [ ] **Step 2–4: fail → implement → pass.**
- [ ] **Step 5: Commit** — `feat(store): TelemetryStore and TelemetryReader with keyset paging`

### Task A6: Typed bug-report records

**Files:**
- Modify:
  - `scanner/bugreport/InstallTimeModule.kt`: emit `PackageInstallHistoryEntry`; keep its current rows until C3.
  - `DbInfoModule.kt:74-78`: emit `DatabasePathObservation`; delete the `dbinfo_audit` emission.
  - `PlatformCompatModule.kt:42-54`: emit `PlatformCompatChange`; delete the `platform_compat_audit` emission.
  - `BatteryDailyModule.kt`: emit a `BatteryDailyEvent` for every parsed entry (install, update, uninstall, downgrade) with today's `event_type`; `timestamp` + `timestampPrecision = "day"` when the section header yields a date; keep its rows until C3.
  - `WakelockParser.kt:69` + `BugReportAnalyzer.kt:185-192`: time base is the bug report's capture time, parsed from the report header (the `== dumpstate:` timestamp line).
  - `data/model/{DatabasePathObservation,BatteryDailyEvent}.kt` and `sigma/TelemetryFieldMaps.kt`: new keys.
  - `BugReportAnalyzer.kt:238-242`: the bundle fills all seven lists.
  - `BugreportModule.kt`: `ModuleResult.typed: TypedTelemetry`.
  - Per-type input bounds: add `MAX_RECORDS_PER_MODULE = 2_000_000` to `BugreportModule`, reported on the card when tripped.
- Test: `scanner/BugReportTypedRecordsTest.kt` (B1, part 1), `scanner/BatteryParityTest.kt`

- [ ] **Step 1: Write the failing tests**
  - Typed records: run the real `BugReportAnalyzer` on a bug-report fixture. Use the existing ones under `app/src/test/resources/fixtures/`, adding a minimal fixture if needed with one install, one dbinfo entry, one compat change, battery install/update/uninstall/downgrade entries, one wakelock and a dumpstate header. Every typed list must be non-empty, and `db_path` / `recent_query_count` must be present.
  - Battery parity: every old `TimelineEvent` row from `BatteryDailyModule` has a typed record with the same `event_type` and package. The day timestamp equals the header date.
  - Wakelock: the wakelock `acquired_at` uses the header time, not `now`.
- [ ] **Step 2–4: fail → implement → pass.**
- [ ] **Step 5: Commit** — `feat(bugreport): typed records for install, db-info, compat, battery; wakelock time base`

### Task A7: Chunked writer, preflight, failure handling

**Files:**
- Create: `scanner/ChunkedScanWriter.kt`, `data/store/StoragePreflight.kt`, `scanner/StartupSweep.kt`
- Modify:
  - `data/repo/ScanRepository.kt`: `beginScan(scan)`; `chunkTransaction { }`; `finishScan(...)` with correlation as today, findings JSON with today's cap, `state = COMPLETE`. `deleteScan` / `deleteAllScans` call `telemetryStore.deleteScan`.
  - `scanner/ScanOrchestrator.kt`: all three writers go through `ChunkedScanWriter`. Delete `deletePriorIntrusionLogRows` and its `preDelete`. `UsageStatsScanner.collectTimelineEvents` returns `UsageEvent`s, mapped to today's rows until C3. Catch `Throwable`.
  - `scanner/intrusionlog/IntrusionLogParser.kt`: delete `seenKeys` (line 78) and the duplicate branch. Yield records lazily per type, carrying `sourceEventKey = "$type $eventId $eventTime"` when `event_id` exists. `MAX_*_RECORDS = 2_000_000`.
  - `scanner/IntrusionLogAnalyzer.kt`: produce three one-shot `ServiceRecords` over one pass. Lines are demultiplexed into three bounded queues of one chunk each, flushed to the writer whenever a queue fills.
  - `network/DnsVpnService.kt:949-962`: on a failed `logDnsEventsBatch`, re-queue the batch within the existing buffer bound and record a health warning.
  - `ui/bugreport/BugReportViewModel.kt` + `BugReportScreen.kt`: preflight dialog with "Import anyway"; import card shows new facts, already stored, duplicates dropped, and bounds tripped.
  - `AndroDrApplication` (or the existing startup hook): run `StartupSweep`.
- Test: `scanner/ChunkedScanWriterTest.kt` (E1 writer half, S3, M1), `data/store/StoragePreflightTest.kt`, `scanner/BugReportTelemetryPersistedTest.kt` (B1, part 2), `network/DnsFlushRetryTest.kt`

**Interfaces:**
```kotlin
class ChunkedScanWriter @Inject constructor(repo: ScanRepository, store: TelemetryStore, engine: SigmaRuleEngine) {
    suspend fun write(scan: ScanResult, batches: Sequence<ServiceRecords>, liveEventServices: Set<String>,
        onFindings: suspend (List<Finding>, LongArray) -> Unit): WriteResult    // Phase A: onFindings accumulates into the capped JSON list; Phase D: writes rows
}
data class WriteResult(val newFacts: Int, val alreadyStored: Int, val duplicatesDropped: Int, val telemetryState: TelemetryState)
class StoragePreflight(statFs: () -> StatFs) { fun check(decompressedBytes: Long): Preflight; companion object { const val STORED_SIZE_FACTOR = 0.6 } }
sealed interface Preflight { data object Ok : Preflight; data class Tight(val estimate: Long, val free: Long) : Preflight }
```
Live scans with `SQLiteFullException` from a chunk:
1. Delete the `IN_PROGRESS` scan.
2. Re-run `write` with no telemetry batches, keeping the findings.
3. Set `telemetryState = FAILED`.

- [ ] **Step 1: Write the failing tests**
  - E1 (writer half): the maps persisted and evaluated per chunk are identical. A gate source-scans `scanner/` for `evaluate[A-Z]` calls outside `ChunkedScanWriter` and the live typed-entry delegation.
  - S3 / Review Focus 5:
    - A writer that throws on chunk 3 leaves no visible scan, and no observations once the writer deletes it.
    - A simulated kill (scan left `IN_PROGRESS`) is removed by `StartupSweep`.
  - M1:
    - Preflight returns `Tight` when free − estimate < 2 × estimate + 200 MB.
    - "Import anyway" proceeds.
    - A live chunk throwing `SQLiteFullException` → scan saved with findings, `telemetryState == FAILED`.
  - Imports:
    - Re-importing the same intrusion-log fixture gives "0 new, N already stored", and both imports are listed.
    - A 200,000-line fixture runs under a test JVM with `maxHeapSize = "256m"` (dedicated Gradle `Test` task `lowHeapTest`, wired into `check`).
  - B1 (part 2): after `analyzeBugReport`, every module with telemetry has observations.
  - DNS flush: a failed batch is retried on the next flush.
- [ ] **Step 2–4: fail → implement → pass**; existing orchestrator tests get the new collaborators; reimport expectations updated (no sweep).
- [ ] **Step 5: Commit** — `feat(scan): chunked single-pass writer; storage preflight; startup sweep; no reimport sweep`

### Task A8: Retention

**Files:**
- Create: `data/store/TelemetryRetention.kt`
- Modify:
  - `ioc/IocUpdateWorker.kt:28-31`: run retention under `ScanOrchestrator.scanMutex`, which is exposed for this.
  - `data/repo/SettingsRepository.kt`: add `snapshotRetentionScans`, key `telemetry_retention_scans`, default 20.
  - `ScanResultDao`: add `setTelemetryState`.
  - `ForensicTimelineEventDao.kt:112-113`: add `AND telemetrySource = 'LIVE_SCAN'`.
- Test: `data/store/TelemetryRetentionTest.kt`, `data/db/ImportRowsExemptFromPruneTest.kt` (P1)

- [ ] **Step 1: Write the failing tests**
  - Snapshot retention: 25 live scans plus 2 imports, with N = 20. The newest 20 keep their snapshots; the older 5 become `PARTIAL_RETENTION`.
  - Live events: event observations older than 30 days are removed; younger ones are kept.
  - Imports are untouched, and pinned facts survive.
  - P1: import timeline rows survive the prune.
- [ ] **Step 2–4: fail → implement → pass.**
- [ ] **Step 5: Commit** — `feat(store): retention — snapshots by scan count, live events by age`

### Task A9: Phase A verification and PR

- [ ] `./gradlew testDebugUnitTest lowHeapTest detekt lintDebug` green.
- [ ] Clean install on the F916B (no `-g`). Scan twice, then pull the DB with `-wal`:
  - observations exist for both scans;
  - there is one scan's worth of snapshot facts;
  - no `IN_PROGRESS` rows remain.
- [ ] PR `feat/telemetry-store-a`; wait for `ci-success`; merge.

---

## Phase B — Report provenance (PR 2)

### Task B1: Streaming generic report, single path

**Files:**
- Modify:
  - `reporting/ReportFormatter.kt`:
    - Signature becomes `suspend fun writeScanReport(out: Writer, scan: ScanResult, findings: FindingsView, logLines: List<String>, telemetry: StoredTelemetrySource, mode: ExportMode, versionName: String)`.
    - Remove the typed telemetry parameters and `intrusionEvents`.
    - Add generic per-service sections.
    - Add `escapeForReport(s: String): String`, which escapes Unicode categories Cc, Cf, Zl, Zp, Co and Cn as `\uXXXX` and is applied to keys and values.
  - `reporting/ReportExporter.kt`:
    - Write through a `BufferedWriter` to the file.
    - Before writing, delete `cache/reports/` files older than one hour.
    - Add `suspend fun summary(scan): ReportSummary`.
    - Add `suspend fun exportEstimate(scan): ExportEstimate` (record count, size, sensitive categories).
  - `ui/history/HistoryViewModel.kt` + `HistoryScreen.kt`:
    - The sheet shows the `ReportSummary`.
    - Delete `INTRUSION_ROW_LIMIT`, `getRecentSnapshot` and `lastAppTelemetry`.
    - The export dialog shows the `ExportEstimate`.
  - `ui/bugreport/BugReportViewModel.kt:160-195`: export through `ReportExporter`; enrichment through `TelemetryReader.latestLive("app_scanner", APP_ENRICHMENT_MAX_AGE_MS)`.
  - `scanner/ScanOrchestrator.kt`: delete every `last*Telemetry*` field and use, and `APP_TELEMETRY_CACHE_MAX_AGE_MS`.
- Create: `reporting/StoredTelemetrySource.kt`, `reporting/ReportSummary.kt`, `reporting/FindingsView.kt`. In Phase B, `FindingsView` wraps `scan.findings`; Phase D swaps its source.
- Test: `reporting/ReportProvenanceTest.kt` (R1), `reporting/SingleReportPathTest.kt` (R2), `reporting/ReportEscapingTest.kt` (R3)

- [ ] **Step 1: Write the failing tests**
  - R1 — each report shows only its own scan's data:
    - Scan A's report shows `com.a` and not `com.b`.
    - Import I's report shows neither, and does show `TOMBSTONE_PARSER`.
    - `PARTIAL_RETENTION`, `NONE` and `FAILED` scans each print their own line.
  - R2: `writeScanReport(` appears only in `ReportExporter.kt`. No `last(App|Device|Process|FileArtifact|Accessibility|Receiver|AppOps)Telemetry` remains.
  - R3: each of `\n`, `\r`, U+2028 and U+202E in a wakelock tag value and in a field key renders as a single line with `\uXXXX`.
- [ ] **Step 2–4: fail → implement → pass**; existing `ReportFormatter*Test` call sites updated in the same commit.
- [ ] **Step 5: Commit** — `fix(report): stream each scan's own stored telemetry; one path; escaped device text`
- [ ] **Step 6: Phase B PR** `feat/telemetry-store-b`; battery: export an older scan's report on the F916B.

---

## Phase C — Events in place and the Timeline (PR 3)

The four tasks ship together, so the Timeline never loses rows between PRs.

### Task C1: Watermarks

**Files:**
- Create: `scanner/Watermarks.kt`, `scanner/UsageAccess.kt`. `UsageAccess` holds the non-UI check lifted from `ui/permissions/UsageStatsPermission`.
- Modify:
  - `scanner/UsageStatsScanner.kt`: replace with `collectEvents(sinceMs, untilMs): UsageCollection`.
  - `data/db/DnsEventDao.kt`: add `eventsAfterId(afterId, untilId, size)` (keyset), `maxId()`, `minIdSince(ts)`.
  - `scanner/ScanOrchestrator.kt`:
    - Add `val scanMutex = Mutex()` around all three writers.
    - Collect live DNS by id and usage by time with a 5-minute re-read.
    - Delete the `getRecentSnapshot()` post-hoc window.
    - Live DNS records carry `sourceEventKey = "dns:${id}"`.
  - `ScanRepository.finishScan`: write the watermarks.
  - `logDnsEvent` / `logDnsEventsBatch`: `ioc_match` rows set `sourceEventKey = "dns:${id}"`.
- Test: `scanner/EventWatermarkTest.kt` (W1)

**Interfaces:**
```kotlin
sealed interface UsageCollection { data class Ok(val events: List<UsageEvent>) : UsageCollection; data object NoAccess : UsageCollection; data class Failed(val e: Throwable) : UsageCollection }
object Watermarks {
    fun nextTime(previous: Long?, collection: UsageCollection, scanStart: Long, now: Long, saveFallback: Boolean): Long?   // null = keep
    fun nextDnsId(previous: Long?, collectedMaxId: Long?, failed: Boolean, saveFallback: Boolean): Long?
}
```
Rules for `nextTime`:
- `NoAccess`, `Failed` or `saveFallback` → null.
- `Ok` → `min(max(events.maxOfOrNull { it.timestamp } ?: scanStart, prev ?: 0), scanStart)`.
- A previous value greater than `now` is treated as absent.
- Capability skips do not stop an advance.

- [ ] **Step 1: Write the failing tests**
  - Collection over two consecutive scans: every event is observed once and none is missed.
  - Watermark advance rules:
    - `NoAccess` on the first scan → null, and the previous value is unchanged.
    - `Ok(empty)` on the first scan → `scanStart`.
    - A future-dated event caps the watermark at `scanStart`.
    - A previous value ahead of `now` is reset to the 24-hour floor.
  - DNS:
    - A DNS row inserted with an older timestamp and a higher id is collected.
    - A capability-skipped `dns_monitor` rule across 10 scans: the watermark advances every scan, and the total observation count equals the number of distinct events.
  - Concurrency: concurrent scan and import serialise on `scanMutex`.
- [ ] **Step 2–4: fail → implement → pass.**
- [ ] **Step 5: Commit** — `feat(scan): per-service watermarks; scan serialisation`

### Task C2: Correlation over facts

**Files:**
- Create: `sigma/TimelineAtom.kt`
- Modify:
  - `sigma/SigmaRuleEngine.kt:125`: `computeAtomBindings(atoms): Map<AtomRef, Set<String>>`.
  - `sigma/SigmaCorrelationEngine.kt`: work over atoms; add `member_fact_ids` beside `member_event_ids`.
  - `sigma/RuleCoverage.kt`: work over atoms.
  - `data/store/TelemetryReader.kt`: add `atomsForScan(scanId, categories): Sequence<TimelineAtom>` and `atomsBetween(since, until, categories, excludeSource): Sequence<TimelineAtom>`. These cover facts with `timePrecision = EXACT` only, and exclude facts referenced by a `forensic_timeline.recordId` or `sourceEventKey`.
  - `ScanRepository.finishScan`: the correlator receives finding-row atoms, `atomsForScan`, and lookback atoms, all restricted to `sigmaRuleEngine.atomCategories()`.
  - Every `member_event_ids` consumer: `ui/timeline/TimelineClusters.kt:136-150`, the `findingsFor` member reader, `reporting/ReportFormatter.kt`, `data/db/ForensicTimelineEventDao.kt`.
- Test: `sigma/CorrelationOverFactsTest.kt` (K1 part 2), `sigma/MemberIdsConsumersGateTest.kt`

**Interfaces:** `data class TimelineAtom(val ref: AtomRef, val category: String, val timestamp: Long, val packageName: String, val ruleId: String, val telemetrySource: TelemetrySource)`; `sealed interface AtomRef : Comparable<AtomRef> { data class Row(val id: Long); data class Fact(val id: Long) }` (string form `r:<id>` / `f:<id>`).

- [ ] **Step 1: Write the failing tests**
  - Binding:
    - An `event_count` rule over 3 fact atoms plus 1 row atom fires once and lists both id kinds.
    - A row and a fact with the same numeric id bind separately.
    - A live DNS fact and its `ioc_match` row bind once, not twice.
    - A day-precision battery fact never becomes an atom.
  - Clusters and coverage:
    - `buildCluster` resolves members of both kinds.
    - `noEventSkipsFor` counts fact categories.
  - Gate: every `main` file mentioning `member_event_ids` also mentions `member_fact_ids`.
- [ ] **Step 2–4: fail → implement → pass.**
- [ ] **Step 5: Commit** — `feat(sigma): correlation over fact atoms keyed by AtomRef`

### Task C3: Event rows live only in the store

**Files:**
- Modify:
  - `scanner/ScanOrchestrator.kt`:
    - No usage, DNS, connect, security, install-history, app-ops or battery event rows go to `forensic_timeline`.
    - `buildIntrusionLogTimelineEvents` keeps finding rows only.
    - Bug-report `rawEvents` and `moduleForensicEvents` are deleted.
  - `data/db/TimelineAdapter.kt`: delete the event adapters.
  - `scanner/bugreport/{AdbKeysModule,AppOpsModule,BatteryDailyModule,InstallTimeModule}.kt`: delete timeline construction.
  - `BugreportModule.kt`: remove `ModuleResult.timeline`.
  - `BugReportAnalyzer.kt`: remove `timeline`.
  - `ui/bugreport/BugReportViewModel.kt` + `BugReportScreen.kt`: link to the Timeline filtered by the import's scan id.
  - Delete `reporting/TimelineFormatter.kt` and `data/model/TimelineEvent.kt`.
- Test: `scanner/EventRowsLiveInStoreTest.kt`

- [ ] **Step 1: Write the failing tests**
  - Intrusion log: `analyzeIntrusionLog` on a 7,000-event fixture writes finding rows plus signals to `forensic_timeline` for that scan, and 7,000 observations.
  - Live scan: after `runFullScan`, no `forensic_timeline` row has `source = 'usage_stats'`.
  - Battery parity: the parity test from A6 still passes (typed records present for every old row type).
- [ ] **Step 2–4: fail → implement → pass**; adapt `IntrusionLogClusterRegressionTest` and `IntrusionLogReportSectionTest`.
- [ ] **Step 5: Commit** — `feat(timeline): event records read in place; TimelineEvent retired`

### Task C4: `TimelineDao`, keyset union, counts

**Files:**
- Create: `data/db/TimelineDao.kt`, `data/db/TimelineQueries.kt` (one builder per filter shape: none, scan, package, source, range, levels, findings-and-evidence), `data/model/TimelineRowEntity.kt`, `data/db/TimelineFilter.kt`, `ui/timeline/TimelinePagingSource.kt` (extends `KeysetPagingSource`; key `(time, rowKind, id)`)
- Modify:
  - `data/db/ForensicTimelineEventDao.kt`: delete the six read queries, including `getAllForExport`.
  - `ui/timeline/TimelineViewModel.kt`: `Flow<PagingData<TimelineRow>>` plus header flows.
  - `ui/timeline/TimelineRow.kt`: add `EventRow`; delete `mergeTimelineRows` and `rollUpFindings`.
  - `ui/timeline/TimelineScreen.kt`: `collectAsLazyPagingItems`, counts, and the switch text "Show findings and their evidence only".
  - `reporting/TimelineExporter.kt`: stream by keyset; keep the CSV guard.
  - C1 allow-list: drop the timeline entries.
- Test: `ui/timeline/TimelineUncappedTest.kt` (T1), `data/db/TimelineQueryPlanTest.kt`, `scanner/NoPersistenceCapsGateTest.kt` (C1, timeline half)

**Interfaces:** `data class TimelineRowEntity(val rowKind: Int, val id: Long, val scanId: Long, val time: Long, val category: String, val packageName: String, val level: String, val ruleId: String, val correlationId: String, val kind: String, val telemetrySource: TelemetrySource, val bodyHash: ByteArray?)`; `data class TimelineFilter(val scanId: Long? = null, val packageName: String? = null, val source: String? = null, val from: Long? = null, val to: Long? = null, val levels: Set<String> = emptySet(), val findingsAndEvidenceOnly: Boolean = false, val zone: ZoneId)`. The fact branch uses `COALESCE` for every non-null column and excludes referenced facts (nested instead).

- [ ] **Step 1: Write the failing tests**
  - T1:
    - 100,000 event facts plus 50 finding rows all page.
    - The count flow reports 100,050.
    - No event row is duplicated.
    - Evidence is nested.
    - Captured SQL has no `OFFSET`.
    - The 100,000 events include 5,000 `permission_use` events, and correlation over them completes under `lowHeapTest`.
  - Query plan: for every filter shape, no `USE TEMP B-TREE` and no full scan of `telemetry_record`, `scan_record` or `forensic_timeline`.
  - C1 timeline half:
    - Regex `_PERSIST_CAP|_ROW_LIMIT|\bLIMIT\s+\d+|limit:\s*Int\s*=\s*\d+` finds nothing in `data/db`, `scanner`, `reporting` or `ui` beyond the allow-list.
    - The allow-list is `getLatestTwo`, `IndicatorDao.lookup`, `DnsEventDao.getRecentEvents` and `getRecentSnapshot`, plus `FINDINGS_PERSIST_CAP` until D2.
- [ ] **Step 2–4: fail → implement → pass.**
- [ ] **Step 5: Commit** — `feat(timeline): keyset-paged union of event facts and timeline rows with counts`
- [ ] **Step 6: Phase C PR** `feat/telemetry-store-c`; battery: scan twice, import an intrusion log twice, open a Timeline with over 20,000 rows, and check the report and Timeline agree.

---

## Phase D — Findings, alerts, lifecycle (PR 4)

### Task D1: Protected confirmation

**Files:**
- Create: `ui/security/ConfirmCredential.kt`. It uses platform `BiometricPrompt` with `setAllowedAuthenticators(DEVICE_CREDENTIAL)` on API 30+, and `KeyguardManager.createConfirmDeviceCredentialIntent` with an `ActivityResult` on API 26–29. It returns `Confirmed | NoSecureLock | Cancelled`.
- Create: `ui/security/ObscuredTouchGuard.kt`, a `Modifier` that rejects pointer events carrying `MotionEvent.FLAG_WINDOW_IS_OBSCURED` or `FLAG_WINDOW_IS_PARTIALLY_OBSCURED`.
- Test: `ui/security/ConfirmCredentialTest.kt`, `ui/security/ObscuredTouchGuardTest.kt`

- [ ] **Step 1: Write the failing tests**
  - API routing: API 30 uses the `BiometricPrompt` path; API 28 uses the `KeyguardManager` intent.
  - No secure lock screen → `NoSecureLock`.
  - A touch carrying the obscured flag is consumed without invoking the action.
- [ ] **Step 2–4: fail → implement → pass.**
- [ ] **Step 5: Commit** — `feat(ui): device-credential confirmation and obscured-touch guard`

### Task D2: `scan_finding`, `alert`, migration 19→20, caps removed

**Files:**
- Create: `data/model/{ScanFinding,Alert,AlertMember,FindingKind,AlertStatus,ScanWithFindings}.kt`, `data/db/{ScanFindingDao,AlertDao}.kt`, `data/db/FrozenRuleServices.kt`, `data/repo/FindingsRepository.kt`, `data/repo/AlertIdentity.kt`
- Modify:
  - Schema:
    - `Migrations.kt`: `MIGRATION_19_20`.
    - `AppDatabase.kt`: `version = 20`.
    - `ScanResult.kt`: drop `findings`; add `triggeredCount` and `maxLevel`.
    - `ForensicTimelineEvent.kt`: add `level`.
    - `TimelineAdapter.kt`: finding rows set `level`.
    - `ScanResultDao.kt`: add `latestLive(): Flow<ScanResult?>` and `pagedAfter(afterTimestamp, size)` (keyset); `getAllScans` deleted; `getLatestTwo` kept, live-only.
  - Writers:
    - `ChunkedScanWriter` `onFindings` writes `scan_finding` rows and alert upserts per chunk through `FindingsRepository.recordChunk`.
    - Correlation findings go through `FindingsRepository.recordCorrelation`.
  - Pins: `TelemetryFactDao.deleteIfUnobservedAndUnpinned` also excludes facts referenced by triggered `scan_finding.recordId` and by `alert.recordId`.
  - Caps: `ScanOrchestrator.kt` deletes `FINDINGS_PERSIST_CAP`, `DNS_PERSIST_CAP`, `CONNECT_PERSIST_CAP`, `SECURITY_PERSIST_CAP`, `capTriggeredFindings` and the caps log. `computeDiff` takes `ScanWithFindings`. `IntrusionLogAnalyzer.kt` drops "kept N of M".
  - Consumers:
    - `ui/dashboard/DashboardViewModel.kt`: open-alert count plus a paged list.
    - `ui/device/DeviceAuditViewModel.kt` and `ui/apps/AppScanViewModel.kt`.
    - `ui/bugreport/BugReportViewModel.kt`.
    - `ui/history/HistoryViewModel.kt` + `HistoryScreen.kt`: keyset paging.
    - `ui/timeline/TimelineViewModel.kt`.
    - `reporting/FindingsView.kt`: now reads from `FindingsRepository`.
  - Tests: the 16 test files constructing `ScanResult(findings = …)` move to a `scanWith(findings)` helper.
- Test: `data/db/Migration19To20Test.kt` (F1 + Review Focus 4), `data/repo/FindingLifecycleTest.kt` (L1), `data/repo/FindingRecordRefTest.kt` (F2), `scanner/NoPersistenceCapsGateTest.kt` (C1 complete)

**Interfaces:**
- Entities per spec §5.4. `alert.id` uses AUTOINCREMENT, and `alertKey` is unique. `scan_finding` indices: `scanId`, `ruleId`, `recordId`, `alertId`, `(kind)`.
- `AlertIdentity`:
  - `fun recordKey(ruleId: String, factId: Long, evidence: Evidence): ByteArray` = `h128("$ruleId|$factId|${evidence.discriminator()}")`. It applies to triggered findings only.
  - `suspend fun correlationAlert(ruleId: String, groupKey: String, members: List<AtomRef>): Long?` finds an existing alert by member overlap.
- `FindingsRepository`:
  - `recordChunk(scanId, findings, factIdByOrdinal, isEventByOrdinal)`
  - `recordCorrelation(scanId, findings, members)`
  - `current(): Flow<CurrentFindingsSummary>`
  - `openAlerts(): Flow<PagingData<AlertView>>`
  - `forScan(scanId): Flow<PagingData<Finding>>`
  - `close(alertId, reason, credential: CredentialResult)`
  - `CurrentFindingsSummary(stateFindings: List<Finding> /* latest live scan; bounded by rule count */, openAlertCount: Int)`
- Migration 19→20 follows spec §5.4 exactly:
  - read findings by `length` plus 256 KB `substr` chunks;
  - schema-19 findings resolved per record through `scan_record`;
  - older findings get their kind from `matchContext` event time, or from an always-event service;
  - unknown rule ids → STATE;
  - alerts OPEN if within 30 days;
  - `level` is backfilled.

- [ ] **Step 1: Write the failing tests**
  - F1 (migration 19→20):
    - 1,200 findings in one scan, a corrupt row and a 3 MB row: the migration completes and all three scans keep their rows.
    - A schema-19 live app-ops finding (`sigma_androdr_063`) stays STATE.
    - A DNS finding becomes an ALERT: OPEN when 10 days old, CLOSED when 40 days old.
    - `level` is backfilled.
  - L1 (finding lifecycle):
    - A state finding follows the latest live scan and survives an intervening import.
    - An alert persists until closed.
    - Import B's finding on a fact shared with import A attaches to the same alert, and B keeps its own `scan_finding` row.
    - A correlation chain that grows from {a,b,c} to {a,b,c,d} across scans joins the existing alert.
    - A closed alert stays closed; a new fact opens a new alert.
    - Two evidence results on one record give two alerts.
  - F2: for every service, a finding's `recordId` decodes to its matched record.
  - C1 complete: the allow-list is reduced to the four entries in spec §5.5.
- [ ] **Step 2–4: fail → implement → pass.**
- [ ] **Step 5: Commit** — `feat(findings): per-scan findings, lasting alerts, migration 19→20; caps removed`

### Task D3: Alerts UI and protected deletion

**Files:**
- Modify:
  - `ui/dashboard/DashboardScreen.kt` + `DashboardViewModel.kt`: open-alerts card and paged list; Close → `ConfirmCredential` → `FindingsRepository.close`; buttons wrapped in `ObscuredTouchGuard`.
  - `ui/timeline/TimelineEventCard.kt`: Close on alert rows.
  - `ui/history/HistoryViewModel.kt`: deleting a scan that has findings on OPEN alerts, and Clear all, both require `ConfirmCredential`.
  - `data/repo/ScanRepository.kt`: `deleteScan` deletes `scan_finding` rows only, never `alert`; closure rows written with `scanResultId = -1`.
  - `FindingsRepository.close`: sets `closedWithCredential` and writes an `alert_closed` row.
  - `reporting/ReportFormatter.kt`: FINDINGS lists state findings, open alerts (with the opening scan), and closed alerts (time, note, credential flag).
  - `res/values/strings.xml`.
- Test: `data/repo/AlertCloseTest.kt` (L2), `ui/dashboard/DashboardAlertsViewModelTest.kt`

- [ ] **Step 1: Write the failing tests**
  - L2 (protected actions):
    - Close, delete-scan-with-open-alerts and clear-all do not run without `Confirmed`, or without `NoSecureLock` (which records `closedWithCredential = false`).
    - The closure row survives deletion of its scan.
    - Deleting a scan keeps its alert.
  - Report: closed alerts are listed with the credential flag.
- [ ] **Step 2–4: fail → implement → pass.**
- [ ] **Step 5: Commit** — `feat(ui): open alerts with credential-protected close and deletion`
- [ ] **Step 6: Phase D PR** `feat/telemetry-store-d`. Battery:
  - scan twice and confirm there are no duplicate alerts;
  - import an intrusion log with over 1,000 findings;
  - close an alert and delete a scan through the credential prompt.

---

## Phase E — Browser, settings, export, vocabulary (PR 5)

### Task E1: Telemetry browser

**Files:**
- Create: `ui/telemetry/TelemetryBrowserViewModel.kt`, `TelemetryServicesScreen.kt`, `TelemetryRecordsScreen.kt`, `SubjectHistorySheet.kt`.
- Modify:
  - `MainActivity.kt`: routes `telemetry/{scanId}`, `telemetry/{scanId}/{service}`, `fact/{factId}`.
  - `ui/history/HistoryScreen.kt` and `ui/timeline/TimelineScreen.kt`: "View telemetry" and "Matched record" entries.
  - `res/values/strings.xml`.
- Field order and descriptions come from `TaxonomyContract`.

**Test:** `ui/telemetry/TelemetryBrowserViewModelTest.kt`:
- the services list reflects the store;
- keyset paging emits;
- a 300 ms debounced search narrows results by package;
- an unreadable record renders as unreadable;
- subject history marks the changed keys.

- [ ] **Step 1–4: fail → implement → pass.**
- [ ] **Step 5: Commit** — `feat(ui): telemetry browser with subject history`

### Task E2: Settings and JSONL export

**Files:**
- Modify `ui/settings/SettingsScreen.kt` + `SettingsViewModel.kt`:
  - storage by kind, from `distinctBytesByKind`;
  - a retention slider, 5–100, default 20;
  - "Delete old snapshot telemetry now".
- Modify `ui/history/HistoryViewModel.kt` + `HistoryScreen.kt` to add "Export telemetry (JSONL)":
  - first show the `ExportEstimate` dialog;
  - then stream the scan's records through `GZIPOutputStream` to `cache/reports/androdr_telemetry_<scanId>.jsonl.gz`, after the stale-file cleanup.
- Modify `data/store/TelemetryReader.kt`: add `exportJsonl(scanId, out: Writer)`.

**Test:**
- `ui/settings/TelemetrySettingsViewModelTest.kt`.
- `ui/history/TelemetryExportTest.kt`:
  - the export streams;
  - stale files are removed;
  - the gz output decodes to one envelope per observation;
  - envelope keys are restored per the observation.

- [ ] **Step 1–4: fail → implement → pass.**
- [ ] **Step 5: Commit** — `feat(ui): telemetry storage settings and JSONL export`

### Task E3: Vocabulary gate and glossary

**Files:**
- Modify `docs/ARCHITECTURE.md`:
  - add a Glossary section containing spec §3's table verbatim;
  - add §5.1 entity rows for `record_body`, `telemetry_record`, `scan_record`, `scan_finding`, `alert`, `alert_member` and `event_watermark`;
  - describe retention in §5.2;
  - remove `TimelineFormatter` from §6.3.
- Modify the `reporting/ReportExporter.kt` comments at lines 29–33.
- Fix any remaining UI copy.

**Test:** `app/src/test/java/com/androdr/VocabularyGateTest.kt` (V1):
- `main` Kotlin, `res/values` and `docs/*.md` (excluding `docs/superpowers/`) contain no "raw telemetry" or "informational telemetry", and no `class TimelineEvent\b`;
- ARCHITECTURE has a Glossary heading listing all ten terms.

- [ ] **Step 1–4: fail → fix → pass.**
- [ ] **Step 5: Commit** — `docs: telemetry glossary; vocabulary gate`
- [ ] **Step 6: Phase E PR** `feat/telemetry-store-e`. Run the full release battery per spec §9, including measuring `STORED_SIZE_FACTOR` and updating the constant if it is off by more than 20%.

---

## Self-review notes

**Spec coverage:**
- §3 → E3.
- §4.1 → A2, A3, A7, 0.2.
- §4.2 → 0.1.
- §4.3 → 0.2, C2.
- §5.1 → A3, A4, A5, A8.
- §5.2 → A7, C1.
- §5.3 → A6, C3.
- §5.4 → D1–D3.
- §5.5 → C4, D2.
- §5.6 → A8.
- §6 → C2, C4, E1.
- §7 → B1, D3, E2.
- §8 → E1, E2.

**Gates:**

| Gate | Task(s) |
|---|---|
| S1, S2, S4 | A5 |
| S3, M1 | A7 |
| S5, S6 | A3 |
| S7 | A2 |
| E1 | A2 + A7 |
| E2, D1, X1 | 0.2 |
| K1 | 0.2 + C2 |
| W1 | C1 |
| R1–R3 | B1 |
| B1 | A6 + A7 |
| C1 | C4 + D2 |
| T1 | C4 |
| F1, F2, L1 | D2 |
| L2 | D3 |
| V1 | E3 |
| P1 | A8 |
| Q1 | A1 |

**Ordering:**
- The taxonomy (Phase 0) lands before the first stored record.
- Typed records (A6) land before their rows are removed (C3).
- Watermarks and correlation over facts (C1, C2) land before the alert identity (D2), so correlation alert keys are fact-based from the first alert.
- Event rows are removed in the same PR as the Timeline union (C3 + C4).
- `FINDINGS_PERSIST_CAP` keeps today's behaviour until `scan_finding` replaces it (D2).

**Type consistency:** each of these is defined once and used by name thereafter: `StoreRecord`, `ServiceRecords`, `ChunkResult`, `WriteResult`, `DecodedRecord`, `ObservedFact`, `TimelineAtom`/`AtomRef`, `TimelineRowEntity`, `TimelineFilter`, `CurrentFindingsSummary`, `UsageCollection`, `TimePrecision`, `Preflight`.
