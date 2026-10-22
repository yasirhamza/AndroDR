# Telemetry Store, Uncapped Timeline, Finding Lifecycle Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Store every telemetry record a scan or import produces, as facts observed by scans. Remove every persistence cap. Read the Timeline as a paged union with no duplicated event rows. Give findings an alert lifecycle that outlives scans. Make the telemetry vocabulary precise and gated.

**Architecture:**
- **Writing.** A push-session writer (`begin → append(service, chunk) → finish`) runs one transaction per chunk of up to 5,000 records. Each transaction persists content (`record_body`), facts (`telemetry_record`) and observations (`scan_record`), evaluates the same maps, and writes finding rows. The scan stays `IN_PROGRESS` and invisible until `finish`. `finish` correlates, creates alerts set-based, and marks the scan `COMPLETE`.
- **Findings and alerts.** Findings are per scan (`scan_finding`). Incidents are `alert` rows that outlive scans.
- **Reading.** The Timeline is a keyset-paged union of visible event facts and `forensic_timeline` rows. Reports stream from one `ReportExporter` path.

**Tech Stack:** Kotlin 2.0; Room 2.6.1 (`room-testing` on the unit-test classpath); AndroidX Paging 3.3.6 (+ `paging-compose`); `androidx.collection` 1.4.0; Jetpack Compose; Hilt; kotlinx.serialization; `java.util.zip`; platform `BiometricPrompt` / `KeyguardManager`; Robolectric 4.14.1 (SDK 35, offline) with `androidx.test:core` 1.6.1; snakeyaml-engine 2.7 (already present).

**Spec:** `docs/superpowers/specs/2026-10-22-telemetry-store-design.md`, revised after plan-gate rounds 1–4. Findings: `docs/superpowers/plans/2026-10-22-telemetry-store-plan-gate-round{1,2,3,4}-findings.md`.

## Global Constraints

**Builds and tests**
- JDK 21.
- Gates: `./gradlew testDebugUnitTest`, `./gradlew detekt`, `./gradlew lintDebug`, `./gradlew lowHeapTest`.
- CI runs `assembleDebug test lowHeapTest` and `lintDebug detekt`. Task A7 adds `lowHeapTest` to `.github/workflows/ci.yml`.
- Every gate is a JVM unit test.
- Every fix lands with a test that fails on the original mistake.
- Every commit compiles and passes the full unit suite.

**Dependencies**
- Pin every new dependency exactly, and review the `verification-metadata.xml` diff in the same commit.
- Add no new native library, no SQLite build, no `androidx.biometric`, and no `room-paging`.

**Caps and memory**
- No `_PERSIST_CAP`, `_ROW_LIMIT`, `LIMIT <n>` or `limit: Int = <n>` outside the per-phase C1 allow-list (spec §5.5).
- No OFFSET paging.
- No full-import `List` anywhere. The one exception is the Phase A–C findings top-K and newest-N heaps, which are bounded.

**Data rules**
- Event facts are never copied into `forensic_timeline`.
- Every fact or observation read requires a `COMPLETE` scan.
- `ReportFormatter` is called only from `ReportExporter`.
- Writers evaluate only through the session.

**SQL**
- Use only API 26 SQLite features.
- List-binding `@Query` calls go through `chunkedIn(≤ 900)`.

**Naming and data formats**
- No source-named types or fields.
- Taxonomy names are `snake_case`.
- Dictionaries are immutable.
- Map lookups on `ByteArray` keys go through `ByteBuffer.wrap`.

**Taxonomy, branches and detekt**
- Taxonomy edits follow CLAUDE.md safe ordering.
- Each phase (0, A–E) is one PR to `main` on branch `feat/telemetry-store-<phase>`, and leaves the app working.
- Phases A–D form one release train: no Play release is cut between the A and D merges, because retention arrives in D4.
- detekt reports at `>=` its threshold, so the effective limits are:
  - classes and objects: ≤ 14 functions
  - interfaces: ≤ 10
  - files: ≤ 10 top-level functions
  - `LongParameterList`: < 13
  - `LongMethod`: < 60
- New Hilt providers go in `di/StoreModule.kt`.

## Review Focus

1. **Content-valued envelope keys.** Keys holding content survive unchanged, and keys equal to the observation restore exactly. Pinned in Task A5 (S1).
2. **Usage access revoked.** When usage access is revoked between scans, the watermark stays unchanged. When access is present but there are no events, it advances to scan start. Pinned in Task C1.
3. **Rule this binary can't evaluate.** A rules update ships a `dns_monitor` rule that this binary cannot evaluate. The watermark still advances; observations stay linear; the late-IOC re-check still runs. Pinned in Task C1.
4. **Oversized or corrupt findings during migration 19→20.** A `findings` value over 2 MB, or corrupt, still lets the migration complete. Pinned in Task D2.
5. **Killed mid-import.** After restart, nothing of the import is visible and the sweep removes it. Pinned in Task A7.

---

## Phase 0 — Taxonomy first (rules PR + AndroDR PR 0)

### Task 0.1: Rules-repo taxonomy change (safe ordering steps 1–2)

**Files (rules repo, branch `feat/taxonomy-emitter-services`):**
- Modify: `validation/logsource-taxonomy.yml`, exactly as spec §4.2 describes:
  - `emitter_only` services `usage_stats` (`timestamp, package_name, app_name, event_type, source, captured_at`) and `system_property` (`key, value, source, captured_at`)
  - `adb_audit` and `activity_audit`, documented from the modules' current record keys
  - `event_time_field` on the nine services the spec lists; not on `db_info`
  - `battery_daily.time_precision_field`
  - `key_fields`, `package_field`, the new fields, and the `positive_only` / `optional` flags
- Modify: `validation/validate-rule.py`:
  - accept the new keys
  - generalise the negation guard (~line 517) to every `positive_only` or `optional` field

- [ ] **Step 1:** Edit, validate locally, push, open the rules PR, and wait for a green `validate`. Do not merge.
- [ ] **Step 2:** Point the submodule at the branch commit. Commit `build: bump android-sigma-rules to taxonomy emitter-services branch`.

### Task 0.2: Kotlin contract, field maps, cross-checks

**Files:**
- Modify:
  - `data/model/DnsEvent.kt:24` (add `"timestamp"`)
  - `data/model/ImportedDnsEvent.kt` (add `toFieldMap()` = `event.toFieldMap() + ("resolved_ips" to resolvedIps)`)
  - `data/model/FileArtifactTelemetry.kt:11-16` (add `"accessible"`)
  - `data/model/SystemPropertySnapshot.kt` (add `toFieldMap()`)
  - `scanner/IntrusionLogAnalyzer.kt` (evaluate imported DNS through `ImportedDnsEvent.toFieldMap()`)
- Create: `data/model/UsageEvent.kt`, `sigma/TaxonomyContract.kt`, `sigma/TimelineCategories.kt`, `app/src/test/resources/contract-corpus/*.json` (sample records for X1).
- Modify tests:
  - `LogsourceTaxonomyCrossCheckTest.kt`: add the new services, honour `optional`, and use `TestRuleRepo.loadTaxonomy`.
  - `ServiceActivationCrossCheckTest.kt`: accept `emitter_only`, and assert those services have no evaluate path.
- Test: `sigma/TaxonomyContractTest.kt` (X1 included), `sigma/TimelineCategoriesAtomTest.kt` (K1 part 1), `data/model/FieldMapCompletenessTest.kt` (E2), `scanner/DnsFindingTimestampTest.kt` (D1).

**Interfaces:**
```kotlin
data class UsageEvent(val timestamp: Long, val packageName: String, val appName: String,
    val eventType: String, val source: TelemetrySource, val capturedAt: Long) { fun toFieldMap(): Map<String, Any?> }
enum class TimePrecision { EXACT, DAY }
object TaxonomyContract {
    fun eventTimeField(service: String): String?
    fun precisionField(service: String): String?
    fun keyFields(service: String): List<String>
    fun packageField(service: String): String?
    fun fieldOrder(service: String): List<String>
    fun description(service: String, field: String): String?
    fun eventTimeOf(service: String, fields: Map<String, Any?>): Long?
    fun precisionOf(service: String, fields: Map<String, Any?>): TimePrecision
    val eventServices: Set<String>
    val contractHash: String            // contract table + categoryOf/precisionOf outputs over the corpus
    const val CONTRACT_SCHEMA_VERSION = 19   // schema version that last recomputed the computed columns
}
object TimelineCategories { fun categoryOf(service: String, fields: Map<String, Any?>): String }   // spec §4.3 table
```

- [ ] **Step 1: Write the failing tests**
  - Contract (X1 included):
    - Every contract accessor equals the taxonomy, in both directions.
    - A live app-ops map is a snapshot; a bug-report app-ops map with `event_time_ms` is an event.
    - `db_info` has no event-time field.
    - `contractHash` equals the pinned value recorded for `CONTRACT_SCHEMA_VERSION`. On mismatch the message is "recompute migration + bump CONTRACT_SCHEMA_VERSION".
  - K1 part 1: every atom selection category in `res/raw/sigma_androdr_atom_*.yml` is produced by `TimelineCategories`, or is a `forensic_timeline` row category.
  - E2: field-map completeness, with a commented allow-list.
  - D1: an imported DNS finding row carries the record's `timestamp`.
- [ ] **Step 2–4: fail → implement → pass.** The taxonomy cross-checks pass on the bumped submodule.
- [ ] **Step 5: Commit** `feat(sigma): taxonomy contract, complete field maps, imported DNS time`
- [ ] **Step 6 (safe ordering 3–5):**
  1. Push and confirm `build-and-test` is green.
  2. Merge the rules PR.
  3. Re-point the submodule; commit `build: bump android-sigma-rules submodule`.
  4. Open PR `feat/telemetry-store-0`, wait for `ci-success`, and merge.

---

## Phase A — Store and the session writer (PR 1)

After Phase A, every scan and import writes facts and observations through the session.

Until later phases, three things keep today's behaviour:
- **Findings** go to `ScanResult.findings` through a streaming top-K that keeps today's cap. This lasts until D2.
- **Event rows** go to `forensic_timeline` from bounded newest-N heaps (today's caps), and the reimport sweep stays. This lasts until C3.

There is no retention yet; it arrives in D4.

### Task A1: JVM Room harness and SQL gates

**Files:**
- Modify `gradle/libs.versions.toml`:
  - Versions: `robolectric = "4.14.1"`, `androidxTestCore = "1.6.1"`, `paging = "3.3.6"`, `androidxCollection = "1.4.0"`.
  - Libraries: `robolectric`, `androidx-test-core`, `androidx-paging-runtime`, `androidx-paging-compose`, `androidx-collection`, and the Robolectric `android-all-instrumented` SDK 35 jar.
- Modify `app/build.gradle.kts`:
  - `testImplementation(libs.robolectric, libs.androidx.test.core, libs.androidx.room.testing)`
  - `testRuntimeOnly(<android-all jar>)`
  - `implementation(libs.androidx.paging.runtime, libs.androidx.paging.compose, libs.androidx.collection)`
  - `getByName("test") { assets.srcDirs("schemas") }`
  - `testOptions.unitTests.isIncludeAndroidResources = true`
  - On all `Test` tasks: `systemProperty("robolectric.offline", "true")` and `systemProperty("robolectric.dependency.dir", <dir filled by a Copy task from the resolved jar>)`.
- Create:
  - `app/src/test/resources/robolectric.properties` (`sdk=35`)
  - `app/src/test/java/com/androdr/data/db/RoomTestDb.kt`
  - `app/src/main/java/com/androdr/data/db/ChunkedIn.kt`
- Test: `data/db/RoomJvmHarnessTest.kt`, `data/db/SqlCompatibilityGateTest.kt` (Q1, syntax and parameters), `data/db/ChunkedInTest.kt`.

**Interfaces:**
- `object RoomTestDb { fun inMemory(): AppDatabase; fun migrationHelper(): MigrationTestHelper }`
- `suspend fun <K, R> chunkedIn(keys: Collection<K>, size: Int = 900, query: suspend (List<K>) -> List<R>): List<R>`
- `suspend fun <K> chunkedEach(keys: Collection<K>, size: Int = 900, action: suspend (List<K>) -> Unit)`

- [ ] **Step 1: Write the failing tests**
  - **Harness:**
    - The in-memory DB round-trips a `ScanResult`.
    - The migration helper opens schema 18.
    - If the test assets are not visible, fall back to a `copySchemas` task.
  - **Q1 syntax:** SQL string literals in `data/db/*.kt` contain none of `ON CONFLICT`, `RETURNING`, `OVER (`, `NULLS LAST`, `NULLS FIRST`, `DROP COLUMN`, `RENAME COLUMN`, `IIF(`, `->>`, `FILTER (`.
  - **Q1 parameters:** every `@Query` function with a `List`/`Collection` parameter is called only inside `chunkedIn`/`chunkedEach`.
  - **Chunking:** with 5,000 keys, each call gets at most 900.
- [ ] **Step 2–4: fail → implement → pass.**
- [ ] **Step 5: Commit** `test: JVM Room harness; SQLite compatibility and parameter-limit gates`

### Task A2: `evaluateRecords` and record builders

**Files:**
- Create: `sigma/StoreRecord.kt`; `sigma/LiveRecordBuilders.kt`, `sigma/BugReportRecordBuilders.kt`, `sigma/IntrusionLogRecordBuilders.kt` (one `object` each, ≤ 14 functions).
- Modify:
  - `sigma/SigmaRuleEvaluator.kt:23-45,135-215`:
    - Add `Finding.service` and `Finding.ordinal`.
    - `evaluate(..., firstOrdinal: Int, include: (Int) -> Boolean)`.
  - `sigma/SigmaRuleEngine.kt:249-358`:
    - Add `evaluateRecords`. Typed `evaluate*` delegate to it through the builders.
    - `evaluateFiles` uses `include` with the accessible flag.
  - `ServiceActivationCrossCheckTest.kt`: re-derive the check from builder service literals and from `evaluateRecords` call sites, keeping the vacuity guard.
- Test: `sigma/EvaluateRecordsTest.kt` (E1, engine half).

**Interfaces:**
```kotlin
data class StoreRecord(val fields: Map<String, Any?>, val sourceEventKey: String? = null)
fun SigmaRuleEngine.evaluateRecords(service: String, chunk: List<StoreRecord>, firstOrdinal: Int): List<Finding>
```

- [ ] **Step 1: Write the failing tests**
  - Each typed entry point's maps equal the builder output, element by element, with ordinals.
  - For `file_scanner` with an inaccessible record at index 0, the finding has `ordinal == 1`.
- [ ] **Step 2–4: fail → implement → pass.** `PureEmitterContractTest` stays green.
- [ ] **Step 5: Commit** `refactor(sigma): evaluateRecords with stored ordinals; record builders`

### Task A3: Codec and immutable dictionaries

**Files:** Create `data/store/TelemetryRecordCodec.kt`, `data/store/TelemetryDictionaries.kt`, `data/store/HashKeys.kt`, `scripts/build_telemetry_dictionaries.py`, and `res/raw/telemetry_dict_*_v1.txt`.

**Test:** `data/store/TelemetryRecordCodecTest.kt`, `data/store/TelemetryDictionariesTest.kt` (S5, S6).

**Interfaces:**
```kotlin
object HashKeys { fun h128(bytes: ByteArray): ByteArray; fun h128(s: String): ByteArray; fun key(b: ByteArray): ByteBuffer }
class TelemetryRecordCodec(private val dictionaries: TelemetryDictionaries) {
    fun strip(fields: Map<String, Any?>, source: TelemetrySource, capturedAt: Long): Stripped
    fun canonicalJson(fields: Map<String, Any?>): String
    fun encode(service: String, canonical: String, isEvent: Boolean, deflater: Deflater): EncodedBody
    fun decode(body: ByteArray, encoding: Int, dictVersion: Int, rawBytes: Int, strippedKeys: Int,
               source: TelemetrySource, capturedAt: Long): Map<String, Any?>?
}
data class Stripped(val fields: Map<String, Any?>, val strippedKeys: Int)
class EncodedBody(val encoding: Int, val dictVersion: Int, val body: ByteArray, val rawBytes: Int)
class TelemetryDictionaries(load: (String) -> ByteArray) {
    fun current(service: String): Pair<Int, ByteArray>; fun byVersion(v: Int): ByteArray
    companion object { val PINNED_SHA256: Map<Int, String> }
}
```

- [ ] **Step 1: Write the failing tests**
  - **Stripping:**
    - `"bugreport_import"` and `"adb_trusted_key"` in `source` are kept.
    - `"BUGREPORT_IMPORT"` is stripped only when the observation's source matches.
    - `captured_at` is stripped only when it is equal.
    - Decode restores exactly the stripped keys.
  - **Canonical JSON:**
    - Int/Long, NaN, `ByteArray`, nested `Map` and `Set` round-trip.
    - Key order doesn't change the hash.
  - **Compression:** event bodies are at least 2.5× smaller on 1,000 real `NetworkTelemetry` records.
  - **S5:**
    - Pinned hashes match.
    - A v1 fixture decodes.
    - The zlib header has the dictionary flag and the dictionary's Adler-32.
    - When the builder output drifts, the test demands a new version.
  - **S6:** a corrupt body, or one that inflates past `rawBytes`, decodes to `null`.
- [ ] **Step 2–4: fail → implement → pass.**
- [ ] **Step 5: Commit** `feat(store): codec with conditional envelope stripping and immutable dictionaries`

### Task A4: Entities, DAOs, migration 18→19

**Files:**
- Create:
  - `data/model/{RecordBody,TelemetryFact,ScanObservation,EventWatermark,SignalMember,TelemetryState,ScanState}.kt`
  - `data/db/{RecordBodyDao,TelemetryFactDao,ScanObservationDao,EventWatermarkDao,SignalMemberDao}.kt`
  - `di/StoreModule.kt`
- Modify:
  - `data/db/Migrations.kt`: `MIGRATION_18_19`.
  - `AppDatabase.kt`: `version = 19`.
  - `data/model/ScanResult.kt`: add `state` (default `COMPLETE` in the entity and in the migration) and `telemetryState`.
  - `data/model/ForensicTimelineEvent.kt`:
    - add `recordId`, `sourceEventKey: ByteArray?` (an h128 hash, the same hash as `telemetry_record.sourceKey`), `level`, and `persistent: Boolean = false`;
    - indices: `recordId`, `sourceEventKey`, `(scanResultId, startTimestamp)`, `(packageName, startTimestamp)`.
  - `MIGRATION_18_19`: backfill `level` on legacy finding rows from `ScanResult.findings`, matching on (`scanResultId`, `ruleId`).
  - `ScanResultDao.kt`: add `insertInProgress`, `complete(...)` and `inProgressIds()`. `deleteById` already exists at `:21`. Every list query filters `state = 'COMPLETE'`.
  - DI: register the migration; `onOpen` runs `PRAGMA journal_size_limit = 67108864`.
  - Commit `19.json`.
- Test: `data/db/Migration18To19Test.kt`, `data/db/StoreDaoTest.kt`.

**Interfaces:**
- Entities follow spec §5.1 exactly. Entities holding `ByteArray` are plain classes. `telemetry_record.id` and `forensic_timeline.id` stay AUTOINCREMENT, which a schema test pins.
- DAOs (each ≤ 10 functions):
  - `RecordBodyDao.insertIgnore(List<RecordBody>)`, `deleteUnreferenced(hashes: List<ByteArray>)`.
  - `TelemetryFactDao`:
    - `insertIgnore(List<TelemetryFact>): List<Long>`
    - `idsFor(service, factKeys: List<ByteArray>): List<FactIdRow>`
    - `liveObserved(ids: List<Long>): List<Long>`
    - `deleteUnobservedUnpinned(ids: List<Long>)`
    - `bodyHashesOf(ids: List<Long>): List<ByteArray>`
    - `idsBySourceKey(keys: List<ByteArray>): List<FactIdRow>`
  - `ScanObservationDao`:
    - `insertIgnore(List<ScanObservation>): List<Long>`
    - `factIdsAfter(scanId, afterService: String, afterOrdinal: Int, size: Int): List<ObservationKey>` (keyset on the PK)
    - `deleteForScan(scanId)`
    - `factIdsForOrdinals(scanId, service, ordinals: List<Int>): List<OrdinalFact>`
  - `EventWatermarkDao.get(service)`, `put(EventWatermark)`.
  - `SignalMemberDao.insertAll(List<SignalMember>)`.
- `deleteUnobservedUnpinned` excludes ids referenced by `forensic_timeline.recordId` or `signal_member` fact refs. Task D2 extends it to `scan_finding` and `alert`.

- [ ] **Step 1: Write the failing tests**
  - **Migration:**
    - tables, columns and composite indices exist; `validateMigration` passes;
    - scans saved before the upgrade read back as `COMPLETE`;
    - legacy finding rows get `level`.
  - **J1:** a live DNS fact (`sourceKey = h128("dns:7")`) and an `ioc_match` row (`sourceEventKey = h128("dns:7")`) join in a real DAO query.
  - **Inserts:**
    - A duplicate fact returns `-1`, and `idsFor` finds the original.
    - Unique `(scanId, recordId)` drops a duplicate observation.
    - A fact pinned by `signal_member` survives deletion.
  - **Query plans:**
    - `factIdsAfter` uses the PK.
    - No captured SQL contains `OFFSET`.
    - Deletes use indices (`EXPLAIN QUERY PLAN`).
- [ ] **Step 2–4: fail → implement → pass.**
- [ ] **Step 5: Commit** `feat(db): content, facts, observations, watermarks, signal members (schema 19)`

### Task A5: `TelemetryStore` and `TelemetryReader`

**Files:** Create `data/store/TelemetryStore.kt`, `data/store/TelemetryReader.kt`, `data/store/OccurrenceCounter.kt`, `data/store/KeysetPagingSource.kt`, `data/store/EventDisplay.kt`, `res/raw/event_display.yml`.

**Test:** `data/store/TelemetryStoreTest.kt` (S1, S2, S4), `data/store/KeysetPagingSourceTest.kt`, `data/store/EventDisplayTest.kt`, `data/db/CompleteVisibilityGateTest.kt` (Q1 visibility).

**Interfaces:**
```kotlin
class OccurrenceCounter { fun next(hash: ByteArray): Int }   // androidx.collection.MutableLongIntMap on the first 8 bytes
data class ChunkResult(val observed: Int, val newFacts: Int, val alreadyStored: Int, val duplicatesDropped: Int,
    val factIdByChunkIndex: LongArray, val isEventByChunkIndex: BooleanArray, val observedThisScanByChunkIndex: BooleanArray)  // index = ordinal - firstOrdinal
data class DecodedRecord(val factId: Long, val scanId: Long, val service: String, val ordinal: Int, val source: TelemetrySource,
    val capturedAt: Long, val eventTime: Long?, val precision: TimePrecision, val category: String?, val fields: Map<String, Any?>?, val summary: String?)
data class RecordChange(val subjectKey: String, val before: DecodedRecord?, val after: DecodedRecord?)

class TelemetryStore @Inject constructor(...) {
    suspend fun persistChunk(scanId: Long, service: String, source: TelemetrySource, capturedAt: Long,
        chunk: List<StoreRecord>, firstOrdinal: Int, counter: OccurrenceCounter, deflater: Deflater, liveEvents: Boolean): ChunkResult
    suspend fun deleteScan(scanId: Long)   // idempotent; keyset candidates; unobserved, unpinned facts; unreferenced bodies
}
class TelemetryReader @Inject constructor(...) {
    suspend fun services(scanId: Long): List<ServiceSummary>
    fun page(scanId: Long, service: String): Flow<PagingData<DecodedRecord>>
    suspend fun forEach(scanId: Long, service: String, block: suspend (DecodedRecord) -> Unit)
    fun history(service: String, subjectKey: String): Flow<List<DecodedRecord>>
    suspend fun changedBetween(scanA: Long, scanB: Long, service: String): List<RecordChange>
    suspend fun latestLive(service: String, maxAgeMs: Long): List<DecodedRecord>?
    suspend fun storage(): StorageSummary            // distinct bodies, by kind, COMPLETE scans only
    companion object { const val APP_ENRICHMENT_MAX_AGE_MS = 5L * 60_000L }
}
abstract class KeysetPagingSource<K : Any, V : Any>(db: RoomDatabase, observed: Array<String>) : PagingSource<K, V>()
```
- **Fact keys** (spec §5.1):
  - with a source key: `factKey = h128("src:"+key+"#"+bodyHashHex)` and `sourceKey = h128(key)`
  - otherwise: `factKey = h128(bodyHashHex+"#"+counter.next(bodyHash))`
- **Live event rule:** with `liveEvents`, no observation is written for an existing fact that already has a live observation.
- **Visibility:** a fact is visible if it has an observation whose scan is `COMPLETE`, or if it has no observation at all (a pinned orphan).
- **Paging:** `KeysetPagingSource`
  - registers an `InvalidationTracker.Observer` on first load and removes it on invalidate, calling `refreshVersionsSync()` before the first load;
  - `getRefreshKey` backs off half a load from the anchor;
  - prepends through a reverse-ordered query;
  - observes only tables that exist in the current schema: `ScanResult` and `forensic_timeline` from schema 19, plus `alert` from schema 20.
- **Detekt split:** reads are split across `TelemetryReader` (per-scan), `AtomReader` (correlation atoms, Phase C) and `TelemetryExport` (JSONL, Phase E), to stay under the detekt function limit.

- [ ] **Step 1: Write the failing tests**
  - **S1:** the full decoded map equals the original for every service.
  - **S2:**
    - Two imports of 1,000 real `NetworkTelemetry` records with different `capturedAt`: the second reports `alreadyStored == 1000`.
    - Two identical-content DNS maps in one batch become 2 facts.
    - The same source key with a different `app_uid` becomes 2 facts.
    - Two id-less intrusion lines with the same type, time and content become 1 fact and 1 observation (`duplicatesDropped == 1`).
    - 400 apps over two live scans become 400 facts and 800 observations.
    - A re-collected live event gets no second observation.
  - **S4:** deleting import A keeps B's records and any pinned facts.
  - **Visibility:**
    - Records of an `IN_PROGRESS` scan are invisible to every reader method.
    - A pinned fact with no remaining observation is still readable through `record(...)` and `history(...)`.
    - The Q1 visibility gate: every DAO query naming `telemetry_record`, `scan_record`, `scan_finding`, or `forensic_timeline` rows owned by a scan must apply the visibility rule (spec §5.1), or be on the writer/deleter allow-list. The allow-list includes `AtomReader`'s current-scan reads.
  - **Paging:**
    - Scroll position survives an invalidation.
    - No captured SQL contains `OFFSET`.
  - **Display:** every event service has an `EventDisplay` template.
- [ ] **Step 2–4: fail → implement → pass.**
- [ ] **Step 5: Commit** `feat(store): TelemetryStore and TelemetryReader; COMPLETE-only visibility; keyset paging`

### Task A6: Typed bug-report records

**Files:**
- Modify:
  - `scanner/bugreport/InstallTimeModule.kt`: emit `PackageInstallHistoryEntry`. Keep its rows until C3.
  - `DbInfoModule.kt:74-78`: emit `DatabasePathObservation`, and delete the generic emission.
  - `PlatformCompatModule.kt:42-54`: emit `PlatformCompatChange`, and delete the generic emission.
  - `BatteryDailyModule.kt`: emit a `BatteryDailyEvent` for every parsed entry, with today's `event_type` plus day-precision time from the section header. Delete the IOC-only generic emission at `:74-83`. Keep its rows until C3.
  - `WakelockParser.kt:69` and `BugReportAnalyzer.kt:185-192`: use the time base from the dumpstate header.
  - `data/model/{DatabasePathObservation,BatteryDailyEvent}.kt` and `sigma/TelemetryFieldMaps.kt`: add the new fields.
  - `BugReportAnalyzer.kt:238-242`: fill the bundle completely.
  - `BugreportModule.kt`: add `ModuleResult.typed: TypedTelemetry`, and `MAX_RECORDS_PER_MODULE = 200_000` with the trip reported.
- Test: `scanner/BugReportTypedRecordsTest.kt` (B1 part 1), `scanner/BatteryParityTest.kt`.

- [ ] **Step 1: Write the failing tests**
  - **Typed records:**
    - Run the real analyzer on the fixture (add a minimal one covering every section).
    - Every typed list is non-empty.
    - `db_path` and `recent_query_count` are present.
    - No `battery_daily`, `dbinfo_audit` or `platform_compat_audit` generic `ModuleResult` remains.
  - **Battery parity:** every old battery row has a typed record, and the day timestamp matches the header.
  - **Wakelock:** wakelock time comes from the header.
- [ ] **Step 2–4: fail → implement → pass.**
- [ ] **Step 5: Commit** `feat(bugreport): typed records for install, db-info, compat, battery; wakelock time base`

### Task A7: Session writer, interim rules, preflight, failure handling

**Files:**
- Create:
  - `scanner/ChunkedScanWriter.kt`
  - `scanner/InterimTimelineRows.kt` (bounded newest-N heaps per type, plus the findings top-K)
  - `data/store/StoragePreflight.kt`
  - `scanner/StartupSweep.kt`
- Modify `data/repo/ScanRepository.kt`: split the transactions used by the writer into a new `data/repo/ScanWriteRepository.kt` (≤ 14 functions). `deleteScan` / `deleteAllScans` call `telemetryStore.deleteScan`.
- Modify `scanner/ScanOrchestrator.kt`:
  - Add `val scanMutex = Mutex()`. It wraps all three writers.
  - All writers use the session.
  - Live DNS records carry `sourceEventKey = "dns:$id"`.
  - Live `ioc_match` rows written by `logDnsEvent` / `logDnsEventsBatch` set `sourceEventKey = h128("dns:$id")`. `DnsEventDao.insert` and `insertAll` return ids.
  - Catch `Throwable`.
  - Keep `deletePriorIntrusionLogRows` (forensic rows only). It runs inside `finish`'s transaction and excludes the current scan.
  - Every `forensic_timeline` write happens inside `finish`'s transaction:
    - finding rows (with `level` and `recordId`);
    - the interim event rows (which also carry `recordId`).
    No `ForensicTimelineEventDao` write is reachable from `append`.
  - `UsageStatsScanner` returns `UsageEvent`s, mapped to today's rows until C3.
  - The set of live event services comes from `TaxonomyContract.eventServices`.
  - Extract `scanner/LiveScanCollector.kt` (telemetry collection and its watermark inputs) to keep `ScanOrchestrator` under the detekt limit.
- Modify `scanner/intrusionlog/IntrusionLogParser.kt`:
  - Delete `seenKeys` (line 78) and its branch.
  - Push records to a callback per type.
  - `sourceEventKey` is `"$type $eventId $eventTime"`, or `"$type ? $eventTime"` when the id is absent.
  - `MAX_*_RECORDS = 2_000_000`.
- Modify `scanner/IntrusionLogAnalyzer.kt`:
  - Make one pass, appending each type's chunk to the session when its 5,000-record buffer fills.
  - `IntrusionLogStats` keeps a running min/max instead of `tsList`.
- Modify `data/repo/ScanRepository.logDnsEventsBatch` / `DnsEventDao.insertAll`: return ids.
- Modify `network/DnsVpnService.kt:903-962`:
  - Make `DnsLogBuffer` `internal`.
  - On failure, re-queue with exponential backoff, drop the oldest beyond the bound, and record a health warning.
- Modify `AndroDRApplication`: run `StartupSweep`.
- Modify `ui/bugreport/BugReportViewModel.kt` and `BugReportScreen.kt`:
  - Add a preflight dialog (estimate, or "unknown size") with "Import anyway".
  - Show reserve aborts.
  - The import card shows new facts, already-stored facts, dropped duplicates, and tripped bounds.
- Modify `.github/workflows/ci.yml:113`: add `lowHeapTest`.
- Modify `app/build.gradle.kts`: add a `lowHeapTest` `Test` task (`maxHeapSize = "256m"`, filtered to `*LowHeap*`), excluded from `test`.
- Test:
  - `scanner/ChunkedScanWriterTest.kt` (E1 writer half, S3, ST1, M1)
  - `scanner/IntrusionLogImportLowHeapTest.kt`
  - `data/store/StoragePreflightTest.kt`
  - `scanner/BugReportTelemetryPersistedTest.kt` (B1 part 2)
  - `scanner/FindingRowRecordIdTest.kt` (F2, Phase A half)
  - `network/DnsFlushRetryTest.kt`

**Interfaces:**
```kotlin
class ChunkedScanWriter @Inject constructor(...) {
    suspend fun begin(scan: ScanResult, liveEvents: Boolean): Session
    inner class Session {
        suspend fun append(service: String, source: TelemetrySource, capturedAt: Long, chunk: List<StoreRecord>)  // ≤ 5,000; evaluate, then one transaction; findings kept only for observedThisScan ordinals
        suspend fun appendAll(service: String, source: TelemetrySource, capturedAt: Long, records: Sequence<StoreRecord>)  // constrainOnce, chunked
        suspend fun evaluateStored(service: String, facts: Sequence<Pair<Long, StoreRecord>>)  // re-check: findings get recordId = factId, ordinal = -1; no observations
        suspend fun finish(): WriteResult      // opens the single finishing transaction; all forensic_timeline writes happen here
        suspend fun abort()                    // NonCancellable, unaudited cleanup delete
    }
}
data class WriteResult(val newFacts: Int, val alreadyStored: Int, val duplicatesDropped: Int, val telemetryState: TelemetryState)
class StoragePreflight(statFs: () -> StatFs) {
    fun check(decompressedBytes: Long?): Preflight; fun reserveOk(): Boolean
    companion object { const val STORED_SIZE_FACTOR = 0.6; const val CHUNK_RESERVE_BYTES = 150L * 1024 * 1024 }
}
sealed interface Preflight { data object Ok : Preflight; data class Tight(val estimate: Long?, val free: Long) : Preflight }
```

**Live `SQLiteFullException` path:**
1. The session switches to evaluate-only for the rest of the pass.
2. Findings are buffered in memory with `recordId = null`.
3. On `finish`, the findings are written, `telemetryState = FAILED` is set, and no watermark advances.
4. If that write also fails, the in-memory result is returned to the UI and a storage-health flag is written to DataStore.

**Import reserve path:** if `reserveOk()` is false before an append, the session switches to evaluate-only for the rest of the import. `finish` sets `telemetryState = FAILED`, and the card states how much space to free.

**`Finding` change:** `Finding` gains `recordId: Long? = null`, set only by `evaluateStored`.

- [ ] **Step 1: Write the failing tests**
  - **E1 (writer half):**
    - Persisted and evaluated maps are identical per chunk.
    - Source gate: no `evaluate[A-Z]` call outside the session and the typed live delegation.
  - **ST1:** an instrumented sequence shows chunk *k* committed before record *(k+1)·5000+1* is pulled.
  - **S3 / Review Focus 5:**
    - A throw on chunk 3 leaves nothing visible: no facts, no finding rows, no Timeline rows.
    - A throw inside `finish`, after alert creation, leaves 0 alerts.
    - A simulated kill leaves the scan `IN_PROGRESS`. `StartupSweep` takes the lock only to snapshot ids, removes the scan, and writes one persistent "import interrupted" row.
    - A scan started during the sweep survives.
    - Aborting writes no "scan_deleted" audit row.
  - **Duplicates (S2):** an intrusion log containing the same id-less line twice yields one observation and **one finding**.
  - **M1:**
    - `Tight` when free − estimate < 2 × estimate + 200 MB; "Import anyway" proceeds.
    - Headers that under-report sizes: the reserve trips, and the import finishes evaluate-only with its findings kept and `FAILED` set.
    - A live `SQLiteFullException` on chunk 1 of the first service: findings from every service are present and `FAILED` is set.
    - A second failure on the findings write: the result is returned in memory and the DataStore health flag is set.
  - **Interim:**
    - Re-importing the same intrusion log in Phase A shows "0 new" and does not stack event rows (the sweep is kept).
    - Interim capped rows equal today's newest-N.
    - The findings top-K equals today's `capTriggeredFindings` on a 1,500-finding fixture.
  - **Low heap:** a 200,000-line intrusion log imports under 256 MB (`lowHeapTest`). The `lowHeapTest` task copies `testClassesDirs` and `classpath` from `testDebugUnitTest`, and depends on the Robolectric jar copy task.
  - **B1 part 2:** every module with telemetry is observed.
  - **F2 (Phase A half):**
    - Every triggered finding row on a stored service has a resolvable `recordId` and a non-null `level`.
    - `FAILED` scans are exempt.
    - The test uses `firstOrdinal > 0`, so chunk-relative indexing is exercised.
  - **DNS retry:** a failed flush retries with backoff; the buffer stays bounded.
- [ ] **Step 2–4: fail → implement → pass.**
- [ ] **Step 5: Commit** `feat(scan): session writer; preflight and reserve; startup sweep; interim bounded rows`

### Task A8: Phase A verification and PR

- [ ] `./gradlew testDebugUnitTest lowHeapTest detekt lintDebug` green.
- [ ] Clean install on the F916B (no `-g`), scan twice, pull the DB with `-wal`, and confirm:
  - both scans have observations;
  - snapshot facts are deduplicated;
  - there are no `IN_PROGRESS` rows.
- [ ] Open PR `feat/telemetry-store-a`, wait for `ci-success`, merge.

---

## Phase B — Report provenance (PR 2)

### Task B1: Streaming generic report, single path

**Files:**
- Modify `reporting/ReportFormatter.kt`:
  - New signature: `suspend fun writeScanReport(out: Writer, scan: ScanResult, findings: FindingsView, logLines: List<String>, telemetry: StoredTelemetrySource, mode: ExportMode, versionName: String)`.
  - Remove the typed telemetry parameters and `intrusionEvents`; render generic per-service sections instead.
  - Add `escapeForReport(s)`. It escapes `\` and characters in Unicode categories Cc, Cf, Zl, Zp, Co, Cn and Cs as `\uXXXX`. It applies to keys and to values nested in lists and maps.
- Modify `reporting/ReportExporter.kt`:
  - Write through a `BufferedWriter`, cleaning stale files first.
  - Add `summary(scan)` and `exportEstimate(scan)`.
- Modify `ui/history/HistoryViewModel.kt` and `HistoryScreen.kt`:
  - The sheet shows the summary.
  - Delete `INTRUSION_ROW_LIMIT`, `getRecentSnapshot` and `lastAppTelemetry`.
  - The export dialog shows the estimate.
- Modify `ui/bugreport/BugReportViewModel.kt:160-195`: export through `ReportExporter`; enrich through `TelemetryReader.latestLive`.
- Modify `scanner/ScanOrchestrator.kt`: delete `last*Telemetry*` and `APP_TELEMETRY_CACHE_MAX_AGE_MS`.
- Create: `reporting/StoredTelemetrySource.kt`, `reporting/ReportSummary.kt`, `reporting/FindingsView.kt`. In Phase B, `FindingsView` wraps `scan.findings`.
- Test: `reporting/ReportProvenanceTest.kt` (R1), `reporting/SingleReportPathTest.kt` (R2), `reporting/ReportEscapingTest.kt` (R3).

- [ ] **Step 1: Write the failing tests**
  - **R1:**
    - Scan A's report shows A's packages only.
    - Import I's report shows only its own services.
    - `PARTIAL_RETENTION`, `NONE` and `FAILED` each print their own line.
  - **R2:** `writeScanReport(` appears only in `ReportExporter.kt`, and no `last*Telemetry` remains.
  - **R3:** escaping covers `\n`, `\r`, U+2028, U+202E, `\`, a lone surrogate, and a newline inside a list element of a map value. Each case is checked in both a key and a value.
- [ ] **Step 2–4: fail → implement → pass.** Existing report test call sites are updated in the same commit.
- [ ] **Step 5: Commit** `fix(report): stream each scan's own stored telemetry; one path; complete escaping`
- [ ] **Step 6:** Open Phase B PR `feat/telemetry-store-b`. Battery: export an older scan's report on the F916B.

---

## Phase C — Events in place and the Timeline (PR 3)

### Task C1: Watermarks and late-IOC re-check

**Files:**
- Create: `scanner/Watermarks.kt`, `scanner/UsageAccess.kt`.
- Modify:
  - `scanner/UsageStatsScanner.kt`: `collectEvents(sinceMs, untilMs): UsageCollection`.
  - `data/db/DnsEventDao.kt`: add `eventsAfterId(afterId, untilId, size)`, `maxId()` and `minIdSince(ts)`.
  - `scanner/ScanOrchestrator.kt`:
    - Collect DNS by id and usage by time, with the 5-minute re-read.
    - Delete the `getRecentSnapshot()` window.
    - Run the late-IOC re-check through `Session.evaluateStored`. It streams stored live DNS facts from the trailing 24 h in keyset chunks; its findings carry `recordId = factId` and `ordinal = -1`.
  - `ScanWriteRepository.finish`: write the watermarks.
  - The `ioc_match` link key is already written from Phase A (Task A7).
- Test: `scanner/EventWatermarkTest.kt` (W1).

**Interfaces:**
```kotlin
sealed interface UsageCollection { data class Ok(val events: List<UsageEvent>) : UsageCollection; data object NoAccess : UsageCollection; data class Failed(val e: Throwable) : UsageCollection }
object Watermarks {
    fun nextTime(previous: Long?, collection: UsageCollection, scanStart: Long, now: Long, saveFallback: Boolean): Long?
    fun nextDnsId(previous: Long?, collectedMaxId: Long?, failed: Boolean, saveFallback: Boolean): Long?
}
```

`nextTime` rules:
- `NoAccess`, `Failed` or `saveFallback` → `null` (keep the previous watermark).
- `Ok` → `min(max(maxTimestamp ?: scanStart, prev ?: 0), scanStart)`.
- A `prev` greater than `now` is treated as absent.

- [ ] **Step 1: Write the failing tests**
  - **Collection over consecutive scans:** each event is observed once and none is missed.
  - **Watermark advance rules:**
    - `NoAccess`, `Failed` and `saveFallback` each leave the watermark unchanged.
    - `Ok(empty)` on the first scan advances it to `scanStart`.
    - A future-dated event caps it at `scanStart`.
    - A `prev` ahead of `now` resets it.
  - **DNS by id:** a late-flushed DNS row (older timestamp, higher id) is collected.
  - **Capability-skipped rule:** across 10 scans with a capability-skipped `dns_monitor` rule, the watermark advances each time and observations equal the distinct events.
  - **Late-IOC re-check:**
    - A domain added to the IOC set after scan 1 fires on scan 2, from the stored fact, once.
    - That finding's `recordId` is the scan-1 fact, and its `ordinal` is −1.
  - **Serialisation:** a scan and an import are serialised.
- [ ] **Step 2–4: fail → implement → pass.**
- [ ] **Step 5: Commit** `feat(scan): per-service watermarks; late-IOC re-check over stored DNS`

### Task C2: Correlation over facts

**Files:**
- Create: `sigma/TimelineAtom.kt`.
- Modify:
  - `sigma/SigmaRuleEngine.kt:125`: `computeAtomBindings(atoms): Map<AtomRef, Set<String>>`.
  - `sigma/SigmaCorrelationEngine.kt`: correlate over atoms; signal details carry `member_fact_ids`; `signal_member` rows are written.
  - `sigma/RuleCoverage.kt`: work over atoms.
  - Create `data/store/AtomReader.kt` with `atomsForScan(scanId, categories)` and `atomsBetween(since, until, categories)`.
    - Both return exact-precision facts only.
    - Both exclude facts referenced by a `forensic_timeline.recordId`, or whose `sourceKey` equals a row's `sourceEventKey` (both h128 BLOBs).
    - Visibility is `(state = 'COMPLETE' OR scanId = :current)`, allow-listed in the Q1 gate.
  - `ScanWriteRepository.finish`: read atoms outside the write transaction. For a live scan, lookback is bounded to `≤ scanStart` and excludes `BUGREPORT_IMPORT` and `INTRUSION_LOG_IMPORT`.
  - Every `member_event_ids` reader: `ui/timeline/TimelineClusters.kt:136-150`, `sigma/CorrelationFindings.kt`, `data/repo/ScanRepository.kt`, `scanner/ScanOrchestrator.kt`, `reporting/ReportFormatter.kt`, `data/db/ForensicTimelineEventDao.kt`.
- Test: `sigma/CorrelationOverFactsTest.kt` (K1 part 2), `sigma/MemberIdsConsumersGateTest.kt`.

**Interfaces:**
- `data class TimelineAtom(val ref: AtomRef, val category: String, val timestamp: Long, val packageName: String, val ruleId: String, val telemetrySource: TelemetrySource)`
- `sealed interface AtomRef : Comparable<AtomRef> { val kind: Int; val id: Long }`
- `data class Row(override val id: Long) : AtomRef { override val kind = 0 }`
- `data class Fact(override val id: Long) : AtomRef { override val kind = 1 }`
- Ordering is by `(kind, id)`.
- `signal_member` rows are deleted together with their signal row, by every delete path.

- [ ] **Step 1: Write the failing tests**
  - Mixed atoms: an `event_count` rule over 3 fact atoms plus 1 row atom fires once, and writes `signal_member` rows of both kinds.
  - Distinct ids: a row and a fact with the same numeric id bind separately.
  - No double binding:
    - A live DNS fact and its `ioc_match` row bind once.
    - An interim intrusion-log event row (carrying `recordId`) and its fact bind once, so `IntrusionLogClusterRegressionTest` still passes at the C2 commit.
  - Precision: day-precision facts never become atoms.
  - Lookback boundaries: lookback excludes bug-report facts and future-dated facts.
  - Gate: every `main` file that mentions `member_event_ids` also mentions `member_fact_ids`.
- [ ] **Step 2–4: fail → implement → pass.**
- [ ] **Step 5: Commit** `feat(sigma): correlation over fact atoms keyed by AtomRef; signal members`

### Task C3: Event rows only in the store; interim removed

**Files:**
- Modify `scanner/ScanOrchestrator.kt`:
  - Stop writing event rows to `forensic_timeline`. Delete the interim heaps for event rows; the findings top-K stays until D2.
  - Delete `deletePriorIntrusionLogRows`.
  - Delete `DNS_PERSIST_CAP`, `CONNECT_PERSIST_CAP` and `SECURITY_PERSIST_CAP`, along with their uses in `ui/bugreport/BugReportScreen.kt:307-322`.
  - Delete the bug-report `rawEvents` / `moduleForensicEvents`.
- Delete the event adapters in `data/db/TimelineAdapter.kt`.
- Delete timeline construction in `scanner/bugreport/{AdbKeysModule,AppOpsModule,BatteryDailyModule,InstallTimeModule}.kt`.
- Remove `ModuleResult.timeline` (`BugreportModule.kt`) and `timeline` (`BugReportAnalyzer.kt`).
- `ui/bugreport/*`: link to the Timeline filtered by scan.
- Delete `reporting/TimelineFormatter.kt` and `data/model/TimelineEvent.kt`.
- Create `data/db/LegacyEventRowCleanup.kt`, run once at the first launch after upgrade.
  - It deletes `forensic_timeline` rows whose `source` is in a frozen list of the retired event adapters' producers (`intrusion_log`, the bug-report module sources, `usage_stats`), for scans with `telemetryState IN ('STORED', 'PARTIAL_RETENTION')`.
  - It does not select by category. Live `package_install` / `device_admin_grant` detected-change rows therefore survive.
- Test: `scanner/EventRowsLiveInStoreTest.kt`, `data/db/LegacyEventRowCleanupTest.kt`.

- [ ] **Step 1: Write the failing tests**
  - Intrusion-log import: on a 7,000-event fixture, `forensic_timeline` gets only finding rows and signals, while the store gets 7,000 observations.
  - No usage rows: a live scan writes no `usage_stats` row.
  - Re-import: importing the same log twice gives one set of facts and two observation sets, with no event rows.
  - Legacy cleanup:
    - It deletes `STORED` scans' event rows and keeps `NONE` scans' rows.
    - A live `package_install` row from `InstallEventEmitter` in a `STORED` scan survives.
- [ ] **Step 2–4: fail → implement → pass.** Adapt `IntrusionLogClusterRegressionTest` and `IntrusionLogReportSectionTest`.
- [ ] **Step 5: Commit** `feat(timeline): event records read in place; legacy event rows cleaned; TimelineEvent retired`

### Task C4: `TimelineDao`, keyset union, counts

**Files:**
- Create:
  - `data/db/TimelineDao.kt`
  - `data/db/TimelineQueries.kt` (one builder per filter shape)
  - `data/model/TimelineRowEntity.kt`
  - `data/db/TimelineFilter.kt`
  - `ui/timeline/TimelinePagingSource.kt`, which extends `KeysetPagingSource` and keys on `(time, rowKind, id)`.
    - In Phase C it observes `ScanResult` and `forensic_timeline`.
    - D2 adds `alert`, because that table does not exist before schema 20.
- Modify:
  - `data/db/ForensicTimelineEventDao.kt`: delete the six read queries.
  - `ui/timeline/TimelineViewModel.kt`, `TimelineRow.kt` (`EventRow`), `TimelineScreen.kt`.
  - `reporting/TimelineExporter.kt`: stream the export, keeping the CSV guard.
- Test: `ui/timeline/TimelineUncappedTest.kt` (T1), `data/db/TimelineQueryPlanTest.kt`, `scanner/NoPersistenceCapsGateTest.kt` (C1, Phase C allow-list).

**Interfaces:**
- `TimelineRowEntity`: rowKind, id, scanId, time, category, packageName, level, ruleId, correlationId, kind, telemetrySource, bodyHash.
- `TimelineFilter`: scanId, packageName, source, from, to, levels, findingsAndEvidenceOnly, zone (`ZoneId`).
- The fact branch applies the spec §5.1 visibility rule: there is a `COMPLETE` observation, or no observation at all. With a scan filter, it reads through `scan_record(scanId, eventTime)`.
- The row branch shows rows with `persistent = 1`, rows with `scanResultId = -1`, or rows whose scan is `COMPLETE`.

- [ ] **Step 1: Write the failing tests**
  - **T1 (100,000 event facts plus 50 finding rows):**
    - Every row pages, and the count shows 100,050.
    - No row is duplicated, and evidence is nested.
    - No captured SQL contains `OFFSET`.
    - Scroll position survives an invalidation.
    - An `IN_PROGRESS` import's facts and finding rows are absent.
    - Severity filtering by `HIGH` returns exactly the writer-produced `HIGH` finding rows.
  - **Low heap:** correlation over 5,000 `permission_use` facts completes, in `TimelineCorrelationLowHeapTest`, which `lowHeapTest` runs.
  - **Query plan:** for every filter shape, no `USE TEMP B-TREE` and no full scan.
  - **C1:**
    - The regex `_PERSIST_CAP|_ROW_LIMIT|\bLIMIT\s+\d+|limit:\s*Int\s*=\s*\d+` finds nothing beyond the Phase C allow-list.
    - The allow-list is `getLatestTwo`, `IndicatorDao.lookup`, `DnsEventDao.getRecentEvents`/`getRecentSnapshot`, `FINDINGS_PERSIST_CAP` and `ScanResultDao.getAllScans`.
- [ ] **Step 2–4: fail → implement → pass.**
- [ ] **Step 5: Commit** `feat(timeline): keyset-paged union of visible event facts and timeline rows`
- [ ] **Step 6:** Open Phase C PR `feat/telemetry-store-c`. Battery:
  - Scan twice.
  - Import an intrusion log twice.
  - Kill the app mid-import and relaunch.
  - Open a Timeline of 20,000+ rows.

---

## Phase D — Findings, alerts, lifecycle, retention (PR 4)

### Task D1: Protected confirmation

**Files:**
- Create `ui/security/ConfirmCredential.kt`. It takes an injected `sdkInt: Int` and a `KeyguardManager`.
  - API 30+: platform `BiometricPrompt` with `setAllowedAuthenticators(DEVICE_CREDENTIAL)`.
  - API 26–29: `KeyguardManager.createConfirmDeviceCredentialIntent`.
  - Returns `Confirmed | NoSecureLock | Cancelled`. `NoSecureLock` only when `!isDeviceSecure()`; any error is `Cancelled`.
- Modify `AndroidManifest.xml`: add `USE_BIOMETRIC`.
- Create `ui/security/ProtectedButton.kt`. It sets `filterTouchesWhenObscured = true` on the host view via `LocalView`, and documents that accessibility clicks bypass it.
- Test: `ui/security/ConfirmCredentialTest.kt`, `ui/security/ProtectedButtonTest.kt` (`ui-test-junit4` added to `testImplementation`).

- [ ] **Step 1: Write the failing tests**
  - Routing: with `sdkInt = 30` the BiometricPrompt path runs; with `sdkInt = 28` the Keyguard path runs.
  - `isDeviceSecure() == false` returns `NoSecureLock`.
  - A thrown error returns `Cancelled`.
  - The host view has `filterTouchesWhenObscured` set.
- [ ] **Step 2–4: fail → implement → pass.**
- [ ] **Step 5: Commit** `feat(ui): device-credential confirmation; obscured-touch filtering`

### Task D2: `scan_finding`, `alert`, migration 19→20, caps removed

**Files:**
- Create:
  - `data/model/{ScanFinding,Alert,AlertMember,FindingKind,AlertStatus,ScanWithFindings}.kt`
  - `data/db/{ScanFindingDao,AlertDao}.kt`
  - `data/db/FrozenRuleServices.kt`
  - `data/repo/FindingsRepository.kt`, `data/repo/AlertIdentity.kt`
- Schema:
  - `Migrations.kt`: `MIGRATION_19_20`.
  - `AppDatabase.kt`: `version = 20`.
  - `ScanResult.kt`: drop `findings`; add `triggeredCount` and `maxLevel`.
  - `ScanResultDao.kt`: add `latestLive()` and `pagedAfter(afterTimestamp, size)`; delete `getAllScans`.
- Writer (`ChunkedScanWriter`):
  - The session writes `scan_finding` rows per chunk, carrying `alertKey`, for newly observed ordinals only.
  - Inside its single finishing transaction, `finish` does three things:
    - writes this scan's `forensic_timeline` finding rows with `INSERT … SELECT … FROM scan_finding WHERE scanId = ? AND triggered`;
    - creates alerts set-based and attaches them, with the post-condition that no `alertKey` is left unattached;
    - runs correlation through `FindingsRepository.recordCorrelation`.
  - This scan's finding atoms are read from `scan_finding`.
- Pins: `TelemetryFactDao.deleteUnobservedUnpinned` also excludes facts referenced by triggered `scan_finding.recordId`, by `alert.recordId`, and by `alert_member` fact refs.
- `ScanOrchestrator.kt`:
  - Delete `FINDINGS_PERSIST_CAP`, `capTriggeredFindings`, the findings top-K and the caps log.
  - Delete the remaining cap references at `BugReportScreen.kt:334` and in the KDoc at `IntrusionLogAnalyzer.kt:42`.
  - `computeDiff(ScanWithFindings, ScanWithFindings)`.
- Consumers:
  - `DashboardViewModel` (count plus a paged list)
  - `DeviceAuditViewModel`, `AppScanViewModel`, `BugReportViewModel`
  - `HistoryViewModel` / `HistoryScreen` (keyset paging)
  - `TimelineViewModel`
  - `reporting/FindingsView.kt`
- Tests: replace `ScanResult(findings = …)` with `scanWith(findings)` in the 16 test files that use it.
- Test: `data/db/Migration19To20Test.kt` (F1 and Review Focus 4), `data/repo/FindingLifecycleTest.kt` (L1), `data/repo/FindingRecordRefTest.kt` (F2), `scanner/NoPersistenceCapsGateTest.kt` (C1 final).

**Interfaces:**
- Entities: as in spec §5.4. That includes `alert.lastActivityAt`, `evidenceJson`, `memberCount` and `truncatedBelow`.
  - `alert.id` is AUTOINCREMENT, and `alertKey` is unique.
  - Indices: `alert(ruleId, groupKey, status)`, `alert(recordId)`, `alert_member(kind, refId)`, `scan_finding(scanId)`, `scan_finding(recordId)`, `scan_finding(scanId, alertKey)`.
- `AlertIdentity`:
  - `fun recordKey(ruleId: String, factId: Long, evidence: Evidence): ByteArray` = `h128("$ruleId|$factId|${evidence.type}|${evidence.matchedValue}")`.
  - `suspend fun resolveCorrelation(ruleId: String, groupKey: String, members: List<AtomRef>, openingScanId: Long): Long`:
    - A ref counts as a member of an alert if it is in `alert_member` or is ≤ `truncatedBelow`.
    - If the members overlap an OPEN alert, it joins that alert and updates `lastActivityAt`.
    - Otherwise, if the members are a subset of a CLOSED alert's members, it attaches there.
    - Otherwise it creates a new alert:
      - keyed `h128("$ruleId|$groupKey|$openingScanId|${members.min()}")`;
      - stores the newest 1,000 members, setting `memberCount` and `truncatedBelow`;
      - copies the opening finding into `evidenceJson`;
      - sets `persistent = 1` on every `Row` member's `forensic_timeline` row.
  - Record alerts also copy the opening finding into `evidenceJson`.
- `FindingsRepository`:
  - `recordChunk(scanId, findings, factIdByOrdinal, isEventByOrdinal)`
  - `createAlertsForScan(scanId)` (set-based)
  - `recordCorrelation(scanId, findings, members)`
  - `current(): Flow<CurrentFindingsSummary>`
  - `openAlerts(): Flow<PagingData<AlertView>>`
  - `forScan(scanId): Flow<PagingData<Finding>>`
  - `close(alertIds: List<Long>, reason: String?, result: CredentialResult)`
- `CurrentFindingsSummary(stateFindings: List<Finding>, openAlertCount: Int)`. `stateFindings` is bounded by rules × live records.
- `findingJson` drops `matchContext` only when `recordId != null`. Untriggered rows are stored only for snapshot services.
- Migration 19→20 follows spec §5.4:
  - `substr` reads and a table rebuild;
  - summary and `level` backfill;
  - per-record kind, with `recordId` resolution preferred over `(scanId, service, ordinal)`;
  - alerts created OPEN within 30 days, with `evidenceJson` set;
  - `matchContext` kept.

- [ ] **Step 1: Write the failing tests**
  - **F1 (migration):**
    - 1,200 findings, plus a corrupt row and a 3 MB row: all scans survive.
    - `triggeredCount` and `maxLevel` are backfilled.
    - A schema-19 live app-ops finding is STATE.
    - DNS findings become ALERTs: OPEN at 10 days old, CLOSED at 40 days.
    - Migrated findings keep `matchContext`.
    - A Phase C late-IOC re-check finding migrates to its own fact and alert key, through `recordId`.
  - **L1 (lifecycle):**
    - A state finding follows the latest live scan and survives an import.
    - An alert persists until closed.
    - Import B attaches to A's alert and keeps its own `scan_finding` row.
    - Correlation chains: {a,b,c} → {a,b,c,d} joins the OPEN alert. Closing {P1,D1} and then seeing {P1,D2} opens a new alert. {P1} ⊂ a closed alert attaches without reopening.
    - Two evidence results yield two alerts.
    - The evidence discriminator is unchanged after an IOC re-sync.
    - Correlation member facts survive 31 days of live-event retention and the deletion of the import, and they still decode through `TelemetryReader`.
    - A closed 1,500-member chain whose window slides with no new facts opens no new alert.
    - A killed mid-import leaves 0 alerts.
  - **F2:** `recordId` resolves for every service.
  - **Query plan:** the extended `deleteUnobservedUnpinned`, the alert insert and attach, the `INSERT … SELECT` of finding rows, and the summary queries all use indices (`EXPLAIN QUERY PLAN`).
  - **C1:** the allow-list is reduced to the permanent four.
- [ ] **Step 2–4: fail → implement → pass.**
- [ ] **Step 5: Commit** `feat(findings): per-scan findings, lasting alerts, migration 19→20; caps removed`

### Task D3: Alerts UI; audited deletion

**Files:**
- Modify `ui/dashboard/DashboardScreen.kt` and `DashboardViewModel.kt`:
  - An open-alerts card with a paged list, multi-select, and Close / Close selected, each going through `ConfirmCredential` then `FindingsRepository.close`.
  - Use `ProtectedButton`.
- Modify `ui/timeline/TimelineEventCard.kt`: add Close on alert rows.
- Modify `data/repo/ScanRepository.kt`:
  - `deleteScan` deletes `scan_finding` rows, observations, and non-persistent `forensic_timeline` rows of the scan (together with their `signal_member` rows). It never deletes alerts or persistent rows.
    - It writes a persistent audit row (`category = "scan_deleted"`, `persistent = 1`) that lists the deleted triggered findings (rule, level, package).
  - `deleteAllScans` deletes scans, observations, `scan_finding` rows, and non-persistent scan-owned `forensic_timeline` rows (with their `signal_member` rows), then writes one persistent audit row.
  - The `abort` and `StartupSweep` cleanup paths use a separate, unaudited delete.
- Modify `FindingsRepository.close`:
  - Re-check `isDeviceSecure()` when given `NoSecureLock`.
  - Set `closedWithCredential`.
  - Write an `alert_closed` row with `persistent = 1`.
- The open-alert list groups alerts by rule and matched value, and re-surfaces alerts by `lastActivityAt`.
- Modify `reporting/ReportFormatter.kt`: FINDINGS lists state, open and closed alerts.
- Add the new UI strings to `res/values/strings.xml`.
- Test: `data/repo/AlertCloseTest.kt` (L2), `ui/dashboard/DashboardAlertsViewModelTest.kt`.

- [ ] **Step 1: Write the failing tests**
  - L2 — confirmation:
    - Close and bulk close do nothing without `Confirmed`.
    - `NoSecureLock` while `isDeviceSecure()` is true is refused.
  - L2 — deletion:
    - Deleting a scan keeps its alert and writes an audit row that lists the scan's triggered findings.
    - "Clear all" keeps alerts, closure rows and audit rows.
    - After deleting a correlation alert's opening scan, and again after "Clear all", these still hold:
      - every `alert_member` ref resolves (its `Row` members are persistent);
      - every pinned fact decodes;
      - `alert.evidenceJson` is present.
  - Report: lists closed alerts with their credential flag.
- [ ] **Step 2–4: fail → implement → pass.**
- [ ] **Step 5: Commit** `feat(ui): open alerts with credential-protected close and bulk close; audited deletion`

### Task D4: Retention

**Files:**
- Create: `data/store/TelemetryRetention.kt`.
- Modify:
  - `ioc/IocUpdateWorker.kt:28-31`: run retention after the IOC fetch. Each keyset batch takes `scanMutex.tryLock()`; if the lock is held, retention stops for this cycle.
  - `data/repo/SettingsRepository.kt`: add `snapshotRetentionScans` (default 20).
  - `ScanResultDao`: add `setTelemetryState`.
  - `ForensicTimelineEventDao.kt:112-113`: the prune deletes only rows that meet all of these:
    - `telemetrySource = 'LIVE_SCAN'`;
    - `persistent = 0`;
    - no `signal_member` row ref points at them.
    This applies whatever their `scanResultId`, so live `ioc_match` rows are trimmed again.
- Test: `data/store/TelemetryRetentionTest.kt`, `data/db/PruneExemptionsTest.kt` (P1).

- [ ] **Step 1: Write the failing tests**
  - Snapshot retention: with 25 live scans, 2 imports and N = 20, the newest 20 keep snapshots and the older 5 are `PARTIAL_RETENTION`.
  - Live-event retention: live events older than 30 days are trimmed, and their scans are marked `PARTIAL_RETENTION`.
  - Kept data: imports stay untouched, and pinned facts (findings, alerts, alert and signal members, timeline refs) survive.
  - Lock skip: retention skips the cycle while a scan holds `scanMutex`.
  - P1: import rows, persistent rows (closure, audit, alert evidence) and rows referenced by `signal_member` survive the prune.
  - P2: a 31-day-old live `ioc_match` row with `scanResultId = -1` is pruned.
- [ ] **Step 2–4: fail → implement → pass.**
- [ ] **Step 5: Commit** `feat(store): retention — snapshots by scan count, live events by age, pins respected`
- [ ] **Step 6:** Open Phase D PR `feat/telemetry-store-d`. Battery:
  - Scan twice and confirm there are no duplicate alerts.
  - Import an intrusion log that has more than 1,000 findings.
  - Close and bulk-close alerts through the credential prompt.
  - Delete a scan and confirm its alert survives.

---

## Phase E — Browser, settings, export, vocabulary (PR 5)

### Task E1: Telemetry browser

**Files:**
- Create `ui/telemetry/{TelemetryBrowserViewModel,TelemetryServicesScreen,TelemetryRecordsScreen,SubjectHistorySheet}.kt`.
- Modify `MainActivity.kt` to add the routes `telemetry/{scanId}`, `telemetry/{scanId}/{service}` and `fact/{factId}`.
- Modify `ui/history/HistoryScreen.kt` and `ui/timeline/TimelineScreen.kt` to add "View telemetry" and "Matched record", both navigating by `recordId`.
- Add strings. Field order and descriptions come from `TaxonomyContract`.

**Test** (`ui/telemetry/TelemetryBrowserViewModelTest.kt`):
- the services list;
- keyset paging;
- debounced search narrows the list by package;
- unreadable bodies;
- subject history highlights changed keys;
- `IN_PROGRESS` scans are not listed.

- [ ] **Step 1–4: fail → implement → pass.**
- [ ] **Step 5: Commit** `feat(ui): telemetry browser with subject history`

### Task E2: Settings and JSONL export

**Files:**
- `ui/settings/SettingsScreen.kt` and `SettingsViewModel.kt`:
  - storage by kind;
  - a retention slider from 5 to 100 (default 20);
  - "Delete old snapshot telemetry now".
- `ui/history/HistoryViewModel.kt` and `HistoryScreen.kt` get "Export telemetry (JSONL)":
  - the estimate dialog;
  - `TelemetryReader.exportJsonl(scanId, Writer)` streamed through `GZIPOutputStream` into `cache/reports/`.
- `data/store/TelemetryReader.kt`: add `exportJsonl`.

**Test:** `ui/settings/TelemetrySettingsViewModelTest.kt`, `ui/history/TelemetryExportTest.kt`. The export test checks:
- the export streams;
- stale files are removed;
- each observation becomes one envelope;
- envelope keys are restored.

- [ ] **Step 1–4: fail → implement → pass.**
- [ ] **Step 5: Commit** `feat(ui): telemetry storage settings and JSONL export`

### Task E3: Vocabulary gate and glossary

**Files:**
- `docs/ARCHITECTURE.md`:
  - a Glossary with spec §3's table, verbatim;
  - in §5.1, rows for `record_body`, `telemetry_record`, `scan_record`, `signal_member`, `scan_finding`, `alert`, `alert_member` and `event_watermark`;
  - in §5.2, retention;
  - in §6.3, remove `TimelineFormatter`.
- `reporting/ReportExporter.kt:29-33`: update the comments.
- Remaining UI copy.

**Test** (`app/src/test/java/com/androdr/VocabularyGateTest.kt`, V1):
- No "raw telemetry" or "informational telemetry" (case-insensitive), and no `class TimelineEvent\b`, in `main` Kotlin, `res/values` or `docs/*.md` (excluding `docs/superpowers/`).
- ARCHITECTURE's glossary lists all ten terms.

- [ ] **Step 1–4: fail → fix → pass.**
- [ ] **Step 5: Commit** `docs: telemetry glossary; vocabulary gate`
- [ ] **Step 6:** Open the Phase E PR. Run the full release battery per spec §9, and update `STORED_SIZE_FACTOR` if the measured value differs by more than 20%.

---

## Self-review notes

**Spec coverage:**

| Spec section | Tasks |
|---|---|
| §3 | E3 |
| §4.1 | A2, A3, A7, 0.2 |
| §4.2 | 0.1 |
| §4.3 | 0.2, C2 |
| §5.1 | A3, A4, A5, D2, D4 |
| §5.2 | A7, C1, C2 |
| §5.3 | A6, C3 |
| §5.4 | D1–D3 |
| §5.5 | C3, C4, D2 |
| §5.6 | D4 |
| §6 | C2, C4, E1 |
| §7 | B1, D3, E2 |
| §8 | E1, E2 |

**Gates:**

| Gates | Tasks |
|---|---|
| S1, S2, S4 | A5 |
| S3, ST1, M1 | A7 |
| S5, S6 | A3 |
| S7 | A7 (`appendAll` uses `constrainOnce`) |
| E1 | A2 + A7 |
| E2, D1, X1 | 0.2 |
| K1 | 0.2 + C2 |
| W1 | C1 |
| R1–R3 | B1 |
| B1 | A6 + A7 |
| C1 | C4 + D2 |
| T1 | C4 |
| F1, L1 | D2 |
| F2 | A7 + D2 |
| L2 | D3 |
| P1 | D4 |
| Q1 | A1 + A5 |
| V1 | E3 |

**Ordering:**
- Phase 0 lands before the first stored record.
- A6 lands before C3.
- C1 and C2 land before D2, so alert keys are fact-based.
- C3 and C4 ship in one PR.
- `FINDINGS_PERSIST_CAP` stays until D2.
- Retention (D4) lands after finding pins (D2).
- Schema 19 already carries every column and index that Phase C reads.
