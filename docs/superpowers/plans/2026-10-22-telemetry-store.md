# Telemetry Store, Uncapped Timeline, Finding Lifecycle Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Persist every telemetry record a scan or import produces, remove every persistence cap, read the Timeline as a paged union with no duplicated event rows, give findings a SOC-style lifecycle, and make the telemetry vocabulary precise and gated.

**Architecture:** Telemetry records are stored as their `toFieldMap()` JSON in SQLite (`telemetry_record` rows referencing content-deduped `record_body` rows; event bodies Deflate-compressed with a preset dictionary). Findings move from a JSON column to `scan_finding` rows with `kind`/`status`. Live event emitters collect from per-service watermarks so an event is observed by one scan. The Timeline pages a `UNION ALL` of event records (read in place) and `forensic_timeline` rows (finding rows, correlation signals, detected changes). Every report reads only its own scan's records through one `ReportExporter` path.

**Tech Stack:** Kotlin, Room 2.6.1 (+ `room-paging` 2.6.1), AndroidX Paging 3.3.6 (+ `paging-compose`), Jetpack Compose, Hilt, kotlinx.serialization, SQLite JSON1, `java.util.zip.Deflater`, Robolectric 4.14.1 + `androidx.test:core` 1.6.1 for JVM Room tests, snakeyaml-engine 2.7 (already present).

**Spec:** `docs/superpowers/specs/2026-10-22-telemetry-store-design.md`

## Global Constraints

- JDK 21 (CLAUDE.md). Gates: `./gradlew testDebugUnitTest`, `./gradlew detekt`, `./gradlew lintDebug`; CI runs `assembleDebug test` and `lintDebug detekt` (`.github/workflows/ci.yml`). Instrumented tests do not gate merges — every gate in this plan is a JVM unit test.
- Every fix lands *with* a deterministic test that fails on the original mistake (CLAUDE.md Regression policy).
- New dependencies are version-pinned exactly; no `@latest`, no new native library, no new SQLite build (spec §2 non-goals).
- No `_PERSIST_CAP`, `_ROW_LIMIT`, or literal `LIMIT <n>` in any DAO outside the C1 allow-list (spec §5.5, §9 C1).
- Event records are never copied into `forensic_timeline` (spec anti-goal 4).
- `ReportFormatter` is called only from `ReportExporter` (spec §7, gate R2).
- No type or field named after its source (`BugReportX`, `ImportedY`); taxonomy field names are `snake_case` (spec §3).
- Retired phrases in `main` source, `res/values`, and `docs/*.md`: "raw telemetry", "informational telemetry", class `TimelineEvent` (spec §3, gate V1).
- Taxonomy edits follow CLAUDE.md safe ordering: rules-repo branch → bump AndroDR submodule to that commit → green `LogsourceTaxonomyCrossCheckTest` + `DetectionFieldCrossCheckTest` → merge rules branch → re-point submodule. Positive-reference-only fleet rule for new fields.
- Each phase (A–E) is one PR to `main` and leaves the app working on its own. Branch names `feat/telemetry-store-<phase>`.
- detekt thresholds (`config/detekt.yml`): `TooManyFunctions` 15 per class/object, `LongParameterList` 13. Split files rather than suppress.

## Review Focus

1. A record whose field map holds a value JSON cannot carry (NaN, `ByteArray`, a nested `Map`) — canonical JSON must encode it deterministically, never throw. Pinned in Task 3.
2. Usage access revoked between scans — a collection that *failed* (SecurityException) must not advance the watermark, while a collection that genuinely saw nothing must. Pinned in Task 17.
3. A device clock that jumped forward produces an event with `eventTime` in the future — the watermark must be capped at the scan's `untilMs`, or later real events are skipped forever. Pinned in Task 17.
4. A `ScanResult` whose `findings` JSON is corrupt during migration 19→20 — the scan row must survive with zero findings rather than abort the migration and brick the app. Pinned in Task 11.
5. An API 26 device whose SQLite lacks JSON1 — `json_extract` queries would fail at runtime; a probe at database open must detect it and the cross-scan features degrade with a visible message, not a crash. Pinned in Task 4 (JVM probe) and the release battery (API 26 emulator).

---

## Phase A — Store foundations (PR 1)

After Phase A the app writes every record of every scan and import into the store and nothing reads it yet. All existing behaviour is unchanged.

### Task 1: JVM Room test harness

**Files:**
- Modify: `gradle/libs.versions.toml` (versions `robolectric = "4.14.1"`, `androidxTestCore = "1.6.1"`, `paging = "3.3.6"`; libraries `robolectric`, `androidx-test-core`, `androidx-room-paging` (group `androidx.room`, name `room-paging`, version.ref `room`), `androidx-paging-runtime`, `androidx-paging-compose`)
- Modify: `app/build.gradle.kts` (`testImplementation(libs.robolectric)`, `testImplementation(libs.androidx.test.core)`, `implementation(libs.androidx.room.paging)`, `implementation(libs.androidx.paging.runtime)`, `implementation(libs.androidx.paging.compose)`; `testOptions.unitTests.isIncludeAndroidResources = true`)
- Create: `app/src/test/java/com/androdr/data/db/RoomTestDb.kt`
- Test: `app/src/test/java/com/androdr/data/db/RoomJvmHarnessTest.kt`

**Interfaces:**
- Produces: `object RoomTestDb { fun inMemory(): AppDatabase }` — Robolectric `ApplicationProvider.getApplicationContext()`, `Room.inMemoryDatabaseBuilder(...).allowMainThreadQueries().build()`; `fun migrationHelper(): MigrationTestHelper` over `AppDatabase::class.java` with `app/schemas` as the asset folder.

- [ ] **Step 1: Write the failing test**

```kotlin
@RunWith(RobolectricTestRunner::class)
class RoomJvmHarnessTest {
    @Test fun `in-memory AppDatabase round-trips a ScanResult on the JVM`() = runTest {
        val db = RoomTestDb.inMemory()
        db.scanResultDao().insert(ScanResult(id = 1L, timestamp = 1L, findings = emptyList(),
            bugReportFindings = emptyList(), riskySideloadCount = 0, knownMalwareCount = 0))
        assertEquals(1, db.scanResultDao().getLatestTwo().size)
    }
    @Test fun `JSON1 is available in the test SQLite`() {
        val db = RoomTestDb.inMemory()
        db.openHelper.readableDatabase.query("SELECT json_extract('{\"a\":1}', '$.a')").use {
            it.moveToFirst(); assertEquals(1, it.getInt(0))
        }
    }
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `./gradlew testDebugUnitTest --tests "com.androdr.data.db.RoomJvmHarnessTest"`
Expected: compilation failure — `RobolectricTestRunner`, `RoomTestDb` unresolved.

- [ ] **Step 3: Add the dependencies and `RoomTestDb`**

Pin exactly the versions above. Robolectric 4.14.1 runs SQLite in native mode with JSON1 built in.

- [ ] **Step 4: Run to verify it passes**

Run: same command. Expected: 2 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add gradle/libs.versions.toml app/build.gradle.kts app/src/test/java/com/androdr/data/db/RoomTestDb.kt app/src/test/java/com/androdr/data/db/RoomJvmHarnessTest.kt
git commit -m "test: JVM Room harness (Robolectric) and paging dependencies"
```

### Task 2: Findings reference the record they matched

**Files:**
- Modify: `app/src/main/java/com/androdr/sigma/SigmaRuleEvaluator.kt:23-45` (`Finding`), `:135-215` (`evaluate`, `buildFinding`)
- Test: `app/src/test/java/com/androdr/sigma/FindingRecordOrdinalTest.kt`

**Interfaces:**
- Produces: `Finding.service: String = ""`, `Finding.recordOrdinal: Int = -1` — the index of the matched record in the `records` list `evaluate()` received. Correlation findings (`SigmaCorrelationEngine.findingsFor`) keep the defaults.

- [ ] **Step 1: Write the failing test** — build a `SigmaRule` for service `app_scanner` matching `package_name: com.b` (use the existing test rule fixtures in `app/src/test/java/com/androdr/sigma/`), call `SigmaRuleEvaluator.evaluate(listOf(rule), listOf(mapOf("package_name" to "com.a"), mapOf("package_name" to "com.b")), "app_scanner")`; assert the single finding has `recordOrdinal == 1` and `service == "app_scanner"`; a `reportSafeState` rule's untriggered finding on record 0 has `recordOrdinal == 0`.

- [ ] **Step 2: Run to verify it fails** — `--tests "com.androdr.sigma.FindingRecordOrdinalTest"`; expected: unresolved `recordOrdinal`.

- [ ] **Step 3: Implement** — iterate `records.forEachIndexed`; `buildFinding(rule, category, triggered, record, evidenceResult, service, ordinal)` sets both fields. `Finding` is `@Serializable`; defaults keep old `ScanResult.findings` JSON decodable.

- [ ] **Step 4: Run to verify it passes**, then run `./gradlew testDebugUnitTest --tests "com.androdr.sigma.*"` — `PureEmitterContractTest` must still pass (construction stays inside `buildFinding`).

- [ ] **Step 5: Commit** — `feat(sigma): findings carry service and record ordinal`

### Task 3: Record codec — canonical JSON, hash, dictionary Deflate

**Files:**
- Create: `app/src/main/java/com/androdr/data/store/TelemetryRecordCodec.kt`
- Create: `app/src/main/java/com/androdr/data/store/TelemetryDictionaryBuilder.kt`
- Create: `app/src/main/res/raw/telemetry_dictionary_v1.txt`
- Test: `app/src/test/java/com/androdr/data/store/TelemetryRecordCodecTest.kt`, `app/src/test/java/com/androdr/data/store/TelemetryDictionaryTest.kt`

**Interfaces:**
- Produces:
  ```kotlin
  class TelemetryRecordCodec(private val dictionary: ByteArray) {
      fun canonicalJson(fields: Map<String, Any?>): String      // keys sorted, kotlinx JsonObject, stable
      fun hash(canonical: String): String                        // SHA-256 hex, lowercase
      fun encode(canonical: String, encoding: Int): ByteArray    // ENCODING_PLAIN → UTF-8; ENCODING_DEFLATE_DICT_V1 → Deflater(BEST_COMPRESSION) with setDictionary
      fun decode(body: ByteArray, encoding: Int): Map<String, Any?>
      companion object { const val ENCODING_PLAIN = 0; const val ENCODING_DEFLATE_DICT_V1 = 1 }
  }
  object TelemetryDictionaryBuilder {
      const val MAX_BYTES = 32_768
      fun build(fieldNames: Collection<String>, vocabulary: Collection<String>): ByteArray  // sorted distinct, '\n'-joined, truncated to MAX_BYTES
  }
  ```
- Hilt: `@Provides fun provideTelemetryRecordCodec(ctx)` in `di/AppModule.kt` reading `R.raw.telemetry_dictionary_v1`.

- [ ] **Step 1: Write the failing tests**

`TelemetryRecordCodecTest`:
- `canonical JSON is key-sorted and independent of map order` — two maps with the same entries in different order → equal strings and equal hashes.
- `values JSON cannot carry are encoded deterministically` — `Double.NaN` → `"NaN"` string, `ByteArray` → base64 string, nested `Map` → nested object, `List` → array; no exception (Review Focus 1).
- `plain and deflate encodings round-trip` — `decode(encode(c, e), e)` equals the original map for 50 generated records.
- `dictionary deflate compresses repetitive event records at least 4x` — 1,000 synthetic `dns_monitor` records (random hostnames under 20 TLDs, `source`, `timestamp`); `sum(encoded) * 4 <= sum(raw)`.

`TelemetryDictionaryTest`:
- `shipped dictionary equals the builder output` — `build(fieldNames = all `fields:` keys parsed from `third-party/android-sigma-rules/validation/logsource-taxonomy.yml` (reuse the taxonomy loader in `LogsourceTaxonomyCrossCheckTest`), vocabulary = `SecurityLogTagRegistry` tag names + `AppScanner.EXPOSED_PERMISSION_SHORT_NAMES`)` byte-equals `res/raw/telemetry_dictionary_v1.txt`.
- `dictionary is under 32 KiB`.

- [ ] **Step 2: Run to verify they fail** — `--tests "com.androdr.data.store.*"`.

- [ ] **Step 3: Implement the codec and builder; generate the dictionary** by running the builder once from a throwaway test and writing the bytes to the resource (then delete the throwaway).

- [ ] **Step 4: Run to verify they pass.**

- [ ] **Step 5: Commit** — `feat(store): telemetry record codec with content hash and dictionary deflate`

### Task 4: Store entities, DAOs, migration 18→19, JSON1 probe

**Files:**
- Create: `app/src/main/java/com/androdr/data/model/TelemetryRecord.kt`, `RecordBody.kt`, `EventWatermark.kt`
- Create: `app/src/main/java/com/androdr/data/db/TelemetryRecordDao.kt`, `EventWatermarkDao.kt`
- Modify: `app/src/main/java/com/androdr/data/db/Migrations.kt` (append `MIGRATION_18_19`), `AppDatabase.kt` (entities, `version = 19`, two DAO accessors), `di/AppModule.kt` (register migration where the others are; provide both DAOs), `app/schemas/com.androdr.data.db.AppDatabase/19.json` (generated by KSP on build)
- Create: `app/src/main/java/com/androdr/data/db/Json1Probe.kt`
- Test: `app/src/test/java/com/androdr/data/db/Migration18To19Test.kt`, `TelemetryRecordDaoTest.kt`, `Json1ProbeTest.kt`

**Interfaces:**
- Produces entities (spec §5.1):
  ```kotlin
  @Entity(tableName = "record_body")
  data class RecordBody(@PrimaryKey val hash: String, val encoding: Int, val body: ByteArray, val rawBytes: Int)

  @Entity(tableName = "telemetry_record",
      indices = [Index("scanId","service"), Index("packageName"), Index("eventTime"), Index("category"),
                 Index(value = ["service","eventKey"], unique = true)],
      foreignKeys = [ForeignKey(RecordBody::class, ["hash"], ["bodyHash"])])
  data class TelemetryRecord(@PrimaryKey(autoGenerate = true) val id: Long = 0, val scanId: Long, val service: String,
      val ordinal: Int, val source: TelemetrySource, val capturedAt: Long, val packageName: String?,
      val eventTime: Long?, val eventKey: String?, val category: String?, val summary: String?, val bodyHash: String)

  @Entity(tableName = "event_watermark")
  data class EventWatermark(@PrimaryKey val service: String, val eventTime: Long, val scanId: Long)
  ```
  `category` and `summary` are filled for event records only (Task 6).
- `TelemetryRecordDao`: `insertRecords(List<TelemetryRecord>): List<Long>` (`OnConflictStrategy.IGNORE`), `insertBodies(List<RecordBody>)` (IGNORE), `countFor(scanId, service): Int`, `serviceSummaries(scanId): List<ServiceSummary>` (`service, COUNT(*) AS recordCount, SUM(b.rawBytes) AS rawBytes, SUM(LENGTH(b.body)) AS storedBytes` joined), `pageFor(scanId, service): PagingSource<Int, TelemetryRecordWithBody>` (ordered by `ordinal`), `byId(id): TelemetryRecordWithBody?`, `history(packageName, service): Flow<List<TelemetryRecordWithBody>>` (ordered `scanId DESC`), `forScanAndService(scanId, service, offset, limit): List<TelemetryRecordWithBody>` (parameterized — not a literal LIMIT), `hashesFor(scanId, service): List<Pair<String,String>>` (`packageName, bodyHash`), `deleteForScan(scanId)`, `deleteUnreferencedBodies()`, `storageByKind(): StorageSummary` (sum of body bytes where `eventTime IS NULL` / `IS NOT NULL` / `source != LIVE_SCAN`).
- `EventWatermarkDao`: `get(service): EventWatermark?`, `upsert(EventWatermark)`.
- `data class TelemetryRecordWithBody(@Embedded val record: TelemetryRecord, @Relation(parentColumn="bodyHash", entityColumn="hash") val body: RecordBody)`
- `data class ServiceSummary(val service: String, val recordCount: Int, val rawBytes: Long, val storedBytes: Long)`; `data class StorageSummary(val snapshotBytes: Long, val liveEventBytes: Long, val importBytes: Long)`
- `object Json1Probe { fun isAvailable(db: SupportSQLiteDatabase): Boolean }` — runs `SELECT json_extract('{"a":1}','$.a')`, false on `SQLiteException`. `AppDatabase.json1Available: Boolean` set in a `RoomDatabase.Callback.onOpen`.

- [ ] **Step 1: Write the failing tests**

`Migration18To19Test` (Robolectric, `RoomTestDb.migrationHelper()`): create version 18, run `MIGRATION_18_19`, assert tables `telemetry_record`, `record_body`, `event_watermark` exist with the indices above (query `sqlite_master`), and `validateMigration` succeeds against schema 19.

`TelemetryRecordDaoTest` (Robolectric):
- `insert with IGNORE returns -1 for a duplicate event key`.
- `serviceSummaries sums raw and stored bytes per service`.
- `pageFor returns records in ordinal order` (load page via `PagingSource.load(Refresh(key=null, loadSize=10, ...))`).
- `deleteUnreferencedBodies keeps a body another scan references`.

`Json1ProbeTest`: `isAvailable` true on the harness DB; false on a mock `SupportSQLiteDatabase` whose `query` throws `SQLiteException`.

- [ ] **Step 2: Run to verify they fail.**

- [ ] **Step 3: Implement entities, DAOs, migration SQL, version bump, Hilt providers, probe.** Build once so KSP exports `19.json`; commit the schema.

- [ ] **Step 4: Run to verify they pass**; also `./gradlew testDebugUnitTest --tests "com.androdr.data.db.*"` (existing `Migration17To18SqlTest` untouched).

- [ ] **Step 5: Commit** — `feat(db): telemetry_record, record_body, event_watermark tables (schema 19)`

### Task 5: `EventTimeFields` registry and `UsageEvent` record type

**Files:**
- Create: `app/src/main/java/com/androdr/sigma/EventTimeFields.kt`
- Create: `app/src/main/java/com/androdr/data/model/UsageEvent.kt`
- Create: `app/src/main/java/com/androdr/data/model/SystemPropertySnapshot.kt` → add `toFieldMap()` (member); add `UsageEvent.toFieldMap()` (member)
- Modify: `app/src/main/java/com/androdr/scanner/UsageStatsScanner.kt:39-91,93-135` (emit `UsageEvent`), `app/src/main/java/com/androdr/data/db/TimelineAdapter.kt` (add `UsageEvent.toForensicTimelineEvent(scanId)` — the existing row shape, kept until Phase D), `ScanOrchestrator.kt:325-326,433-434` (map through the adapter)
- Test: `app/src/test/java/com/androdr/sigma/EventTimeFieldsTest.kt`, `app/src/test/java/com/androdr/scanner/UsageStatsScannerFieldMapTest.kt`

**Interfaces:**
- Produces:
  ```kotlin
  object EventTimeFields {
      val byService: Map<String, String> = mapOf(
          "usage_stats" to "timestamp", "dns_monitor" to "timestamp", "network_monitor" to "timestamp",
          "security_log" to "timestamp", "appops_audit" to "event_time_ms", "tombstone_parser" to "crash_timestamp",
          "wakelock_parser" to "acquired_at", "battery_daily" to "timestamp",
          "package_install_history" to "timestamp", "db_info" to "observation_timestamp")
      fun eventTimeOf(service: String, fields: Map<String, Any?>): Long?   // null when the service has no field or the value is absent / not > 0
  }
  data class UsageEvent(val timestamp: Long, val packageName: String, val appName: String, val eventType: String /* "app_foreground" | "app_background" */, val source: TelemetrySource, val capturedAt: Long) { fun toFieldMap(): Map<String, Any?> }  // keys: timestamp, package_name, app_name, event_type, source, captured_at
  ```
  Builder: confirm each field name above against `TelemetryFieldMaps.kt` before committing; `db_info` is an event only when `observation_timestamp > 0`. `dns_monitor` gains `timestamp` in its field map in Task 15; until then `eventTimeOf("dns_monitor", …)` returns null and live DNS records are stored as snapshots — acceptable for Phase A.
- `UsageStatsScanner.collectEvents(sinceMs: Long, untilMs: Long): List<UsageEvent>?` — `null` when the query threw `SecurityException` (permission), empty list when nothing happened (Review Focus 2). `collectTimelineEvents(hoursBack)` deleted; callers map `UsageEvent.toForensicTimelineEvent`.

- [ ] **Step 1: Write the failing tests** — `EventTimeFieldsTest`: `appops record with event_time_ms is an event`, `live appops record with last_access_time 0 is a snapshot` (`eventTimeOf` null), `every service in byService exists in the taxonomy`; `UsageStatsScannerFieldMapTest`: `UsageEvent field map keys are exactly the six taxonomy keys`, `collectEvents returns null on SecurityException` (mock `UsageStatsManager`).

- [ ] **Step 2: Run to verify they fail.**

- [ ] **Step 3: Implement.**

- [ ] **Step 4: Run to verify they pass.** `LogsourceTaxonomyCrossCheckTest` will fail on `usage_stats` until Task 15 adds the taxonomy entry — mark the `every service` assertion `@Ignore("enabled in Task 15")` and leave a TODO naming Task 15; everything else green.

- [ ] **Step 5: Commit** — `feat(sigma): event-time field registry; usage events as typed records`

### Task 6: `TelemetryStore` — persist with dedup, read, delete

**Files:**
- Create: `app/src/main/java/com/androdr/data/store/TelemetryStore.kt`, `app/src/main/java/com/androdr/data/store/EventDisplay.kt`, `app/src/main/res/raw/event_display.yml`
- Test: `app/src/test/java/com/androdr/data/store/TelemetryStoreTest.kt`, `EventDisplayTest.kt`

**Interfaces:**
- Produces:
  ```kotlin
  data class ServiceRecords(val service: String, val source: TelemetrySource, val capturedAt: Long, val records: List<Map<String, Any?>>)
  data class PersistSummary(val service: String, val inserted: Int, val alreadyStored: Int, val newBodies: Int)
  data class DecodedRecord(val id: Long, val scanId: Long, val service: String, val ordinal: Int, val source: TelemetrySource,
      val capturedAt: Long, val eventTime: Long?, val category: String?, val summary: String?, val fields: Map<String, Any?>)
  data class RecordChange(val packageName: String, val before: DecodedRecord?, val after: DecodedRecord?)

  @Singleton class TelemetryStore @Inject constructor(dao: TelemetryRecordDao, codec: TelemetryRecordCodec, display: EventDisplay) {
      suspend fun persist(scanId: Long, batch: ServiceRecords): PersistSummary   // caller holds the transaction
      suspend fun resolveRecordId(scanId: Long, service: String, ordinal: Int): Long?
      suspend fun services(scanId: Long): List<ServiceSummary>
      fun page(scanId: Long, service: String): PagingSource<Int, DecodedRecord>
      suspend fun forEachRecord(scanId: Long, service: String, pageSize: Int = 1000, block: (DecodedRecord) -> Unit)
      suspend fun record(recordId: Long): DecodedRecord?
      fun history(packageName: String, service: String): Flow<List<DecodedRecord>>
      suspend fun changedBetween(scanA: Long, scanB: Long, service: String): List<RecordChange>
      suspend fun exportJsonl(scanId: Long, out: OutputStream)   // one envelope per line, spec §4.1 shape
      suspend fun deleteScan(scanId: Long)                       // records then unreferenced bodies
      suspend fun storage(): StorageSummary
  }
  class EventDisplay(yaml: String) { fun categoryFor(service: String, fields: Map<String, Any?>): String?; fun summaryFor(service: String, fields: Map<String, Any?>): String? }
  ```
- Persist rules (spec §5.1): `eventTime = EventTimeFields.eventTimeOf(service, fields)`; event record → `encoding = DEFLATE_DICT_V1`, `eventKey = fields["event_id"]?.toString()?.let { "$service:$it" } ?: hash`, `category = display.categoryFor`, `summary = display.summaryFor`; snapshot → `ENCODING_PLAIN`, `eventKey = null`, `category = null`, `summary = null`. `packageName = fields["package_name"] ?: fields["source_package"]`. `alreadyStored` = count of `-1` from `insertRecords`.
- `event_display.yml` shape: `services: { usage_stats: { category: "{event_type}", summary: "App {event_type}: {app_name}" }, dns_monitor: { category: "dns_query", summary: "DNS: {domain}" }, network_monitor: { category: "network_connect", summary: "Connect: {destination_ip}:{destination_port}" }, security_log: { category: "security_event", summary: "Security: {tag_name}" }, appops_audit: { category: "appops_access", summary: "{package_name} used {operation}" }, … }` — one entry per service in `EventTimeFields.byService`; placeholders resolved with `TemplateResolver`. `usage_stats` categories must stay `app_foreground` / `app_background` (the bundled atom `sigma_androdr_atom_app_launch.yml` binds on them).

- [ ] **Step 1: Write the failing tests**

`TelemetryStoreTest` (Robolectric):
- `S1 every active service round-trips` — for each service in the taxonomy build one representative field map, persist, `record(id).fields == original`.
- `S2 snapshot bodies dedup across scans` — persist 400 identical app records under scan 1 and scan 2 → `record_body` count 400, `telemetry_record` 800; change one → 401 bodies.
- `S2 overlapping event imports store each event once` — 1,000 events with `event_id` under scan A; 1,000 of which 600 overlap under scan B → B's summary `inserted 400, alreadyStored 600`.
- `events are compressed, snapshots plain` — encodings per row.
- `deleteScan drops records and only unreferenced bodies`.
- `changedBetween reports changed, added, removed packages`.
- `exportJsonl writes one envelope per record with record_id scanId:service:ordinal`.

`EventDisplayTest`: `every EventTimeFields service has a display entry`; `usage_stats category equals event_type`.

- [ ] **Step 2: Run to verify they fail.**

- [ ] **Step 3: Implement.**

- [ ] **Step 4: Run to verify they pass.**

- [ ] **Step 5: Commit** — `feat(store): TelemetryStore with dedup, compression, paging reads, export`

### Task 7: Writers — every scan and import persists its records

**Files:**
- Create: `app/src/main/java/com/androdr/scanner/TelemetryBatches.kt`
- Modify: `app/src/main/java/com/androdr/data/repo/ScanRepository.kt:117-158` (`saveScanWithCorrelation` gains `persistTelemetry: (suspend (scanId: Long) -> List<PersistSummary>)? = null`, invoked inside the transaction after the scan row insert), `ScanOrchestrator.kt` (`runFullScan` ~430-510, `analyzeBugReport` ~636-660, `analyzeIntrusionLog` ~780-800; constructor gains `telemetryStore: TelemetryStore`), `ScanResult.kt` (no change), `ScanRepository.deleteScan/deleteAllScans:239-255` (call `telemetryStore.deleteScan` inside the transaction)
- Test: `app/src/test/java/com/androdr/scanner/TelemetryBatchesTest.kt`, `app/src/test/java/com/androdr/scanner/BugReportTelemetryPersistedTest.kt`, `app/src/test/java/com/androdr/data/repo/SaveScanPersistsTelemetryTest.kt`

**Interfaces:**
- Produces:
  ```kotlin
  object TelemetryBatches {
      fun fromLiveScan(app: List<AppTelemetry>, device: List<DeviceTelemetry>, process: List<ProcessTelemetry>, file: List<FileArtifactTelemetry>,
          accessibility: List<AccessibilityTelemetry>, receiver: List<ReceiverTelemetry>, appOps: List<AppOpsTelemetry>,
          usage: List<UsageEvent>, dns: List<DnsEvent>, capturedAt: Long): List<ServiceRecords>
      fun fromBugReport(result: BugReportAnalyzer.BugReportAnalysisResult, moduleResults: List<ModuleResult>, capturedAt: Long): List<ServiceRecords>
      fun fromIntrusionLog(result: IntrusionLogAnalysisResult, capturedAt: Long): List<ServiceRecords>
  }
  ```
  Service names: the string each `SigmaRuleEngine.evaluate*` passes; `TelemetryBundle` lists via the `com.androdr.sigma` extension `toFieldMap()`s; `ModuleResult.telemetry` under `telemetryService`; `SystemPropertySnapshot` under `system_property`. `BugReportAnalysisResult` gains `moduleResults: List<ModuleResult>` so the generic records are available to the orchestrator.
- Intrusion-log persistence inserts in batches of 5,000 (`ServiceRecords.records.chunked(5_000)` inside `persist`).

- [ ] **Step 1: Write the failing tests**

- `TelemetryBatchesTest`: `fromLiveScan emits one ServiceRecords per non-empty input with the engine's service names` (assert the exact set `app_scanner, device_auditor, process_monitor, file_scanner, accessibility_audit, receiver_audit, appops_audit, usage_stats, dns_monitor`); `fromIntrusionLog emits dns_monitor, network_monitor, security_log with full counts` (parser output of 7,000 DNS events → 7,000 records, no cap).
- `BugReportTelemetryPersistedTest` (gate B1): reflect over `TelemetryBundle`'s constructor parameters; for each, a result with one element in that list produces a `ServiceRecords` with count 1 — a new bundle field without a batch mapping fails the test. Plus: a `ModuleResult(telemetry = 3 maps, telemetryService = "adb_audit")` → `adb_audit` count 3.
- `SaveScanPersistsTelemetryTest` (Robolectric, real `ScanRepository` over `RoomTestDb`): `saveScanWithCorrelation` with `persistTelemetry` → records exist after commit; when the correlator throws → no scan row and `telemetry_record` empty (gate S3).

- [ ] **Step 2: Run to verify they fail.**

- [ ] **Step 3: Implement.** In `runFullScan`, build the batch from the already-awaited lists and the `recentDnsEvents` the post-hoc DNS evaluation used. In `analyzeBugReport`, `fromBugReport(result, result.moduleResults, now)`. In `analyzeIntrusionLog`, `fromIntrusionLog(result, now)` — the uncapped `result.dnsEvents/networkEvents/securityEvents` (the capped lists still feed `forensic_timeline` until Phase D).

- [ ] **Step 4: Run to verify they pass**; then the full unit suite — existing `ScanOrchestrator*Test` constructors need the new `telemetryStore = mockk(relaxed = true)` argument.

- [ ] **Step 5: Commit** — `feat(scan): persist every telemetry record of live scans and imports`

### Task 8: Phase A branch verification and PR

- [ ] Run `./gradlew testDebugUnitTest detekt lintDebug`; all green.
- [ ] Clean install on the F916B (`./gradlew installDebug`, no `-g`); run a scan; pull the DB (with `-wal`) and confirm `SELECT service, COUNT(*) FROM telemetry_record GROUP BY 1` lists every live service with the expected counts (438 `app_scanner` on that device) and `record_body` is smaller than `telemetry_record` after a second scan.
- [ ] Open PR `feat/telemetry-store-a` → `main`, body "Part 1 of 5 of docs/superpowers/specs/2026-10-22-telemetry-store-design.md"; wait for `ci-success`; merge.

---

## Phase B — Report provenance (PR 2)

### Task 9: `ReportFormatter` renders stored records generically and streams

**Files:**
- Modify: `app/src/main/java/com/androdr/reporting/ReportFormatter.kt` (signature; `appendTelemetrySections`/`appendExtendedTelemetry` 209-387 replaced by a generic per-service renderer)
- Create: `app/src/main/java/com/androdr/reporting/StoredTelemetryReader.kt`
- Test: `app/src/test/java/com/androdr/reporting/ReportFormatterStoredTelemetryTest.kt`

**Interfaces:**
- Produces:
  ```kotlin
  interface StoredTelemetryReader {
      val services: List<ServiceSummary>
      val retention: Retention                       // data class Retention(val expired: Boolean, val keepScans: Int)
      suspend fun forEach(service: String, block: (DecodedRecord) -> Unit)
      suspend fun displayNames(): Map<String, String> // package_name → app_name from app_scanner records
  }
  object ReportFormatter {
      suspend fun writeScanReport(out: Appendable, scan: ScanResult, findings: List<Finding>, logLines: List<String>,
          telemetry: StoredTelemetryReader, mode: ExportMode, versionName: String)
  }
  ```
  Rendering per service: `section("<SERVICE NAME> (<recordCount> records)")`, each record as `  key: value` lines in taxonomy field order (taxonomy order from a small `TaxonomyFieldOrder` object reading `res/raw`-bundled copy? — no: field order = sorted keys, documented; taxonomy order is a UI nicety, Task 25). `DNS ACTIVITY` and `APP HASH INVENTORY` sections read `dns_monitor` / `app_scanner` records. Expired retention prints exactly: `Telemetry for this scan is no longer stored (retention: last N scans)` per section. The old typed parameters and `intrusionEvents` are deleted.

- [ ] **Step 1: Write the failing test** — a fake reader with two services; assert each service heading, each record's lines, the retention line when `expired = true`, and that `TELEMETRY_ONLY` omits FINDINGS while rendering all services.
- [ ] **Step 2: Run to verify it fails.**
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run to verify it passes**; fix `ReportFormatter*Test`s that called the old signature (update their call sites; assertions about findings sections stay).
- [ ] **Step 5: Commit** — `refactor(report): render stored telemetry generically, streaming`

### Task 10: One report path, reading only its own scan

**Files:**
- Modify: `app/src/main/java/com/androdr/reporting/ReportExporter.kt:52-100` (`export` builds a `TelemetryStoreReader(scan.id)`; new `suspend fun renderText(scan, mode): String` for the History sheet), `ui/history/HistoryViewModel.kt:80-100,156` (sheet uses `reportExporter.renderText`; delete `INTRUSION_ROW_LIMIT`), `ui/bugreport/BugReportViewModel.kt:160-195` (enrichment via `telemetryStore.history`/latest `app_scanner` records; `exportReport` goes through `reportExporter.export(scanResult)`), `scanner/ScanOrchestrator.kt:84-108,330-347,535-560` (delete `last*Telemetry*`; APK-hash enrichment reads the latest live scan's `app_scanner` records via `TelemetryStore.latestLiveRecords("app_scanner")` within `APP_TELEMETRY_CACHE_TTL_MS`, else `appScanner.collectTelemetry()` and discard)
- Create: `app/src/main/java/com/androdr/reporting/TelemetryStoreReader.kt` (implements `StoredTelemetryReader` over `TelemetryStore` + `SettingsRepository.telemetryRetentionScans`)
- Test: `app/src/test/java/com/androdr/reporting/ReportProvenanceTest.kt` (R1), `app/src/test/java/com/androdr/reporting/SingleReportPathTest.kt` (R2)

**Interfaces:**
- Produces: `TelemetryStore.latestLiveRecords(service: String): Pair<Long /*scanId*/, List<DecodedRecord>>?`; `SettingsRepository.telemetryRetentionScans: Flow<Int>` (key `telemetry_retention_scans`, default 20) and `setTelemetryRetentionScans(Int)`.

- [ ] **Step 1: Write the failing tests**
  - R1 (Robolectric, real store): persist scan A (`app_scanner` = `com.a`), scan B (`com.b`), import I (source `BUGREPORT_IMPORT`, `tombstone_parser` only). `renderText(A)` contains `com.a` and not `com.b`; `renderText(I)` contains neither and does contain `TOMBSTONE_PARSER`; delete A's records → `renderText(A)` contains the retention line in each telemetry section.
  - R2 source scan (pattern of `PureEmitterContractTest`): `ReportFormatter.writeScanReport(` appears in `main` only inside `reporting/ReportExporter.kt`; `lastAppTelemetry|lastDeviceTelemetry|lastProcessTelemetry|lastFileArtifactTelemetry|lastAccessibilityTelemetry|lastReceiverTelemetry|lastAppOpsTelemetry` appear nowhere in `main`.
- [ ] **Step 2: Run to verify they fail.**
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run to verify they pass**, full suite green.
- [ ] **Step 5: Commit** — `fix(report): reports read only their own scan's stored telemetry; single report path`
- [ ] **Step 6: Phase B PR** `feat/telemetry-store-b`; battery: export the report of an *older* scan on the F916B and confirm telemetry sections are populated with that scan's data.

---

## Phase C — Findings as rows, lifecycle, caps removed (PR 3)

### Task 11: `scan_finding` table and migration 19→20

**Files:**
- Create: `app/src/main/java/com/androdr/data/model/ScanFinding.kt`, `app/src/main/java/com/androdr/data/db/ScanFindingDao.kt`
- Modify: `Migrations.kt` (`MIGRATION_19_20`), `AppDatabase.kt` (`version = 20`), `ScanResult.kt` (drop `findings` column; add `triggeredCount: Int = 0`, `maxLevel: String = "low"`; computed `overallRiskLevel` from `maxLevel`; `deviceFlags/appRisks/activityChains` move to `ScanWithFindings`), `Converters.kt` (keep `toFindingList` — the migration uses it), `ForensicTimelineEvent.kt` (+ `level: String = ""`), `di/AppModule.kt`
- Create: `app/src/main/java/com/androdr/data/model/ScanWithFindings.kt`
- Test: `app/src/test/java/com/androdr/data/db/Migration19To20Test.kt` (F1 + Review Focus 4), `ScanFindingDaoTest.kt`

**Interfaces:**
- Produces:
  ```kotlin
  enum class FindingKind { STATE, ALERT }
  enum class FindingStatus { OPEN, CLOSED }
  @Entity(tableName = "scan_finding", indices = [Index("scanId"), Index("ruleId"), Index("triggered"), Index("kind","status")])
  data class ScanFinding(@PrimaryKey(autoGenerate = true) val id: Long = 0, val scanId: Long, val ruleId: String, val triggered: Boolean,
      val level: String, val category: FindingCategory, val kind: FindingKind, val status: FindingStatus = FindingStatus.OPEN,
      val closedAt: Long? = null, val closedReason: String? = null, val recordId: Long? = null, val service: String,
      val recordOrdinal: Int, val findingJson: String /* the Finding, kotlinx */)
  data class ScanWithFindings(val scan: ScanResult, val findings: List<Finding>) { val deviceFlags; val appRisks; val activityChains }
  object FindingKinds { fun kindOf(finding: Finding): FindingKind }  // ALERT iff EventTimeFields.byService contains finding.service or category == CORRELATION
  ```
  `ScanFindingDao`: `insertAll(List<ScanFinding>): List<Long>`, `forScan(scanId): List<ScanFinding>`, `flowForScan(scanId): Flow<List<ScanFinding>>`, `openAlerts(): Flow<List<ScanFinding>>` (`kind='ALERT' AND status='OPEN' AND triggered`), `close(id, closedAt, reason)`, `deleteForScan(scanId)`, `deleteAll()`.
- Migration 19→20: `CREATE TABLE scan_finding…`; for each `ScanResult` row read `findings` JSON with `Converters.toFindingList` (corrupt JSON → `emptyList()` and a `Log.w`, row kept — Review Focus 4), insert rows with `kind = FindingKinds.kindOf`, `status = OPEN`; recreate `ScanResult` without `findings`, with `triggeredCount`, `maxLevel`; `ALTER TABLE forensic_timeline ADD COLUMN level TEXT NOT NULL DEFAULT ''`.

- [ ] **Step 1: Write the failing tests** — F1: version-19 DB with one scan holding 1,200 findings (JSON via `Converters.fromFindingList`) → after migration 1,200 `scan_finding` rows, `triggeredCount` correct, history query returns the scan; a second scan with `findings = 'not json'` survives with 0 rows. `ScanFindingDaoTest`: `openAlerts excludes closed and STATE`.
- [ ] **Step 2: Run to verify they fail.**
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run to verify they pass.**
- [ ] **Step 5: Commit** — `feat(db): findings become scan_finding rows with kind and status (schema 20)`

### Task 12: Repository and consumers move to rows; caps deleted

**Files:**
- Modify: `ScanRepository.kt` (`saveScanWithCorrelation` writes `scan_finding` rows after the scan row, resolving `recordId` via `telemetryStore.resolveRecordId(scanId, f.service, f.recordOrdinal)`; new `findings(scanId): Flow<List<Finding>>`, `latestWithFindings(): Flow<ScanWithFindings?>`, `currentFindings(): Flow<CurrentFindings>`, `closeAlert(id, reason)`, `scansPaged(): PagingSource<Int, ScanResult>`; `allScans` removed), `ScanResultDao.kt` (`latest(): Flow<ScanResult?>`, `paged(): PagingSource<Int, ScanResult>`, `getLatestTwo` kept with gate comment; `getAllScans` deleted), `ScanOrchestrator.kt` (`computeDiff(newer: ScanWithFindings, older: ScanWithFindings)`; delete `FINDINGS_PERSIST_CAP`, `DNS_PERSIST_CAP`, `CONNECT_PERSIST_CAP`, `SECURITY_PERSIST_CAP`, `capTriggeredFindings`, the caps log; `buildIntrusionLogTimelineEvents` writes all rows), `IntrusionLogAnalyzer.kt` (remove the `FINDINGS_PERSIST_CAP`-derived "kept N of M" field), consumers: `ui/dashboard/DashboardViewModel.kt`, `ui/device/DeviceAuditViewModel.kt`, `ui/apps/AppScanViewModel.kt`, `ui/bugreport/BugReportViewModel.kt`, `ui/history/HistoryViewModel.kt` + `HistoryScreen.kt` (paged list via `collectAsLazyPagingItems`), `ui/timeline/TimelineViewModel.kt` (`latestFindings` from `currentFindings`), `reporting/ReportExporter.kt` (findings from repository)
- Test: `app/src/test/java/com/androdr/data/repo/FindingLifecycleTest.kt` (L1), `FindingRecordRefTest.kt` (F2), `app/src/test/java/com/androdr/scanner/NoPersistenceCapsGateTest.kt` (C1, initial allow-list)

**Interfaces:**
- Produces: `data class CurrentFindings(val stateFindings: List<Finding>, val openAlerts: List<AlertFinding>)`, `data class AlertFinding(val findingId: Long, val scanId: Long, val finding: Finding)`; `currentFindings()` = latest scan's triggered `STATE` findings ∪ all `OPEN` triggered `ALERT` rows.
- C1 allow-list (a `Set<String>` of `"<Dao>.<fun>"` in the test): `ScanResultDao.getLatestTwo`, `DnsEventDao.getRecentSnapshot`, `DnsEventDao.getRecentEvents`, `ForensicTimelineEventDao.getRecentEvents`, `ForensicTimelineEventDao.getEventsBySource`, `ForensicTimelineEventDao.getEventsBySourceForScan`, `ForensicTimelineEventDao.getEventsByPackage`, `ForensicTimelineEventDao.getEventsInRange`, `ForensicTimelineEventDao.getAllForExport` — the timeline entries are removed from the list in Task 20.

- [ ] **Step 1: Write the failing tests** — L1 (Robolectric, real repository + store): a `STATE` finding present in scan 1 and absent in scan 2 leaves `currentFindings`; an `ALERT` from scan 1 is still present after scan 2; `closeAlert` removes it; persisting scan 3 does not reopen it; a new event matching the same rule opens a new alert. F2: a finding's `recordId` resolves to the record whose fields equal its `matchContext` scalars. C1: regex scan of `app/src/main/java/com/androdr/{scanner,data,reporting,ui}` for `_PERSIST_CAP|_ROW_LIMIT|\bLIMIT\s+\d+` → offenders minus allow-list is empty; also `take\(` inside `buildIntrusionLogTimelineEvents` absent.
- [ ] **Step 2: Run to verify they fail.**
- [ ] **Step 3: Implement**, then run the whole suite; update the existing `ScanOrchestrator*Test`, `SaveScanWithCorrelationTest`, `ReportFormatter*Test` call sites.
- [ ] **Step 4: Run to verify everything passes.**
- [ ] **Step 5: Commit** — `feat(findings): rows with lifecycle; persistence caps removed; history paged`

### Task 13: Alert UI — current findings and Close

**Files:**
- Modify: `ui/dashboard/DashboardScreen.kt` + `DashboardViewModel.kt` (open-alerts card with count, list rows, "Close" → dialog with optional note → `repository.closeAlert`), `ui/timeline/TimelineEventCard.kt` (finding row detail: "Close alert" for `ALERT` findings), `reporting/ReportFormatter.kt` (FINDINGS section: "State findings" and "Open alerts (opened by scan <date>)" sub-headings), `res/values/strings.xml`
- Test: `app/src/test/java/com/androdr/ui/dashboard/DashboardAlertsViewModelTest.kt`, extend `ReportFormatterStoredTelemetryTest` with `open alerts are listed with the scan that opened them`

- [ ] **Step 1: Write the failing tests** — ViewModel exposes `openAlerts: StateFlow<List<AlertFinding>>`; `closeAlert(id, note)` calls the repository; report test as named.
- [ ] **Step 2–4: fail → implement → pass.**
- [ ] **Step 5: Commit** — `feat(ui): open alerts on the dashboard with close-and-note`
- [ ] **Step 6: Phase C PR** `feat/telemetry-store-c`; battery: import an intrusion log with > 1,000 triggered findings (fixture from `IntrusionLogEndToEndTest` scaled) and confirm History opens.

---

## Phase D — Watermarks, events in place, Timeline union, taxonomy (PR 4; rules-repo PR first)

### Task 14: Taxonomy PR in `android-sigma-rules` (safe ordering step 1)

**Files (rules repo, branch `feat/taxonomy-emitter-services`):**
- Modify: `validation/logsource-taxonomy.yml` — add services `adb_audit`, `activity_audit`, `usage_stats`, `system_property` (`status: active`, `field_map: member` for `usage_stats`/`system_property`, `field_map: generic` for the two module services, fields documented from the modules' record keys); add `timestamp: { kind: raw_fact, type: int, description: "Epoch ms of the DNS query" }` to `dns_monitor`; add `event_time_field: <name>` to every service in `EventTimeFields.byService` (Task 5 values); remove nothing yet.
- Modify: `validation/validate-rule.py` if it rejects unknown service keys (`event_time_field`, `field_map: generic`).

- [ ] **Step 1:** Branch, edit, run the repo's own `validate` locally if a script exists; push; open the rules PR; wait for green `validate` (do **not** merge yet).
- [ ] **Step 2:** In AndroDR: `cd third-party/android-sigma-rules && git fetch && git checkout <branch-commit>`; `git add third-party/android-sigma-rules`.
- [ ] **Step 3: Commit** — `build: bump android-sigma-rules to taxonomy emitter-services branch`

### Task 15: Kotlin side of the taxonomy change

**Files:**
- Modify: `data/model/DnsEvent.kt:24` (`"timestamp" to timestamp` in `toFieldMap`), `scanner/bugreport/DbInfoModule.kt:78` and `PlatformCompatModule.kt:54` (delete the generic `ModuleResult.telemetry` emission; typed records already reach `TelemetryBundle`), `sigma/EventTimeFields.kt` (un-ignore the taxonomy assertion from Task 5; add cross-check: `byService == taxonomy event_time_field map`), test `LogsourceTaxonomyCrossCheckTest` (add `usage_stats`, `system_property`, `adb_audit`, `activity_audit` field maps), `DetectionFieldCrossCheckTest` as needed
- Test: `app/src/test/java/com/androdr/sigma/EventTimeFieldsTaxonomyTest.kt`

- [ ] **Step 1: Write the failing test** — `byService equals the taxonomy's event_time_field entries exactly` (both directions).
- [ ] **Step 2–4: fail → implement → pass**; `LogsourceTaxonomyCrossCheckTest` green with the bumped submodule.
- [ ] **Step 5: Commit** — `feat(sigma): dns timestamp field; emitter-only taxonomy services cross-checked`
- [ ] **Step 6 (safe ordering 3–5):** push the AndroDR branch, confirm `build-and-test` green (`submodule-check` red is expected mid-ordering); merge the rules PR; re-point the submodule at the resulting `main` commit; commit `build: bump android-sigma-rules submodule`.

### Task 16: Correlation and clusters over record-backed events

**Files:**
- Modify: `sigma/SigmaRuleEngine.kt:125` (`computeAtomBindings(events: List<TimelineAtom>)`), `sigma/SigmaCorrelationEngine.kt` (`evaluate` over `List<TimelineAtom>`; signal details gain `"member_record_ids":"…"` beside `member_event_ids`), `sigma/RuleCoverage.kt` (`noEventSkipsFor` over atoms), `ui/timeline/TimelineClusters.kt:136-150` (`buildCluster` resolves both id lists; `byRecordId: Map<Long, DecodedRecord>`), `data/store/TelemetryStore.kt` (+ `eventAtomsBetween(sinceMs: Long, untilMs: Long, categories: Set<String>, excludeSource: TelemetrySource?): List<TimelineAtom>`, + `eventAtomsForScan(scanId, categories): List<TimelineAtom>`)
- Create: `app/src/main/java/com/androdr/sigma/TimelineAtom.kt`
- Test: `app/src/test/java/com/androdr/sigma/CorrelationOverRecordsTest.kt`

**Interfaces:**
- Produces: `data class TimelineAtom(val ref: AtomRef, val category: String, val timestamp: Long, val packageName: String, val ruleId: String = "", val telemetrySource: TelemetrySource)`; `sealed interface AtomRef { data class Row(val id: Long); data class Record(val id: Long) }`; `fun ForensicTimelineEvent.toAtom(): TimelineAtom`.
- The correlator in `saveScanWithCorrelation` receives `lookbackAtoms + persistedFindingRows.map { toAtom() } + eventAtoms` where `eventAtoms` is fetched **inside the transaction after `persistTelemetry`** with only the categories `sigmaRuleEngine.atomCategories()` binds — never the whole import.

- [ ] **Step 1: Write the failing test** — an `event_count` correlation rule over `app_foreground` with 3 record-backed atoms and 1 row-backed atom fires once; its signal details contain both `member_event_ids` and `member_record_ids`; `buildCluster` with both lookups yields 4 members. `RuleCoverage.noEventSkipsFor` sees record-backed categories (no false `NoEventsToCheck`).
- [ ] **Step 2–4: fail → implement → pass.**
- [ ] **Step 5: Commit** — `feat(sigma): correlation and clusters bind record-backed events`

### Task 17: Watermarks for live events

**Files:**
- Modify: `scanner/ScanOrchestrator.kt` (`runFullScan`: per service in `LIVE_EVENT_SERVICES = setOf("usage_stats","dns_monitor")` read `eventWatermarkDao.get(service)`; `since = watermark?.eventTime ?: (scanStart - 24h)`, `until = scanStart`; usage via `usageStatsScanner.collectEvents(since, until)`; DNS via `dnsEventDao.eventsBetween(since, until)`; delete `replaceUsageStatsEvents` and the `getRecentSnapshot()` call), `data/db/DnsEventDao.kt` (+ `eventsBetween(sinceExclusive: Long, untilInclusive: Long): List<DnsEvent>`), `data/repo/ScanRepository.kt` (`saveScanWithCorrelation` gains `watermarks: List<EventWatermark> = emptyList()` upserted inside the transaction; delete `replaceUsageStatsEvents` and `deleteBySource("usage_stats")`; `advanceWatermark(service, events, untilMs, collectionFailed): EventWatermark?` helper)
- Create: `app/src/main/java/com/androdr/scanner/Watermarks.kt`
- Test: `app/src/test/java/com/androdr/scanner/EventWatermarkTest.kt` (W1 + Review Focus 2, 3)

**Interfaces:**
- Produces: `object Watermarks { fun next(previous: Long?, events: List<Long /*eventTime*/>, untilMs: Long, collectionFailed: Boolean): Long? }` — `null` when `collectionFailed` (keep previous); otherwise `min(max(events.maxOrNull() ?: previous ?: untilMs, previous ?: 0), untilMs)` — never beyond `untilMs`, never backwards.

- [ ] **Step 1: Write the failing tests** — `two consecutive scans store each event once and miss none` (fixture stream split by watermark; Robolectric repo); `failed collection leaves the watermark unchanged`; `an event timestamped in the future caps the watermark at untilMs`; `first scan uses a 24h floor`; `watermark does not advance when the save fails` (S3 pattern).
- [ ] **Step 2–4: fail → implement → pass**; delete `UsageStatsScanner.collectTimelineEvents` callers' remnants.
- [ ] **Step 5: Commit** — `feat(scan): per-service watermarks; an event is observed by one scan`

### Task 18: Event rows live only in the store

**Files:**
- Modify: `scanner/ScanOrchestrator.kt` (`runFullScan`: usage events no longer mapped to `ForensicTimelineEvent`; `analyzeBugReport`: delete `rawEvents` and `moduleForensicEvents` (`InstallTimeModule` package-install rows are `package_install_history` records), keep finding rows; `analyzeIntrusionLog`: `buildIntrusionLogTimelineEvents` returns finding rows only — DNS/connect/security rows deleted; `deletePriorIntrusionLogRows` also calls `telemetryStore.deleteScan(priorScanId)`), `data/repo/ScanRepository.kt:183-220` (`logDnsEvent`/`logDnsEventsBatch` keep writing the `ioc_match` detected-change row — unchanged), `data/db/TimelineAdapter.kt` (delete `ImportedDnsEvent/NetworkTelemetry/SecurityLogEvent/UsageEvent.toForensicTimelineEvent`), `scanner/bugreport/{AdbKeysModule,AppOpsModule,BatteryDailyModule,InstallTimeModule}.kt` (delete `TimelineEvent` construction; `AdbKeysModule` records gain no time → snapshot; `AppOpsModule` records already carry `event_time_ms`), `scanner/bugreport/BugreportModule.kt` (`ModuleResult.timeline` removed), `scanner/BugReportAnalyzer.kt` (`timeline` removed; `moduleResults` kept), `ui/bugreport/BugReportViewModel.kt` + `BugReportScreen.kt` (timeline tab reads `telemetryStore.page(scanId, service)` events — or simply links to the Timeline filtered by scan), `reporting/TimelineFormatter.kt` → delete; `data/model/TimelineEvent.kt` → delete; `data/db/ForensicTimelineEventDao.kt` (`deleteOlderThan(cutoff)` gains `AND telemetrySource = 'LIVE_SCAN'`)
- Test: `app/src/test/java/com/androdr/scanner/EventRowsLiveInStoreTest.kt` (anti-goal 4), `app/src/test/java/com/androdr/data/db/ImportRowsExemptFromPruneTest.kt` (P1), `app/src/test/java/com/androdr/scanner/DnsFindingTimestampTest.kt` (D1)

- [ ] **Step 1: Write the failing tests** — after `analyzeIntrusionLog` on a 7,000-event fixture: `forensic_timeline` rows for that scan == triggered finding count (+ signals), `telemetry_record` rows == 7,000; after `runFullScan`, no `forensic_timeline` row with `source = 'usage_stats'`. P1: 31-day-old `INTRUSION_LOG_IMPORT` row survives `deleteOlderThan`, a live row does not. D1: an imported DNS finding's row `startTimestamp == record timestamp`.
- [ ] **Step 2–4: fail → implement → pass**; `IntrusionLogClusterRegressionTest` and `IntrusionLogReportSectionTest` adapt to record-backed members.
- [ ] **Step 5: Commit** — `feat(timeline): event records are read in place; TimelineEvent retired`

### Task 19: Timeline union query, paging, counts

**Files:**
- Modify: `data/db/ForensicTimelineEventDao.kt` (replace `getRecentEvents/getEventsBySource/getEventsBySourceForScan/getEventsByPackage/getEventsInRange/getAllForExport` with `pagedTimeline(filter: TimelineFilter): PagingSource<Int, TimelineRowEntity>` built from a `UNION ALL` of `telemetry_record WHERE eventTime IS NOT NULL` and `forensic_timeline`, ordered `time DESC, id DESC`; `scanGroupHeaders(): Flow<List<ScanGroupHeader>>` and `dateGroupHeaders(filter): Flow<List<DateGroupHeader>>` as aggregate queries; `countFor(filter): Flow<Int>`; `allForExport(filter): Flow<List<TimelineRowEntity>>` via `forEach` paging in the exporter), `ui/timeline/TimelineViewModel.kt` (`rows: Flow<PagingData<TimelineRow>>`; filters as before; severity filter and "findings and their evidence only" become SQL predicates), `ui/timeline/TimelineRow.kt` (`TelemetryRow` → `EventRow`; `mergeTimelineRows`/`rollUpFindings` deleted), `ui/timeline/TimelineScreen.kt` (`collectAsLazyPagingItems`; header counts; switch text `Show findings and their evidence only`), `reporting/TimelineExporter.kt` (streams)
- Create: `app/src/main/java/com/androdr/data/model/TimelineRowEntity.kt`, `app/src/main/java/com/androdr/data/db/TimelineFilter.kt`
- Test: `app/src/test/java/com/androdr/ui/timeline/TimelineUncappedTest.kt` (T1), `TimelineUnionQueryPlanTest.kt`

**Interfaces:**
- Produces: `data class TimelineRowEntity(val rowKind: Int /*0 record,1 row*/, val id: Long, val scanId: Long, val time: Long, val category: String, val summary: String, val packageName: String, val level: String, val ruleId: String, val correlationId: String, val kind: String, val telemetrySource: TelemetrySource)`; `data class TimelineFilter(val scanId: Long? = null, val packageName: String? = null, val source: String? = null, val from: Long? = null, val to: Long? = null, val levels: Set<String> = emptySet(), val findingsAndEvidenceOnly: Boolean = false)`.

- [ ] **Step 1: Write the failing tests** — T1 (Robolectric): 100,000 event records + 50 finding rows; paging through `pagedTimeline(TimelineFilter())` yields 100,050 rows; `countFor` == 100,050; `scanGroupHeaders` reports the count; no `forensic_timeline` row exists for an event record. `TimelineUnionQueryPlanTest`: `EXPLAIN QUERY PLAN` of the union contains no `SCAN telemetry_record` without `USING INDEX`.
- [ ] **Step 2–4: fail → implement → pass**; remove the timeline DAO entries from the C1 allow-list and run `NoPersistenceCapsGateTest`.
- [ ] **Step 5: Commit** — `feat(timeline): paged union of event records and finding rows; counts shown`
- [ ] **Step 6: Phase D PR** `feat/telemetry-store-d`; battery: scan twice on the F916B (watermark), import an intrusion log twice (overlap dedup → "N new, M already stored" in logcat), open Timeline with > 20k rows and scroll.

---

## Phase E — Browser, retention, export, vocabulary (PR 5)

### Task 20: Telemetry browser

**Files:**
- Create: `app/src/main/java/com/androdr/ui/telemetry/TelemetryBrowserViewModel.kt`, `TelemetryServicesScreen.kt`, `TelemetryRecordsScreen.kt`, `RecordHistorySheet.kt`
- Modify: `MainActivity.kt` (routes `telemetry/{scanId}`, `telemetry/{scanId}/{service}`, `record/{recordId}`), `ui/history/HistoryScreen.kt` ("View telemetry"), `ui/timeline/TimelineScreen.kt` (scan header "View telemetry"; finding detail "Matched record"), `res/values/strings.xml`
- Test: `app/src/test/java/com/androdr/ui/telemetry/TelemetryBrowserViewModelTest.kt`

**Interfaces:**
- `TelemetryBrowserViewModel(scanId)`: `services: StateFlow<List<ServiceSummary>>`, `records(service): Flow<PagingData<DecodedRecord>>`, `search: MutableStateFlow<String>` (filters on `packageName`, `summary`, `category` via DAO predicate), `history(packageName, service): Flow<List<RecordChange>>` (diff of consecutive records, changed keys highlighted).

- [ ] **Step 1: Write the failing test** — services list reflects the store; `records` paging emits; search narrows by package.
- [ ] **Step 2–4: fail → implement → pass.**
- [ ] **Step 5: Commit** — `feat(ui): telemetry browser with per-service paging and package history`

### Task 21: Retention, storage settings, JSONL export

**Files:**
- Create: `app/src/main/java/com/androdr/data/store/TelemetryRetention.kt`
- Modify: `ioc/IocUpdateWorker.kt:28-31` (call `telemetryRetention.apply()` after the prunes), `ui/settings/SettingsScreen.kt` + `SettingsViewModel.kt` ("Telemetry storage": size by kind, "Keep full telemetry for the last N scans" slider 5–100 default 20, "Delete stored telemetry for old scans now"), `ui/history/HistoryViewModel.kt` + `HistoryScreen.kt` ("Export telemetry (JSONL)" → `telemetryStore.exportJsonl` to `cache/reports/androdr_telemetry_<scanId>.jsonl.gz` via `GZIPOutputStream`, shared through the existing `FileProvider`)
- Test: `app/src/test/java/com/androdr/data/store/TelemetryRetentionTest.kt`

**Interfaces:**
- `class TelemetryRetention @Inject constructor(store, scanResultDao, settings) { suspend fun apply(): RetentionReport }` — deletes `telemetry_record` rows of `LIVE_SCAN` scans beyond the newest N (`scanResultDao.liveScanIdsBeyond(n)`), never import scans, then unreferenced bodies; `data class RetentionReport(val scansTrimmed: Int, val bytesFreed: Long)`.

- [ ] **Step 1: Write the failing tests** — 25 live scans + 2 imports with N=20 → records remain for the newest 20 live scans and both imports; a body still referenced by a kept scan survives; `scan_finding` rows of trimmed scans untouched.
- [ ] **Step 2–4: fail → implement → pass.**
- [ ] **Step 5: Commit** — `feat(store): retention by scan count; storage settings; JSONL export`

### Task 22: Vocabulary gate and glossary

**Files:**
- Modify: `docs/ARCHITECTURE.md` (new §2.x "Glossary" with spec §3's table verbatim; §5.1 table row for `forensic_timeline`, new rows for `telemetry_record`/`record_body`/`scan_finding`/`event_watermark`; §6.3 without `TimelineFormatter`; `TELEMETRY_ONLY` wording), `reporting/ReportExporter.kt:29-33` (comment wording), any remaining UI copy
- Test: `app/src/test/java/com/androdr/VocabularyGateTest.kt` (V1)

- [ ] **Step 1: Write the failing test** — scan `app/src/main/**/*.kt`, `app/src/main/res/values/*.xml`, `docs/*.md` (not `docs/superpowers/`): no `raw telemetry`, no `informational telemetry` (case-insensitive), no `class TimelineEvent\b`; `docs/ARCHITECTURE.md` contains each of `Telemetry record`, `Snapshot record`, `Event record`, `Timeline event`, `Finding`, `Provenance`, `Watermark` under a `## ` heading containing `Glossary`.
- [ ] **Step 2–4: fail → fix copy and docs → pass.**
- [ ] **Step 5: Commit** — `docs: telemetry glossary; vocabulary gate`
- [ ] **Step 6: Phase E PR** `feat/telemetry-store-e`; full release battery (spec §9): clean install on F916B + emulators (include API 26 for the JSON1 probe), scan twice, bug-report import, intrusion-log import twice, browse each, close an alert, export each report and compare telemetry sections to the browser, export JSONL and open it.

---

## Self-review notes

- Spec coverage: §3 → Task 22; §4.1–4.3 → Tasks 3, 5, 6, 15; §5.1 → 4, 6, 21; §5.2 → 7, 17; §5.3 → 6, 18; §5.4 → 11, 12, 13; §5.5 → 12, 19; §5.6 → 17, 18; §6 → 16, 18, 19, 20; §7 → 9, 10, 13, 21; §8 → 20, 21; §9 gates S1–S4 (6, 7), W1 (17), R1/R2 (10), B1 (7), C1 (12, 19), T1 (19), F1/F2 (11, 12), L1 (12), V1 (22), P1/D1 (18). Spec's single migration 18→19 is split into 19 (store) and 20 (findings) so each phase ships alone — a plan decision, noted here.
- Type consistency: `ServiceRecords`, `PersistSummary`, `DecodedRecord`, `TimelineAtom`, `TimelineRowEntity`, `TimelineFilter`, `CurrentFindings` are defined once and used by name thereafter.
- Review Focus items are pinned in Tasks 3, 4, 11, 17.
