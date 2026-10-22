# Telemetry Store, Uncapped Timeline, Finding Lifecycle Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Persist every telemetry record a scan or import produces as facts observed by scans, remove every persistence cap, read the Timeline as a paged union with no duplicated event rows, give findings a SOC-style lifecycle, and make the telemetry vocabulary precise and gated.

**Architecture:** Each emitter's output is projected to field maps once (`ServiceRecords`); the rule engine evaluates exactly that list and the store persists exactly that list. Storage is `record_body` (content, envelope keys excluded, events Deflate-compressed with immutable per-service dictionaries) → `telemetry_record` (one row per fact, unique `(service, factKey)`) → `scan_record` (one row per observation). Findings become `scan_finding` rows with `kind`/`status`/`alertKey`. Live event collection runs from per-service watermarks. The Timeline pages a `UNION ALL` of event facts and `forensic_timeline` rows. Reports stream from one `ReportExporter` path.

**Tech Stack:** Kotlin 2.0, Room 2.6.1 (+ `room-paging` 2.6.1, `room-testing` on the unit-test classpath), AndroidX Paging 3.3.6 (+ `paging-compose`), `androidx.biometric` 1.1.0, Jetpack Compose, Hilt, kotlinx.serialization, `java.util.zip`, Robolectric 4.14.1 (SDK 35) + `androidx.test:core` 1.6.1, snakeyaml-engine 2.7 (present).

**Spec:** `docs/superpowers/specs/2026-10-22-telemetry-store-design.md` (revised after plan-gate round 1; findings: `docs/superpowers/plans/2026-10-22-telemetry-store-plan-gate-round1-findings.md`)

## Global Constraints

- JDK 21. Gates: `./gradlew testDebugUnitTest`, `./gradlew detekt`, `./gradlew lintDebug`; CI runs `assembleDebug test` and `lintDebug detekt`. Every gate in this plan is a JVM unit test.
- Every fix lands with a test that fails on the original mistake (CLAUDE.md Regression policy). Every commit compiles and passes the full unit suite.
- New dependencies pinned exactly; `gradle/verification-metadata.xml` regenerated and its diff reviewed per `docs/supply-chain.md` (if present) in the same commit. No new native library or SQLite build.
- No `_PERSIST_CAP`, `_ROW_LIMIT`, literal `LIMIT <n>` or `limit: Int = <n>` default in any DAO outside the C1 allow-list (spec §5.5).
- Event facts are never copied into `forensic_timeline` (anti-goal 4). No bound silently drops evidence.
- `ReportFormatter` is called only from `ReportExporter`. No report or export is built as one in-memory `String` or full `List`.
- No source-named types or fields; taxonomy field names `snake_case`.
- DAO SQL uses only features available in API 26's SQLite (no UPSERT, `RETURNING`, window functions, `NULLS LAST`).
- Taxonomy edits follow CLAUDE.md safe ordering. Shipped compression dictionaries are immutable.
- Each phase (0, A–E) is one PR to `main` that leaves the app working. Branches `feat/telemetry-store-<phase>`.
- detekt: classes/objects ≤ 15 functions, interfaces ≤ 11, `LongParameterList` 13, `LongMethod` 60. New Hilt providers go in a new `di/StoreModule.kt` (`AppModule` is at 14). Split rather than suppress.

## Review Focus

1. A field map holding a value JSON cannot carry (NaN, `ByteArray`, nested `Map`, `Set`) — canonical JSON encodes it with a type tag, deterministically, and decodes it back. Pinned in Task A3.
2. Usage access revoked between scans — collection failed, watermark unchanged; access present with no events — watermark advances to the scan's start. Pinned in Task C1.
3. Device clock set ahead then corrected — the usage watermark resets when ahead of `now`; DNS watermark uses row id and is immune. Pinned in Task C1.
4. A `ScanResult.findings` value over 2 MB or corrupt during migration 19→20 — the scan row survives; the migration completes. Pinned in Task C2.
5. Storage nearly full during an import — the import is refused with a message before anything is written; a live scan whose telemetry write fails still saves its findings. Pinned in Task A7.

---

## Phase 0 — Taxonomy first (rules PR + AndroDR PR 0)

### Task 0.1: Rules-repo taxonomy change (safe ordering steps 1–2)

**Files (rules repo `third-party/android-sigma-rules`, branch `feat/taxonomy-emitter-services`):**
- Modify: `validation/logsource-taxonomy.yml` — per spec §4.2: `status: emitter_only` services `usage_stats` (fields `timestamp, package_name, app_name, event_type, source, captured_at`) and `system_property` (`key, value, source, captured_at`); `adb_audit`, `activity_audit` documented from the modules' current record keys (`status: active`, `field_map: generic`); `event_time_field` on `usage_stats, dns_monitor, network_monitor, security_log, appops_audit (event_time_ms), tombstone_parser (crash_timestamp), wakelock_parser (acquired_at), battery_daily (timestamp), package_install_history (timestamp), db_info (observation_timestamp)`; `key_fields` on every snapshot-capable service; new fields `dns_monitor.timestamp`, `dns_monitor.resolved_ips`, `file_scanner.accessible`, `appops_audit.event_time_ms (optional)`, `battery_daily.timestamp (optional)`, `db_info.db_path`, `db_info.recent_query_count`; `positive_only: true` on every field old binaries lack (spec §4.2 list).
- Modify: `validation/validate-rule.py` — accept the new keys; reject rules on `emitter_only` services outside `staging/`; generalise the negation guard (line ~517) from `requested_permissions` to every `positive_only` field.

- [ ] **Step 1:** Edit; run the repo's validator locally; push; open the rules PR; wait for green `validate`; do **not** merge.
- [ ] **Step 2:** In AndroDR, point the submodule at the branch commit; commit `build: bump android-sigma-rules to taxonomy emitter-services branch`.

### Task 0.2: Kotlin side — field maps, registries, cross-checks

**Files:**
- Modify: `data/model/DnsEvent.kt:24` (+ `"timestamp"`), `data/model/ImportedDnsEvent.kt` (+ `fun toFieldMap() = event.toFieldMap() + ("resolved_ips" to resolvedIps)`), `data/model/FileArtifactTelemetry.kt:11-16` (+ `"accessible"`), `data/model/SystemPropertySnapshot.kt` (+ member `toFieldMap()`), `sigma/SigmaRuleEngine.kt:277-280` (`evaluateFiles` keeps its accessible pre-filter; unchanged semantics)
- Create: `data/model/UsageEvent.kt`, `sigma/EventTimeFields.kt`, `sigma/TimelineCategories.kt`, `sigma/TaxonomyContract.kt` (loads the bundled taxonomy copy at test time only — see Interfaces)
- Modify tests: `LogsourceTaxonomyCrossCheckTest.kt` (new services; `optional` honoured; `loadTaxonomy` made `internal` in a shared `TaxonomyTestSupport.kt`), `ServiceActivationCrossCheckTest.kt` (accept `emitter_only`; assert no evaluate path exists for them)
- Test: `sigma/EventTimeFieldsTaxonomyTest.kt`, `sigma/TimelineCategoriesAtomTest.kt` (K1), `data/model/FieldMapCompletenessTest.kt` (E2)

**Interfaces:**
- Produces:
  ```kotlin
  data class UsageEvent(val timestamp: Long, val packageName: String, val appName: String,
      val eventType: String /* app_foreground | app_background */, val source: TelemetrySource, val capturedAt: Long) {
      fun toFieldMap(): Map<String, Any?> }
  object EventTimeFields {
      val byService: Map<String, String>                       // exactly the taxonomy's event_time_field entries
      fun eventTimeOf(service: String, fields: Map<String, Any?>): Long?   // value as Long when present and > 0, else null
  }
  object TimelineCategories {
      fun categoryOf(service: String, fields: Map<String, Any?>): String
      // usage_stats → fields["event_type"]; appops_audit → "permission_use"; package_install_history → "package_install";
      // battery_daily → fields["event_type"]; network_monitor → "network_connect"; security_log → "security_event";
      // dns_monitor → the category TimelineAdapter.kt:170-180 assigns to imported DNS today (read it; keep it);
      // tombstone_parser/wakelock_parser/db_info → the service name
  }
  ```

- [ ] **Step 1: Write the failing tests**
  - `EventTimeFieldsTaxonomyTest`: `byService equals taxonomy event_time_field in both directions`; `named field is declared on its service`; `live AppOpsTelemetry record is a snapshot` (`eventTimeOf` null for `last_access_time = 0` map without `event_time_ms`); `bug-report appops map with event_time_ms > 0 is an event`.
  - K1 `TimelineCategoriesAtomTest`: parse every `res/raw/sigma_androdr_atom_*.yml`; each `selection.category` value is produced by `TimelineCategories` for some service or is a `forensic_timeline`-row category (`ioc_match`, `device_admin_grant`, `package_install` from the live install emitter).
  - E2 `FieldMapCompletenessTest`: for each telemetry data class with a field map, constructor property names (snake-cased) ⊆ field-map keys ∪ `ALLOWED_OMISSIONS` (a commented map; `AppTelemetry` entries for derived judgment inputs as found today); `FileArtifactTelemetry` includes `accessible`; `ImportedDnsEvent` includes `resolved_ips`.
- [ ] **Step 2: Run to verify they fail** — `./gradlew testDebugUnitTest --tests "com.androdr.sigma.*" --tests "com.androdr.data.model.*"`.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run to verify they pass**, plus the full suite (`LogsourceTaxonomyCrossCheckTest`, `DetectionFieldCrossCheckTest`, `ServiceActivationCrossCheckTest` green on the bumped submodule).
- [ ] **Step 5: Commit** — `feat(sigma): taxonomy contract for event time, categories, emitter-only services`
- [ ] **Step 6 (safe ordering 3–5):** push; confirm `build-and-test` green (red `submodule-check` mid-ordering is expected); merge the rules PR; re-point the submodule at rules `main`; commit `build: bump android-sigma-rules submodule`; open PR `feat/telemetry-store-0`, wait for `ci-success`, merge.

---

## Phase A — Store foundations (PR 1)

After Phase A every scan and import writes its facts and observations; nothing reads them yet except retention.

### Task A1: JVM Room harness

**Files:**
- Modify: `gradle/libs.versions.toml` (`robolectric = "4.14.1"`, `androidxTestCore = "1.6.1"`, `paging = "3.3.6"`, `biometric = "1.1.0"`; libraries `robolectric`, `androidx-test-core`, `androidx-room-paging` (version.ref `room`), `androidx-paging-runtime`, `androidx-paging-compose`, `androidx-biometric`)
- Modify: `app/build.gradle.kts` (`testImplementation(libs.robolectric, libs.androidx.test.core, libs.androidx.room.testing)`; `implementation(libs.androidx.room.paging, libs.androidx.paging.runtime, libs.androidx.paging.compose)`; `sourceSets { getByName("test") { assets.srcDirs("schemas") } }` beside the existing `androidTest` entry at :163; `testOptions.unitTests.isIncludeAndroidResources = true`)
- Create: `app/src/test/resources/robolectric.properties` (`sdk=35`), `app/src/test/java/com/androdr/data/db/RoomTestDb.kt`
- Test: `app/src/test/java/com/androdr/data/db/RoomJvmHarnessTest.kt`, `app/src/test/java/com/androdr/data/db/DaoSqlCompatibilityTest.kt` (Q1)

**Interfaces:** `object RoomTestDb { fun inMemory(): AppDatabase; fun migrationHelper(): MigrationTestHelper }`.

- [ ] **Step 1: Write the failing tests** — `in-memory AppDatabase round-trips a ScanResult`; `MigrationTestHelper creates version 18 from exported schema`; Q1: regex over every `@Query`/`@RawQuery` string in `data/db/*.kt` finds none of `ON CONFLICT`, `RETURNING`, `OVER (`, `NULLS LAST`, `NULLS FIRST`.
- [ ] **Step 2: Run to verify they fail.**
- [ ] **Step 3: Add dependencies, verification metadata, harness.** Robolectric fetches `android-all-instrumented` at test time; declare that jar (SDK 35 coordinates Robolectric 4.14.1 requests) as a pinned `testRuntimeOnly` dependency and set `robolectric.offline=true` so it is checksum-verified.
- [ ] **Step 4: Run to verify they pass.**
- [ ] **Step 5: Commit** — `test: JVM Room harness, SQLite compatibility gate, paging and biometric deps`

### Task A2: One list, evaluated and stored

**Files:**
- Create: `app/src/main/java/com/androdr/sigma/ServiceRecords.kt`
- Modify: `sigma/SigmaRuleEvaluator.kt:23-45,135-215` (`Finding.service`, `Finding.ordinal`; `evaluate` iterates `forEachIndexed` and accepts an optional `include: (Int) -> Boolean`), `sigma/SigmaRuleEngine.kt:249-358` (add `evaluateRecords`; each typed `evaluate*` builds `ServiceRecords` and delegates; `evaluateFiles` passes `include = { records[it]["accessible"] == true }`)
- Test: `app/src/test/java/com/androdr/sigma/EvaluatedEqualsStoredTest.kt` (E1)

**Interfaces:**
- Produces:
  ```kotlin
  data class StoreRecord(val fields: Map<String, Any?>, val sourceEventKey: String? = null)
  data class ServiceRecords(val service: String, val source: TelemetrySource, val capturedAt: Long, val records: Sequence<StoreRecord>)
  fun SigmaRuleEngine.recordsFor(...)   // one builder per typed list, e.g. fun appRecords(t: List<AppTelemetry>, source, capturedAt): ServiceRecords
  fun SigmaRuleEngine.evaluateRecords(batch: ServiceRecords, include: (Int) -> Boolean = { true }): List<Finding>
  // Finding gains: val service: String = "", val ordinal: Int = -1
  ```
  `records` is a `Sequence` so imports never materialise a full list of maps; evaluation consumes it in chunks of 5,000 (`chunked(5_000)`), keeping a running ordinal.

- [ ] **Step 1: Write the failing test** — E1: for every typed evaluate entry point, build a fixture list, capture the `ServiceRecords` it builds and the `records` the evaluator receives (test hook `SigmaRuleEngine.onEvaluate: ((service, ordinal, map) -> Unit)?`), and assert element-wise equality of maps and ordinals; `file_scanner` with an inaccessible record at index 0 and a matching record at index 1 → finding `ordinal == 1`.
- [ ] **Step 2–4: fail → implement → pass**; `PureEmitterContractTest` stays green.
- [ ] **Step 5: Commit** — `refactor(sigma): field maps built once; findings carry service and stored ordinal`

### Task A3: Codec and immutable dictionaries

**Files:**
- Create: `data/store/TelemetryRecordCodec.kt`, `data/store/TelemetryDictionaries.kt`, `scripts/build_telemetry_dictionaries.py` (reads the taxonomy, writes `res/raw/telemetry_dict_<family>_v1.txt`), the generated dictionary resources
- Test: `data/store/TelemetryRecordCodecTest.kt`, `data/store/TelemetryDictionariesTest.kt` (S5, S6)

**Interfaces:**
- Produces:
  ```kotlin
  object EnvelopeKeys { val KEYS = setOf("captured_at", "source") }
  class TelemetryRecordCodec(private val dictionaries: TelemetryDictionaries) {
      fun canonicalJson(fields: Map<String, Any?>): String   // envelope keys removed; keys sorted recursively; tagged values: {"$t":"long","v":..}, {"$t":"nan"}, {"$t":"bytes","v":base64}, sets sorted
      fun hash(canonical: String): String                     // SHA-256 hex
      fun encodeEvent(service: String, canonical: String): EncodedBody     // Deflate with the service family's current dictionary
      fun encodeSnapshot(canonical: String): EncodedBody                   // plain UTF-8
      fun decode(body: ByteArray, encoding: Int, dictVersion: Int, rawBytes: Int): Map<String, Any?>?  // null = unreadable
  }
  data class EncodedBody(val encoding: Int, val dictVersion: Int, val body: ByteArray, val rawBytes: Int)
  class TelemetryDictionaries(load: (resName: String) -> ByteArray) {
      fun current(service: String): Pair<Int, ByteArray>; fun byVersion(dictVersion: Int): ByteArray
      companion object { val PINNED_SHA256: Map<Int, String> }   // dictVersion → hash; append-only
  }
  ```
  One `Deflater`/`Inflater` per `TelemetryStore.persist` call (`reset()` between records, `end()` after). Inflation stops at `rawBytes`; a dictionary-check failure or overrun returns null.

- [ ] **Step 1: Write the failing tests**
  - `canonical JSON ignores envelope keys and map order` — same content, different `captured_at`/`source`/order → equal hash.
  - `tagged values round-trip` — Long vs Int, NaN, ByteArray, nested Map, Set: `canonicalJson(decode(encode(c))) == c`.
  - `event encoding compresses 1,000 real NetworkTelemetry maps at least 2.5x`.
  - S5: `every shipped dictionary matches its pinned SHA-256`; `a body encoded with v1 (fixture bytes checked into test resources) decodes`; `builder output differing from the newest shipped version fails with a message to add a new version`.
  - S6: `truncated or bit-flipped body decodes to null`; `body inflating past rawBytes decodes to null`.
- [ ] **Step 2–4: fail → implement (run the script once to generate v1; commit resources) → pass.**
- [ ] **Step 5: Commit** — `feat(store): canonical record codec with immutable per-service dictionaries`

### Task A4: Entities, DAOs, migration 18→19

**Files:**
- Create: `data/model/RecordBody.kt`, `TelemetryFact.kt` (table `telemetry_record`), `ScanObservation.kt` (table `scan_record`), `EventWatermark.kt`, `TelemetryState.kt`
- Create: `data/db/RecordBodyDao.kt`, `TelemetryFactDao.kt`, `ScanObservationDao.kt`, `EventWatermarkDao.kt`
- Modify: `data/db/Migrations.kt` (`MIGRATION_18_19`), `AppDatabase.kt` (`version = 19`), `data/model/ScanResult.kt` (+ `telemetryState: TelemetryState = TelemetryState.NONE`), `data/model/ForensicTimelineEvent.kt` (+ `recordId: Long? = null`), create `di/StoreModule.kt` (DAOs; register `MIGRATION_18_19` wherever `AppModule.provideDatabase` lists migrations; `onOpen` sets `PRAGMA journal_size_limit = 67108864`), schema `19.json`
- Test: `data/db/Migration18To19Test.kt`, `data/db/StoreDaoTest.kt`

**Interfaces:**
- Entities exactly as spec §5.1 tables. Indices: `telemetry_record` unique `(service, factKey)`, `(service, subjectKey)`, `eventTime`, `packageName`, `bodyHash`; `scan_record` PK `(scanId, service, ordinal)`, index `recordId`. FK `telemetry_record.bodyHash → record_body.hash`, `scan_record.recordId → telemetry_record.id`.
- `enum class TelemetryState { NONE, STORED, PARTIAL_RETENTION, FAILED }`
- DAOs (each ≤ 11 functions): `RecordBodyDao.insertIgnore(List<RecordBody>)`, `deleteUnreferenced(batch: Int): Int`, `distinctBytesByKind(): StorageSummary`; `TelemetryFactDao.insertIgnore(List<TelemetryFact>): List<Long>`, `idsFor(service: String, factKeys: List<String>): List<FactIdRow>`, `history(service, subjectKey): Flow<List<FactWithObservation>>`, `deleteUnobserved(batch: Int): Int`; `ScanObservationDao.insert(List<ScanObservation>)`, `pageForScan(scanId, service): PagingSource<Int, ObservedFact>`, `chunkAfter(scanId, service, afterOrdinal: Int, size: Int): List<ObservedFact>` (keyset), `servicesForScan(scanId): List<ServiceSummary>`, `deleteForScan(scanId)`, `deleteSnapshotsForScans(scanIds: List<Long>)`, `deleteLiveEventsBefore(cutoff: Long)`, `factIdsForOrdinals(scanId, service): List<OrdinalFact>`; `EventWatermarkDao.get(service)`, `put(EventWatermark)`.
- Result classes: `data class ServiceSummary(val service: String, val recordCount: Int)`, `data class StorageSummary(val snapshotBytes: Long, val liveEventBytes: Long, val importBytes: Long)` (sums over **distinct** bodies), `ObservedFact` (observation + fact + body columns, flat `@Embedded`, no `@Relation`).

- [ ] **Step 1: Write the failing tests** — migration creates the four tables with the listed indices and `ScanResult.telemetryState` defaulting `NONE`; `validateMigration` against 19; DAO: duplicate fact key returns `-1` and `idsFor` finds the existing id; `chunkAfter` pages by ordinal; `deleteUnobserved` keeps a fact another scan observes; `distinctBytesByKind` counts a shared body once; `EXPLAIN QUERY PLAN` of `deleteUnreferenced` uses `bodyHash` index.
- [ ] **Step 2–4: fail → implement → pass.**
- [ ] **Step 5: Commit** — `feat(db): record_body, telemetry_record, scan_record, event_watermark (schema 19)`

### Task A5: `TelemetryStore`

**Files:**
- Create: `data/store/TelemetryStore.kt` (writes, delete, retention hooks), `data/store/TelemetryReader.kt` (reads), `data/store/EventDisplay.kt`, `res/raw/event_display.yml`
- Test: `data/store/TelemetryStoreTest.kt` (S1, S2, S4), `data/store/EventDisplayTest.kt`

**Interfaces:**
- Produces:
  ```kotlin
  data class PersistResult(val service: String, val observed: Int, val newFacts: Int, val ordinalToFactId: Map<Int, Long>)
  data class DecodedRecord(val factId: Long, val scanId: Long, val service: String, val ordinal: Int, val source: TelemetrySource,
      val capturedAt: Long, val eventTime: Long?, val category: String?, val fields: Map<String, Any?>?, /* null = unreadable */ val summary: String?)
  data class RecordChange(val subjectKey: String, val before: DecodedRecord?, val after: DecodedRecord?)

  @Singleton class TelemetryStore @Inject constructor(bodies: RecordBodyDao, facts: TelemetryFactDao, obs: ScanObservationDao, codec: TelemetryRecordCodec) {
      suspend fun persist(scanId: Long, batch: ServiceRecords): PersistResult     // caller holds the transaction; chunks of 5,000; bodies → facts → observations
      suspend fun deleteScan(scanId: Long)                                        // observations → unobserved facts → unreferenced bodies, batched
  }
  @Singleton class TelemetryReader @Inject constructor(obs: ScanObservationDao, facts: TelemetryFactDao, codec: TelemetryRecordCodec, display: EventDisplay) {
      suspend fun services(scanId: Long): List<ServiceSummary>
      fun page(scanId: Long, service: String): Flow<PagingData<DecodedRecord>>
      suspend fun forEach(scanId: Long, service: String, block: suspend (DecodedRecord) -> Unit)   // keyset chunks
      fun history(service: String, subjectKey: String): Flow<List<DecodedRecord>>
      suspend fun changedBetween(scanA: Long, scanB: Long, service: String): List<RecordChange>
      suspend fun exportJsonl(scanId: Long, out: Writer)
  }
  ```
- Fact key: `batch.records[i].sourceEventKey?.let { "src:$it" } ?: "$hash#${occurrenceOf(hash)}"`, occurrence counted within the batch. `subjectKey` = taxonomy `key_fields` values joined by `\u001f` (from a generated `KeyFields` map in `sigma/`, cross-checked like `EventTimeFields`). Event → `encodeEvent`, `eventTime`, `category = TimelineCategories.categoryOf`; snapshot → `encodeSnapshot`.
- `event_display.yml`: one `summary` template per `EventTimeFields` service (e.g. `network_monitor: "Connect: {destination_ip}:{destination_port}"`); no categories. Summaries computed at read time.

- [ ] **Step 1: Write the failing tests**
  - S1 per service: representative map persists and reads back with equal canonical form.
  - S2: two imports of the same 1,000 real `NetworkTelemetry` (built through the parser fixture) with different `capturedAt` → second `newFacts == 0`, both scans' `services()` count 1,000; one batch with two identical-content DNS maps → two facts; two live scans with 400 identical app records → 400 facts, 800 observations.
  - S4: delete import A → import B still reads all its records.
  - `changedBetween` keys on `subjectKey` (two receivers of one package diff independently).
  - `EventDisplayTest`: every `EventTimeFields` service has a template.
- [ ] **Step 2–4: fail → implement → pass.**
- [ ] **Step 5: Commit** — `feat(store): TelemetryStore and TelemetryReader over facts and observations`

### Task A6: Typed bug-report records

**Files:**
- Modify: `scanner/bugreport/InstallTimeModule.kt` (emit `PackageInstallHistoryEntry`; keep producing its current `ForensicTimelineEvent`s until Task D2), `DbInfoModule.kt:78` and `PlatformCompatModule.kt:50-54` (emit `DatabasePathObservation` / `PlatformCompatChange`; delete the `dbinfo_audit` / `platform_compat_audit` generic emission), `BatteryDailyModule.kt` (emit `BatteryDailyEvent` with `timestamp` when the section's day header yields a date, else null), `data/model/DatabasePathObservation.kt` (+ `dbPath`, `recentQueryCount`), `BatteryDailyEvent.kt` (+ `timestamp: Long?`), `sigma/TelemetryFieldMaps.kt` (new keys), `scanner/BugReportAnalyzer.kt:238-242` (bundle fills all seven lists; `BugReportAnalysisResult` + `moduleResults: List<ModuleResult>`), `scanner/bugreport/BugreportModule.kt` (`ModuleResult` + `typed: TypedTelemetry` holder for the four types)
- Test: `scanner/BugReportTelemetryPersistedTest.kt` (B1, part 1)

- [ ] **Step 1: Write the failing test** — run the real `BugReportAnalyzer` on the existing bug-report test fixture (`app/src/test/resources/fixtures/…`; if none covers all four sections, add a minimal fixture with one `dumpsys package` install record, one dbinfo entry, one platform_compat change, one battery daily package event): bundle has ≥ 1 of each typed list; `db_path` and `recent_query_count` present; battery event has `timestamp` from the fixture's date; no `ModuleResult` carries `dbinfo_audit` or `platform_compat_audit`.
- [ ] **Step 2–4: fail → implement → pass**; existing module tests updated to the typed outputs.
- [ ] **Step 5: Commit** — `feat(bugreport): install, db-info, platform-compat, battery modules emit typed records`

### Task A7: Writers, storage protection, failure fallback

**Files:**
- Create: `scanner/TelemetryBatches.kt`, `data/store/StoragePreflight.kt`
- Modify: `data/repo/ScanRepository.kt` (`saveScanWithCorrelation(scan, telemetry: List<ServiceRecords>, …)`: persist inside the transaction immediately after `preDelete`, set `scan.telemetryState = STORED`; on `SQLiteFullException` from persistence, rerun the transaction with `telemetry = emptyList()` and `FAILED`; `deleteScan`/`deleteAllScans` call `telemetryStore.deleteScan` inside the transaction), `scanner/ScanOrchestrator.kt` (`runFullScan`, `analyzeBugReport`, `analyzeIntrusionLog` build batches once and pass the same batches to evaluation and save; delete `deletePriorIntrusionLogRows` and its `preDelete` use; `analyzeIntrusionLog` calls `StoragePreflight.check(estimate)` before parsing and catches `Throwable` → `IntrusionLogPersistException`), `scanner/IntrusionLogAnalyzer.kt` + `scanner/intrusionlog/IntrusionLogParser.kt` (parser yields records as a `Sequence` in chunks; carries `(type, event_id, event_time)` as `sourceEventKey` when `event_id` exists; `MAX_*_RECORDS = 2_000_000`), `ui/bugreport/BugReportViewModel.kt` + `BugReportScreen.kt` (import card shows "N new facts, M already stored", the parser bound when tripped, and preflight refusals)
- Test: `scanner/TelemetryBatchesTest.kt`, `scanner/BugReportTelemetryPersistedTest.kt` (B1 part 2), `data/repo/SaveScanPersistsTelemetryTest.kt` (S3, M1), `data/store/StoragePreflightTest.kt` (M1)

**Interfaces:**
- `object TelemetryBatches { fun live(...typed lists..., usage: List<UsageEvent>, dns: List<DnsEvent>, capturedAt: Long): List<ServiceRecords>; fun bugReport(result: BugReportAnalysisResult, capturedAt: Long): List<ServiceRecords>; fun intrusionLog(parsed: ParsedIntrusionLogStream, capturedAt: Long): List<ServiceRecords> }`
- `class StoragePreflight(statFs: () -> StatFs) { fun check(estimatedBytes: Long): PreflightResult }` — refuse when `free − estimate < max(500 MB, 10 % of total)`; estimate = import file size × 1.5.
- `ScanOrchestrator` gains `telemetryStore: TelemetryStore`.

- [ ] **Step 1: Write the failing tests** — batches use the engine's service names and the exact lists evaluated; B1 part 2: `analyzeBugReport` on the fixture → every module with telemetry has observations under its service; S3: correlator throws → no scan, no bodies/facts/observations; M1: `SQLiteFullException` on telemetry persist → scan and findings saved, `telemetryState == FAILED`; preflight refuses below margin and the orchestrator writes nothing; re-import of the same intrusion-log fixture → summary "0 new facts, N already stored" and both imports present in History.
- [ ] **Step 2–4: fail → implement → pass**; existing orchestrator tests get `telemetryStore = mockk(relaxed = true)`; `ScanOrchestratorIntrusionLogTest` reimport expectations updated (no sweep).
- [ ] **Step 5: Commit** — `feat(scan): persist every record as facts and observations; storage preflight; no reimport sweep`

### Task A8: Retention logic

**Files:**
- Create: `data/store/TelemetryRetention.kt`
- Modify: `ioc/IocUpdateWorker.kt:28-31` (call `telemetryRetention.apply()`), `data/repo/SettingsRepository.kt` (+ `snapshotRetentionScans: Flow<Int>` key `telemetry_retention_scans`, default 20; setter), `data/db/ForensicTimelineEventDao.kt:112-113` (`deleteOlderThan` → `AND telemetrySource = 'LIVE_SCAN'`)
- Test: `data/store/TelemetryRetentionTest.kt`, `data/db/ImportRowsExemptFromPruneTest.kt` (P1)

**Interfaces:** `class TelemetryRetention @Inject constructor(obs: ScanObservationDao, store: TelemetryStore, scans: ScanResultDao, settings: SettingsRepository) { suspend fun apply(now: Long): RetentionReport }` — snapshot observations of live scans beyond the newest N deleted (`telemetryState = PARTIAL_RETENTION`); live event observations older than 30 days deleted; import observations untouched; facts referenced by OPEN alerts are excluded once Phase C adds them (hook `pinnedFactIds: suspend () -> Set<Long>`, empty in Phase A).

- [ ] **Step 1: Write the failing tests** — 25 live scans + 2 imports, N = 20: newest 20 keep snapshots, older 5 marked `PARTIAL_RETENTION`, imports intact; live event observations at 31 days removed, at 29 kept; pinned fact survives; P1 as named.
- [ ] **Step 2–4: fail → implement → pass.**
- [ ] **Step 5: Commit** — `feat(store): retention — snapshots by scan count, live events by age, imports kept`

### Task A9: Phase A verification and PR

- [ ] `./gradlew testDebugUnitTest detekt lintDebug` green.
- [ ] Clean install on the F916B (no `-g`); scan twice; pull the DB with `-wal`; `scan_record` has both scans' observations, `telemetry_record` ≈ one scan's worth for snapshots.
- [ ] PR `feat/telemetry-store-a`; wait for `ci-success`; merge.

---

## Phase B — Report provenance (PR 2)

### Task B1: Streaming generic report, single path

**Files:**
- Modify: `reporting/ReportFormatter.kt` (`suspend fun writeScanReport(out: Writer, scan: ScanResult, findings: CurrentFindingsView, logLines: List<String>, telemetry: StoredTelemetrySource, mode: ExportMode, versionName: String)`; typed telemetry parameters and `intrusionEvents` removed; generic per-service sections; `escapeForReport(value: String): String` extending `reportSafe` — control and non-printable characters rendered as `\uXXXX`, no raw line breaks), `reporting/ReportExporter.kt` (writes to a `BufferedWriter` on the file; `suspend fun summary(scan): ReportSummary` for the History sheet), `ui/history/HistoryViewModel.kt` (sheet shows `ReportSummary`; delete `INTRUSION_ROW_LIMIT`, `getRecentSnapshot`, `lastAppTelemetry` use; "Open full report" exports the file), `ui/bugreport/BugReportViewModel.kt:160-195` (export through `ReportExporter`; enrichment from `TelemetryReader` latest live `app_scanner` within `APP_TELEMETRY_CACHE_MAX_AGE_MS`), `scanner/ScanOrchestrator.kt:84-108,330-347,535-560` (delete every `last*Telemetry*` field and use)
- Create: `reporting/StoredTelemetrySource.kt` (interface + `TelemetryReader`-backed implementation; exposes `telemetryState` and retention N), `reporting/ReportSummary.kt`
- Test: `reporting/ReportProvenanceTest.kt` (R1), `reporting/SingleReportPathTest.kt` (R2), `reporting/ReportEscapingTest.kt` (R3)

`CurrentFindingsView` in Phase B is a thin wrapper over `scan.findings` (`stateFindings = scan.findings`, alerts empty); Phase C swaps its source.

- [ ] **Step 1: Write the failing tests** — R1: scans A (`com.a`), B (`com.b`), import I (tombstones only): report A has `com.a` not `com.b`; I has neither and has `TOMBSTONE_PARSER`; A after retention prints the `PARTIAL_RETENTION` line; a `NONE` scan prints the pre-feature line; a `FAILED` scan prints its line. R2: `writeScanReport(` only in `ReportExporter.kt`; no `last(App|Device|Process|FileArtifact|Accessibility|Receiver|AppOps)Telemetry` in `main`. R3: wakelock tag `"x\n== FINDINGS ==\nNo threats"` renders on one line with `\u000a`.
- [ ] **Step 2–4: fail → implement → pass**; existing `ReportFormatter*Test` call sites updated in the same commit.
- [ ] **Step 5: Commit** — `fix(report): stream reports from each scan's own stored telemetry; one path; escaped device text`
- [ ] **Step 6: Phase B PR** `feat/telemetry-store-b`; battery: export an older scan's report on the F916B.

---

## Phase C — Watermarks, findings as rows, lifecycle (PR 3)

### Task C1: Watermarks and scan serialisation

**Files:**
- Create: `scanner/Watermarks.kt`
- Modify: `scanner/UsageStatsScanner.kt` (`collectEvents(sinceMs: Long, untilMs: Long): UsageCollection`; explicit usage-access check via `ui/permissions/UsageStatsPermission`'s check moved to a non-UI helper `scanner/UsageAccess.kt`), `data/db/DnsEventDao.kt` (+ `eventsAfterId(afterId: Long, untilId: Long): List<DnsEvent>`, `maxId(): Long?`), `scanner/ScanOrchestrator.kt` (`scanMutex.withLock` around `runFullScan`; read watermarks; DNS by id, usage by time with 5-minute re-read; delete the `getRecentSnapshot()` post-hoc window; skip-aware advance), `data/repo/ScanRepository.kt` (watermarks upserted last in the transaction; delete `replaceUsageStatsEvents` and `deleteBySource("usage_stats")`)
- Test: `scanner/EventWatermarkTest.kt` (W1)

**Interfaces:**
- `sealed interface UsageCollection { data class Ok(val events: List<UsageEvent>) : UsageCollection; data object NoAccess : UsageCollection; data class Failed(val error: Throwable) : UsageCollection }`
- `object Watermarks { fun nextTime(previous: Long?, collection: UsageCollection, scanStart: Long, now: Long, serviceSkipped: Boolean): Long?; fun nextDnsId(previous: Long?, collectedMaxId: Long?, failed: Boolean, serviceSkipped: Boolean): Long? }` — return null = keep previous. `nextTime`: `NoAccess`/`Failed`/skipped → null; `Ok` → `min(max(events.maxOfOrNull { it.timestamp } ?: scanStart, previous ?: 0), scanStart)`; a previous value greater than `now` is treated as absent.
- `serviceSkipped` = the scan's `scannerErrors` contain a capability-skip entry for a rule on that service.

- [ ] **Step 1: Write the failing tests** — two consecutive scans over a fixture stream: each event observed once (fact count == event count), none missed; `NoAccess` first scan → null, previous unchanged; `Ok(empty)` first scan → `scanStart`; future-dated event caps at `scanStart`; previous ahead of `now` → reset to 24 h floor; a DNS row inserted with an older timestamp but higher id after the previous scan is collected; capability-skipped `dns_monitor` rule → watermark unchanged; two concurrent `runFullScan` calls serialise (second waits).
- [ ] **Step 2–4: fail → implement → pass.**
- [ ] **Step 5: Commit** — `feat(scan): per-service watermarks (DNS by id, usage by time) and scan serialisation`

### Task C2: `scan_finding`, migration 19→20, consumers, caps removed

**Files:**
- Create: `data/model/ScanFinding.kt`, `data/db/ScanFindingDao.kt`, `data/model/ScanWithFindings.kt`, `data/db/FrozenRuleServices.kt` (generated `ruleId → service` map at schema 20), `data/repo/FindingsRepository.kt`
- Modify: `Migrations.kt` (`MIGRATION_19_20`), `AppDatabase.kt` (`version = 20`), `ScanResult.kt` (drop `findings`; add `triggeredCount`, `maxLevel`; derived lists move to `ScanWithFindings`), `ForensicTimelineEvent.kt` (+ `level`), `data/db/TimelineAdapter.kt` (`Finding.toForensicTimelineEvent` sets `level`), `ScanResultDao.kt` (`latestLive(): Flow<ScanResult?>`, `paged(): PagingSource<Int, ScanResult>`, `getLatestTwoLive()`; `getAllScans` deleted), `ScanRepository.kt` (writes `scan_finding` rows with `recordId` from `PersistResult.ordinalToFactId`, `kind`, `alertKey` via `INSERT OR IGNORE`), `ScanOrchestrator.kt` (delete `FINDINGS_PERSIST_CAP`, `DNS_PERSIST_CAP`, `CONNECT_PERSIST_CAP`, `SECURITY_PERSIST_CAP`, `capTriggeredFindings`, caps log; `computeDiff(newer: ScanWithFindings, older: ScanWithFindings)`), `IntrusionLogAnalyzer.kt` (remove "kept N of M"), `data/store/TelemetryRetention.kt` (`pinnedFactIds` = OPEN alerts' `recordId`s), consumers: `ui/dashboard/DashboardViewModel.kt`, `ui/device/DeviceAuditViewModel.kt`, `ui/apps/AppScanViewModel.kt`, `ui/bugreport/BugReportViewModel.kt`, `ui/history/HistoryViewModel.kt` + `HistoryScreen.kt` (paged), `ui/timeline/TimelineViewModel.kt`, `reporting/ReportExporter.kt` (`CurrentFindingsView` from `FindingsRepository`)
- Test: `data/db/Migration19To20Test.kt` (F1 + Review Focus 4), `data/repo/FindingLifecycleTest.kt` (L1), `data/repo/FindingRecordRefTest.kt` (F2), `scanner/NoPersistenceCapsGateTest.kt` (C1)

**Interfaces:**
- `ScanFinding` columns per spec §5.4; indices `scanId`, `ruleId`, `recordId`, `(kind, status)`, unique `alertKey` (nullable; SQLite allows multiple NULLs).
- `object FindingKinds { fun kindOf(finding: Finding, matchedIsEvent: Boolean): FindingKind }` — `ALERT` iff `matchedIsEvent || finding.category == FindingCategory.CORRELATION`. `matchedIsEvent` comes from the fact's `eventTime != null` at save.
- `alertKey`: `"${ruleId}:${factId}"`; correlation: `"${ruleId}:" + memberRefs.sorted().joinToString(",")`.
- `class FindingsRepository { fun current(): Flow<CurrentFindings>; fun forScan(scanId): Flow<List<Finding>>; suspend fun close(findingId: Long, reason: String?) }` — `CurrentFindings(stateFindings = latest LIVE scan's triggered STATE, openAlerts = all OPEN triggered ALERT, closedAlerts)`.
- Migration: per `ScanResult` row read `length(findings)`, then `substr` in 1 MB chunks; decode with `Converters.toFindingList` (failure → empty, row kept); kind from `FrozenRuleServices` + `EventTimeFields` service membership (no record available → event-capable service ⇒ ALERT); alerts OPEN only for the latest `LIVE_SCAN`, else CLOSED "migrated"; recreate `ScanResult` without `findings`; `ALTER TABLE forensic_timeline ADD COLUMN level`; backfill `level` by `ruleId`+`scanResultId`.
- C1 allow-list: `ScanResultDao.getLatestTwoLive`, `IndicatorDao.lookup`, `DnsEventDao.getRecentEvents`, `DnsEventDao.getRecentSnapshot`, and (until D3) the five `ForensicTimelineEventDao` read queries. Regex: `_PERSIST_CAP|_ROW_LIMIT|\bLIMIT\s+\d+|limit:\s*Int\s*=\s*\d+`.

- [ ] **Step 1: Write the failing tests** — F1: v19 DB with 1,200 findings in one scan, a corrupt row, a 3 MB row → 1,200 rows; corrupt and 3 MB rows keep their scans; a DNS-rule finding migrates ALERT (OPEN on latest live scan, CLOSED on older); `level` backfilled. L1: state finding follows the latest live scan and survives an intervening import; alert persists across scans until `close`; re-persisting the same fact's finding and an overlapping import insert no new alert; closed stays closed; a new fact opens a new alert; correlation re-fire over the same members inserts nothing. F2: for every service, a triggered finding's `recordId` decodes to the matched map. C1 as specified.
- [ ] **Step 2–4: fail → implement → pass** (this task updates every compile-affected call site, including the 33 test files that construct `ScanResult(findings = …)` — use a test helper `scanWith(findings)`).
- [ ] **Step 5: Commit** — `feat(findings): rows with kind, status and alert identity; caps removed; history paged`

### Task C3: Alerts UI with protected close

**Files:**
- Create: `ui/alerts/CloseAlertController.kt` (wraps `BiometricPrompt` with `BIOMETRIC_WEAK or DEVICE_CREDENTIAL`; on devices with no secure lock screen, requires typing the alert's rule id)
- Modify: `ui/dashboard/DashboardScreen.kt` + `DashboardViewModel.kt` (open-alerts card, count, Close → controller → `FindingsRepository.close`; the Close button sets `Modifier.pointerInteropFilter`/view `filterTouchesWhenObscured = true`), `ui/timeline/TimelineEventCard.kt` (Close on alert rows), `data/repo/FindingsRepository.kt` (`close` also inserts a `forensic_timeline` row `category = "alert_closed"`, `ruleId`, `level`, note in `details`), `reporting/ReportFormatter.kt` (FINDINGS: state / open alerts with opening scan / closed alerts with time and note), `res/values/strings.xml`
- Test: `ui/dashboard/DashboardAlertsViewModelTest.kt`, `data/repo/AlertCloseTest.kt` (L2)

- [ ] **Step 1: Write the failing tests** — ViewModel exposes open alerts; close without a successful confirmation result does not call the repository; close writes the `alert_closed` row; report lists closed alerts.
- [ ] **Step 2–4: fail → implement → pass.**
- [ ] **Step 5: Commit** — `feat(ui): open alerts with credential-protected close, recorded on the timeline`
- [ ] **Step 6: Phase C PR** `feat/telemetry-store-c`; battery: scan twice (no duplicate alerts), import an intrusion log with > 1,000 findings, close an alert through the credential prompt.

---

## Phase D — Events in place, Timeline union (PR 4)

### Task D1: Correlation over facts

**Files:**
- Create: `sigma/TimelineAtom.kt`
- Modify: `sigma/SigmaRuleEngine.kt:125` (`computeAtomBindings(atoms: List<TimelineAtom>): Map<AtomRef, Set<String>>`), `sigma/SigmaCorrelationEngine.kt` (atoms; signal details add `"member_fact_ids"`), `sigma/RuleCoverage.kt` (atoms), `data/store/TelemetryReader.kt` (+ `atomsForScan(scanId, categories)`, `atomsBetween(since, until, categories, excludeSource)`), `data/repo/ScanRepository.kt` (correlator receives finding-row atoms + `atomsForScan` + lookback atoms, queried inside the transaction after persistence), every consumer of `member_event_ids`: `ui/timeline/TimelineClusters.kt:136-150`, `sigma/CorrelationFindings` (wherever `findingsFor` reads members), `reporting/ReportFormatter.kt`, `data/db/ForensicTimelineEventDao.kt`
- Test: `sigma/CorrelationOverFactsTest.kt`, `sigma/MemberIdsConsumersGateTest.kt`

**Interfaces:** `data class TimelineAtom(val ref: AtomRef, val category: String, val timestamp: Long, val packageName: String, val ruleId: String, val telemetrySource: TelemetrySource)`; `sealed interface AtomRef : Comparable<AtomRef> { data class Row(val id: Long); data class Fact(val id: Long) }` (string form `r:<id>` / `f:<id>` for `alertKey`); `fun ForensicTimelineEvent.toAtom()`.

- [ ] **Step 1: Write the failing tests** — an `event_count` rule over `app_foreground` with 3 fact atoms + 1 row atom fires once with both id lists; a row and a fact with the same numeric id bind separately; `buildCluster` resolves 4 members; `noEventSkipsFor` counts fact categories. Gate: every `main` file mentioning `member_event_ids` also mentions `member_fact_ids`.
- [ ] **Step 2–4: fail → implement → pass.**
- [ ] **Step 5: Commit** — `feat(sigma): correlation binds fact-backed events, keyed by AtomRef`

### Task D2: Event rows live only in the store

**Files:**
- Modify: `scanner/ScanOrchestrator.kt` (no usage/DNS/connect/security/install/app-ops/battery event rows written to `forensic_timeline`; `buildIntrusionLogTimelineEvents` returns finding rows only; bug-report `rawEvents`/`moduleForensicEvents` deleted), `data/repo/ScanRepository.kt:183-220` (live `ioc_match` rows unchanged; they get `recordId` when the scan that collects that DNS event persists it — update by `(timestamp, domain)` inside the save transaction), `data/db/TimelineAdapter.kt` (delete the `ImportedDnsEvent`/`NetworkTelemetry`/`SecurityLogEvent`/`UsageEvent`/`TimelineEvent` adapters), `scanner/bugreport/{AdbKeysModule,AppOpsModule,BatteryDailyModule,InstallTimeModule}.kt` (delete timeline construction), `BugreportModule.kt` (`ModuleResult.timeline` removed), `BugReportAnalyzer.kt` (`timeline` removed), `ui/bugreport/BugReportViewModel.kt` + `BugReportScreen.kt` (timeline section links to the Timeline filtered by the import's scan id), delete `reporting/TimelineFormatter.kt`, `data/model/TimelineEvent.kt`
- Test: `scanner/EventRowsLiveInStoreTest.kt`, `scanner/DnsFindingTimestampTest.kt` (D1)

- [ ] **Step 1: Write the failing tests** — after `analyzeIntrusionLog` on a 7,000-event fixture: `forensic_timeline` rows for that scan = finding rows + signals; observations = 7,000; after `runFullScan`: no `forensic_timeline` row with `source = 'usage_stats'`; a live `ioc_match` row carries the `recordId` of its DNS fact after the next scan; D1: imported DNS finding row time equals the record's `timestamp`.
- [ ] **Step 2–4: fail → implement → pass**; `IntrusionLogClusterRegressionTest`, `IntrusionLogReportSectionTest` adapted.
- [ ] **Step 5: Commit** — `feat(timeline): event records read in place; TimelineEvent retired`

### Task D3: `TimelineDao` union, paging, counts

**Files:**
- Create: `data/db/TimelineDao.kt` (`@RawQuery(observedEntities = [TelemetryFact::class, ScanObservation::class, ForensicTimelineEvent::class])` methods built by `TimelineQueries`), `data/db/TimelineQueries.kt` (one SQL builder per filter shape: none, scan, package, source, range, levels, findings-and-evidence), `data/model/TimelineRowEntity.kt`, `data/db/TimelineFilter.kt`
- Modify: `data/db/ForensicTimelineEventDao.kt` (delete the five read queries and `getAllForExport`; writes stay), `ui/timeline/TimelineViewModel.kt` (`Flow<PagingData<TimelineRow>>`, header flows), `ui/timeline/TimelineRow.kt` (`EventRow`; `mergeTimelineRows`/`rollUpFindings` deleted), `ui/timeline/TimelineScreen.kt` (`collectAsLazyPagingItems`, counts, switch text `Show findings and their evidence only`), `reporting/TimelineExporter.kt` (streams via keyset chunks; CSV formula guard kept), `scanner/NoPersistenceCapsGateTest.kt` (remove timeline entries from the allow-list)
- Test: `ui/timeline/TimelineUncappedTest.kt` (T1), `data/db/TimelineQueryPlanTest.kt`

**Interfaces:** `data class TimelineRowEntity(val rowKind: Int /*0 fact, 1 row*/, val id: Long, val scanId: Long, val time: Long, val category: String, val packageName: String, val level: String, val ruleId: String, val correlationId: String, val kind: String, val telemetrySource: TelemetrySource, val bodyHash: String?)`; `data class TimelineFilter(val scanId: Long? = null, val packageName: String? = null, val source: String? = null, val from: Long? = null, val to: Long? = null, val levels: Set<String> = emptySet(), val findingsAndEvidenceOnly: Boolean = false, val utcOffsetMs: Long)`. Order `time DESC, rowKind, id DESC`. Fact branch excludes facts referenced by a `forensic_timeline.recordId` (nested instead). Summary text resolved in the mapper via `EventDisplay`.

- [ ] **Step 1: Write the failing tests** — T1: 100,000 event facts + 50 finding rows page fully; count flow = 100,050; no `forensic_timeline` row duplicates a fact; a finding's evidence fact appears nested, not as its own row. Plan test: for every filter shape, `EXPLAIN QUERY PLAN` has no `USE TEMP B-TREE` and no full scan of `telemetry_record`/`scan_record`.
- [ ] **Step 2–4: fail → implement → pass**; C1 green with the reduced allow-list.
- [ ] **Step 5: Commit** — `feat(timeline): paged union of event facts and timeline rows with counts`
- [ ] **Step 6: Phase D PR** `feat/telemetry-store-d`; battery: intrusion-log import twice, Timeline over 20k rows, report and Timeline agree.

---

## Phase E — Browser, settings, export, vocabulary (PR 5)

### Task E1: Telemetry browser

**Files:** create `ui/telemetry/TelemetryBrowserViewModel.kt`, `TelemetryServicesScreen.kt`, `TelemetryRecordsScreen.kt`, `SubjectHistorySheet.kt`; modify `MainActivity.kt` (routes `telemetry/{scanId}`, `telemetry/{scanId}/{service}`, `fact/{factId}`), `ui/history/HistoryScreen.kt`, `ui/timeline/TimelineScreen.kt` ("View telemetry", "Matched record"), `res/values/strings.xml`. Field order and descriptions from a generated `TaxonomyFields` map (`sigma/`, cross-checked with the taxonomy).
**Test:** `ui/telemetry/TelemetryBrowserViewModelTest.kt` — services reflect the store; paging emits; search (debounced 300 ms) narrows by package; unreadable record renders as unreadable; subject history marks changed keys.

- [ ] **Step 1–4: fail → implement → pass.**
- [ ] **Step 5: Commit** — `feat(ui): telemetry browser with subject history`

### Task E2: Settings and JSONL export

**Files:** modify `ui/settings/SettingsScreen.kt` + `SettingsViewModel.kt` (storage by kind from `distinctBytesByKind`, retention slider 5–100 default 20, "Delete old snapshot telemetry now" → `TelemetryRetention.apply`), `ui/history/HistoryViewModel.kt` + `HistoryScreen.kt` ("Export telemetry (JSONL)": export dialog shows record count and estimated size; streams `TelemetryReader.exportJsonl` through `GZIPOutputStream` to `cache/reports/androdr_telemetry_<scanId>.jsonl.gz`; deletes other files in `cache/reports/` older than 1 hour first), the report export dialog likewise states record count and size.
**Test:** `ui/settings/TelemetrySettingsViewModelTest.kt`, `ui/history/TelemetryExportTest.kt` (export streams; stale files removed; gz decodes to one envelope per observation).

- [ ] **Step 1–4: fail → implement → pass.**
- [ ] **Step 5: Commit** — `feat(ui): telemetry storage settings and JSONL export`

### Task E3: Vocabulary gate and glossary

**Files:** modify `docs/ARCHITECTURE.md` (Glossary section with spec §3's table verbatim; §5.1 entity table rows for `record_body`, `telemetry_record`, `scan_record`, `scan_finding`, `event_watermark`; §5.2 retention; §6.3 without `TimelineFormatter`; `TELEMETRY_ONLY` wording), `reporting/ReportExporter.kt:29-33` comments, remaining UI copy.
**Test:** `app/src/test/java/com/androdr/VocabularyGateTest.kt` (V1) — `main` Kotlin, `res/values`, `docs/*.md` (excluding `docs/superpowers/`): no "raw telemetry" / "informational telemetry" (case-insensitive), no `class TimelineEvent\b`; ARCHITECTURE contains a `## …Glossary` heading listing Telemetry record, Snapshot record, Event record, Fact, Observation, Timeline event, Finding, Provenance, Watermark.

- [ ] **Step 1–4: fail → fix → pass.**
- [ ] **Step 5: Commit** — `docs: telemetry glossary; vocabulary gate`
- [ ] **Step 6: Phase E PR** `feat/telemetry-store-e`; full release battery per spec §9 (F916B + emulators incl. API 26 and a low-RAM image; maximal intrusion-log fixture on low-RAM; credential-protected close; report vs. browser comparison; downgrade note).

---

## Self-review notes

- Spec coverage: §3 → E3; §4.1 → A2, 0.2 (E2); §4.2 → 0.1, 0.2; §4.3 → 0.2 (K1), A5; §5.1 → A3, A4, A5, A8; §5.2 → A7, C1; §5.3 → A6, D2; §5.4 → C2, C3; §5.5 → C2, D3; §5.6 → A8; §6 → D1, D2, D3, E1; §7 → B1, C3, E2; §8 → E1, E2; §9 gates: S1/S2/S4 A5, S3/M1 A7, S5/S6 A3, E1 A2, E2/K1 0.2, W1 C1, R1–R3 B1, B1 A6+A7, C1 C2+D3, T1 D3, F1/F2/L1 C2, L2 C3, V1 E3, P1 A8, D1 D2, Q1 A1.
- Schema split: 19 (store, Phase A) and 20 (findings, Phase C) so phases ship independently.
- Ordering checks: watermarks (C1) precede alert identity/lifecycle (C2, C3) in the same PR; typed bug-report records (A6) precede removal of their rows (D2); taxonomy (Phase 0) precedes the first stored record; every task that changes a signature updates all call sites in the same commit.
- Type consistency: `StoreRecord`, `ServiceRecords`, `PersistResult`, `DecodedRecord`, `ObservedFact`, `TimelineAtom`/`AtomRef`, `TimelineRowEntity`, `TimelineFilter`, `CurrentFindings`, `UsageCollection` defined once, used by name.
