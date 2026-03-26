# Known-App DB — Design Spec
**Date:** 2026-03-25
**Status:** Approved for implementation

---

## Problem

`AppScanner` suppresses false positives through a hardcoded `knownSystemPrefixes` list inside
`scan()`. This list has grown ad-hoc across sessions as real devices expose new OEM package
prefixes. It has no update mechanism, no test coverage for its contents, and no ability to
detect impersonation — a sideloaded APK using a known-good package name to masquerade as a
legitimate app.

---

## Goals

1. Replace `knownSystemPrefixes` with a data-driven, remotely-updatable known-app database.
2. Enable impersonation detection: flag sideloaded apps whose package name matches a known
   legitimate app.
3. Mirror the existing IOC DB architecture (Room + WorkManager + in-memory cache + bundled
   fallback) so no new patterns are introduced.
4. Require zero API keys or secrets.

---

## Community Sources

| Feed | URL | Content | Auth |
|---|---|---|---|
| UAD-ng | `https://raw.githubusercontent.com/Universal-Debloater-Alliance/universal-android-debloater-next-generation/main/resources/assets/uad_lists.json` | 1,000+ OEM/AOSP/carrier/Google pre-installed packages | None |
| Plexus | `https://plexus.techlore.tech/api/v1/apps?limit=500` (paginated) | 9,333 well-known user apps with package names | None |

Both feeds are community-maintained and freely accessible without credentials.

---

## Data Model

### `KnownAppCategory`

See `KnownAppEntry` section below for the full annotated definition. The enum is defined
alongside `KnownAppEntry` in `data/model/KnownAppEntry.kt` and annotated `@Serializable`.

```kotlin
@Serializable
enum class KnownAppCategory {
    AOSP,     // Standard Android OS apps
    GOOGLE,   // Google apps
    OEM,      // OEM/carrier/chipset/partnership pre-installs (includes UAD-ng "Carrier" and "Misc")
    USER_APP  // Well-known user-facing apps (for impersonation detection)
}
```

UAD-ng categories `"Carrier"` and `"Misc"` are both mapped to `OEM`. The scanner's goal is
false-positive suppression, not category fidelity — both carrier and miscellaneous pre-installs
should suppress firmware-implant and sideload flags. A future enum extension can separate these
if needed.

Category drives two distinct scanner behaviours:

| Category | FLAG_SYSTEM + unknown prefix | Sideloaded (untrusted source) |
|---|---|---|
| OEM / AOSP / GOOGLE | suppress firmware-implant flag | suppress sideload flag |
| USER_APP | n/a | raise impersonation flag (HIGH) |

When `knownApp` is `null` (cache cold and not in bundled snapshot), `isKnownOemApp` evaluates
to `false` because `null in setOf(...)` is `false` in Kotlin. This is the correct conservative
behaviour — unknown apps are never suppressed. The bundled snapshot (loaded before any scan via
`KnownAppDatabase`) ensures the cache is never fully cold on first launch.

### `KnownAppEntry` (domain model)

Both `KnownAppCategory` and `KnownAppEntry` must be annotated `@Serializable` so that
`KnownAppDatabase` can deserialize `res/raw/known_good_apps.json` with
`Json.decodeFromString<List<KnownAppEntry>>(raw)`. Without these annotations the
kotlinx.serialization compiler plugin will reject the build.

```kotlin
@Serializable
enum class KnownAppCategory { AOSP, GOOGLE, OEM, USER_APP }

@Serializable
data class KnownAppEntry(
    val packageName: String,
    val displayName: String,
    val category: KnownAppCategory,
    val sourceId: String,
    val fetchedAt: Long
)
```

### `KnownAppDbEntry` (Room entity)

```kotlin
@Entity(tableName = "known_app_entries")
data class KnownAppDbEntry(
    @PrimaryKey val packageName: String,
    val displayName: String,
    val category: String,   // KnownAppCategory.name()
    val sourceId: String,   // column name: "sourceId" (intentionally differs from domain_ioc_entries.source)
    val fetchedAt: Long
)
```

**Room migration 3→4** — three changes required in `AppDatabase.kt`:
1. Change `version = 3` to `version = 4` in the `@Database` annotation.
2. Add `KnownAppDbEntry::class` to the `entities = [...]` array (Room's annotation processor
   requires every entity to be declared here; missing it causes a build-time schema mismatch
   even if the migration DDL is correct).
3. Add the `knownAppEntryDao()` abstract function.

Also add `MIGRATION_3_4` to `Migrations.kt` and call `.addMigrations(..., MIGRATION_3_4)` in
`AppModule.provideDatabase()`.

```kotlin
val MIGRATION_3_4 = object : Migration(3, 4) {
    override fun migrate(db: SupportSQLiteDatabase) {
        db.execSQL(
            """CREATE TABLE IF NOT EXISTS known_app_entries (
                packageName TEXT NOT NULL PRIMARY KEY,
                displayName TEXT NOT NULL,
                category    TEXT NOT NULL,
                sourceId    TEXT NOT NULL,
                fetchedAt   INTEGER NOT NULL
            )"""
        )
    }
}
```

---

## Feed Layer

### `KnownAppFeed` interface

```kotlin
interface KnownAppFeed {
    val sourceId: String
    suspend fun fetch(): List<KnownAppEntry>   // returns empty list on any failure
}
```

### `UadKnownAppFeed`

- Fetches UAD-ng `uad_lists.json` (flat JSON object keyed by package name).
- Parser: key → `packageName`; `"description"` → `displayName`; `"list"` field →
  `KnownAppCategory`:
  - `"OEM"` → `OEM`
  - `"Carrier"` → `OEM` (carrier pre-installs suppressed same as OEM; see rationale above)
  - `"Misc"` → `OEM` (miscellaneous pre-installs suppressed same as OEM; see rationale above)
  - `"AOSP"` → `AOSP`
  - `"Google"` → `GOOGLE`
- Each entry's `fetchedAt` is set to `System.currentTimeMillis()` at parse time.
- `sourceId = "uad_ng"`.
- On HTTP error or parse failure: logs warning, returns empty list.

### `PlexusKnownAppFeed`

Fetches all pages from `https://plexus.techlore.tech/api/v1/apps?limit=500&page={n}`.

Response shape:

```json
{
  "data": [{ "name": "WhatsApp", "package": "com.whatsapp", "updated_at": "...", "icon_url": null }],
  "meta": { "current_page": 1, "total_pages": 19, "per_page": 500, "total_apps": 9333 }
}
```

Pagination loop: fetch page 1, continue incrementing page number while `current_page < total_pages`.

Internal data classes for parsing:

```kotlin
@Serializable
data class PlexusApp(val name: String, val `package`: String)

@Serializable
data class PlexusMeta(
    @SerialName("current_page") val currentPage: Int,
    @SerialName("total_pages") val totalPages: Int
)

@Serializable
data class PlexusResponse(val data: List<PlexusApp>, val meta: PlexusMeta)
```

Each entry's `fetchedAt` is set to `System.currentTimeMillis()` at the point each page is
parsed (consistent with `UadKnownAppFeed` and with how other feed implementations populate
timestamps).

All entries mapped to `KnownAppCategory.USER_APP`. `sourceId = "plexus"`.
On HTTP error or parse failure on any page: logs warning, returns all entries collected so far
(partial results are better than nothing for impersonation detection).

---

## Storage + Resolver

### `KnownAppEntryDao`

Uses `@Insert(onConflict = OnConflictStrategy.REPLACE)` to match the convention of all
existing DAOs (`IocEntryDao`, `DomainIocEntryDao`). The `deleteStaleEntries` parameter is
named `olderThan` (same name as `IocEntryDao` and `DomainIocEntryDao`) to avoid copy-paste
errors when writing `KnownAppUpdater`.

```kotlin
@Dao
interface KnownAppEntryDao {
    @Query("SELECT * FROM known_app_entries")
    suspend fun getAll(): List<KnownAppDbEntry>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsertAll(entries: List<KnownAppDbEntry>)

    @Query("DELETE FROM known_app_entries WHERE sourceId = :sourceId AND fetchedAt < :olderThan")
    suspend fun deleteStaleEntries(sourceId: String, olderThan: Long)

    @Query("SELECT COUNT(*) FROM known_app_entries")
    suspend fun count(): Int

    @Query("SELECT MAX(fetchedAt) FROM known_app_entries")
    suspend fun mostRecentFetchTime(): Long?
}
```

### `KnownAppUpdater`

Parallel fetch across all feeds, upsert to Room, stale-entry cleanup, cache refresh.
Mirrors `DomainIocUpdater` exactly (including the `withContext(Dispatchers.IO)` wrapper,
coroutineScope/async pattern, and `refreshCache()` call at the end of `update()`).

```kotlin
@Singleton
class KnownAppUpdater @Inject constructor(
    private val dao: KnownAppEntryDao,
    private val resolver: KnownAppResolver,
    @JvmSuppressWildcards private val feeds: List<KnownAppFeed>
) {
    suspend fun update(): Int = withContext(Dispatchers.IO) {
        var totalStored = 0
        coroutineScope {
            val deferreds = feeds.map { feed ->
                async {
                    val entries = feed.fetch()
                    if (entries.isNotEmpty()) {
                        dao.upsertAll(entries.map { it.toDbEntry() })
                        val runStart = entries.minOf { it.fetchedAt } - 1
                        dao.deleteStaleEntries(feed.sourceId, runStart)
                        Log.i(TAG, "Known-app feed '${feed.sourceId}': ${entries.size} entries upserted")
                    } else {
                        Log.w(TAG, "Known-app feed '${feed.sourceId}': no entries returned")
                    }
                    entries.size
                }
            }
            totalStored = deferreds.sumOf { it.await() }
        }
        resolver.refreshCache()
        Log.i(TAG, "Known-app update complete — fetched: $totalStored, DB: ${dao.count()}")
        totalStored
    }

    companion object {
        private const val TAG = "KnownAppUpdater"
    }
}

private fun KnownAppEntry.toDbEntry() = KnownAppDbEntry(
    packageName = packageName,
    displayName = displayName,
    category    = category.name,
    sourceId    = sourceId,
    fetchedAt   = fetchedAt
)
```

### `KnownAppResolver`

`AtomicReference<Map<String, KnownAppEntry>>` cache, same pattern as `IocResolver`.
The lookup priority is: live Room cache → bundled `KnownAppDatabase`. This mirrors `IocResolver`
exactly. `refreshCache()` is called by `KnownAppUpdater.update()` at the end of each feed
update run — there is no need to call it manually from `AppScanner` or any ViewModel.

When `cache.get()` is `null` (before the first `KnownAppUpdater.update()` completes),
the `?.get()` short-circuits to `null` and the bundled fallback is consulted. There is no
cold-start gap because `KnownAppDatabase` is populated from the bundled snapshot at injection
time.

```kotlin
@Singleton
class KnownAppResolver @Inject constructor(
    private val dao: KnownAppEntryDao,
    private val bundled: KnownAppDatabase
) {
    private val cache = AtomicReference<Map<String, KnownAppEntry>?>(null)

    suspend fun refreshCache() = withContext(Dispatchers.IO) {
        cache.set(dao.getAll().associate { it.packageName to it.toDomain() })
    }

    fun lookup(packageName: String): KnownAppEntry? =
        cache.get()?.get(packageName) ?: bundled.lookup(packageName)
}

private fun KnownAppDbEntry.toDomain() = KnownAppEntry(
    packageName = packageName,
    displayName = displayName,
    category    = KnownAppCategory.valueOf(category),
    sourceId    = sourceId,
    fetchedAt   = fetchedAt
)
```

### `KnownAppDatabase`

Loads `res/raw/known_good_apps.json` lazily (identical to `IocDatabase`). Provides O(1)
lookup via internal `HashMap`. Is an `@Inject constructor` singleton — no `@Provides` needed
in `AppModule` (same as `IocDatabase`).

Exposes `val size: Int` computed from the lazy list so `DashboardViewModel` can show a
non-zero count before remote feeds have loaded:

```kotlin
@Singleton
class KnownAppDatabase @Inject constructor(
    @ApplicationContext private val context: Context,
) {
    private val json = Json { ignoreUnknownKeys = true }

    private val entries: List<KnownAppEntry> by lazy { /* load res/raw/known_good_apps.json */ }
    private val map: HashMap<String, KnownAppEntry> by lazy {
        HashMap<String, KnownAppEntry>(entries.size * 2).also { m ->
            entries.forEach { e -> m[e.packageName] = e }
        }
    }

    val size: Int get() = entries.size   // safe: lazy list is initialised before first access

    fun lookup(packageName: String): KnownAppEntry? = map[packageName]
    fun getAll(): List<KnownAppEntry> = entries
}
```

---

## Bundled Snapshot — `res/raw/known_good_apps.json`

Unified JSON array combining both feed schemas:

```json
[
  { "packageName": "com.sem.factoryapp",      "displayName": "Samsung Factory App", "category": "OEM",      "sourceId": "bundled", "fetchedAt": 0 },
  { "packageName": "com.touchtype.swiftkey",  "displayName": "SwiftKey",            "category": "OEM",      "sourceId": "bundled", "fetchedAt": 0 },
  { "packageName": "com.whatsapp",            "displayName": "WhatsApp",            "category": "USER_APP", "sourceId": "bundled", "fetchedAt": 0 },
  { "packageName": "org.telegram.messenger",  "displayName": "Telegram",            "category": "USER_APP", "sourceId": "bundled", "fetchedAt": 0 }
]
```

Generated by `scripts/generate_known_good_apps.py` — a one-off dev script that fetches
UAD-ng + all Plexus pages, merges them into this schema, and writes the file. The script is
committed to the repo and documented in `CLAUDE.md` under "Common commands". Maintainers
re-run it periodically and commit the updated snapshot.

---

## AppScanner Integration

### Constructor

```kotlin
@Singleton
class AppScanner @Inject constructor(
    @ApplicationContext private val context: Context,
    private val iocResolver: IocResolver,
    private val knownAppResolver: KnownAppResolver      // new
)
```

### Replacement of `knownSystemPrefixes`

The `knownSystemPrefixes` list and `looksLikeKnownSystem` variable are removed entirely.
Replaced by a single resolver call:

```kotlin
val knownApp: KnownAppEntry? = knownAppResolver.lookup(packageName)
val isKnownOemApp = knownApp?.category in setOf(
    KnownAppCategory.OEM, KnownAppCategory.AOSP, KnownAppCategory.GOOGLE
)
```

`isKnownOemApp` replaces every use of `looksLikeKnownSystem`:
- Firmware-implant check: `if (isSystemApp && !isKnownOemApp)`
- Sideload gate: `if (!isSystemApp && !fromTrustedStore && !isKnownOemApp)`

### Impersonation detection (new, check 2b)

```kotlin
// ── 2b. Impersonation detection ───────────────────────────────
// A USER_APP entry sideloaded from an untrusted source is likely
// a spoofed APK masquerading as the legitimate app.
if (!isSystemApp && !fromTrustedStore && knownApp?.category == KnownAppCategory.USER_APP) {
    riskLevel = RiskLevel.HIGH
    reasons.add(
        "Package name matches well-known app '${knownApp.displayName}' but was not " +
            "installed from a trusted store — possible impersonation"
    )
}
```

### Full scan decision tree

```
for each installed package:
  1.  IOC check          → CRITICAL if known malware/stalkerware
  2.  Permission scoring → HIGH/CRITICAL if sideloaded + ≥2 surveillance perms
  2b. Impersonation      → HIGH if USER_APP in DB + sideloaded from untrusted source
  3.  Sideload flag      → MEDIUM if not system + not trusted store + not known OEM app
  4.  Firmware implant   → HIGH if FLAG_SYSTEM + not OEM/AOSP/GOOGLE in DB
```

---

## WorkManager Integration

`runBothUpdaters` is renamed `runAllUpdaters` and extended with the third updater.
Show the full updated `IocUpdateWorker` constructor and `doWork()` body:

```kotlin
@HiltWorker
class IocUpdateWorker @AssistedInject constructor(
    @Assisted context: Context,
    @Assisted params: WorkerParameters,
    private val remoteIocUpdater: RemoteIocUpdater,
    private val domainIocUpdater: DomainIocUpdater,
    private val knownAppUpdater: KnownAppUpdater      // new
) : CoroutineWorker(context, params) {

    @Suppress("TooGenericExceptionCaught")
    override suspend fun doWork(): Result {
        return try {
            val fetched = runAllUpdaters(remoteIocUpdater, domainIocUpdater, knownAppUpdater)
            Log.i(TAG, "Worker finished — $fetched entries fetched total")
            Result.success()
        } catch (e: Exception) {
            Log.e(TAG, "Worker failed: ${e.message}")
            Result.retry()
        }
    }

    companion object {
        private const val TAG = "IocUpdateWorker"
        const val WORK_NAME = "ioc_periodic_update"
    }
}

internal suspend fun runAllUpdaters(
    remoteIoc: RemoteIocUpdater,
    domainIoc: DomainIocUpdater,
    knownApp: KnownAppUpdater
): Int = coroutineScope {
    val a = async { remoteIoc.update() }
    val b = async { domainIoc.update() }
    val c = async { knownApp.update() }
    a.await() + b.await() + c.await()
}
```

**`IocUpdateWorkerTest` must be updated**: rename all `runBothUpdaters` call sites to
`runAllUpdaters`, add a `mockKnownAppUpdater` stub returning `15`, update the total assertion
from `assertEquals(30, total)` to `assertEquals(45, total)`, and pass the new mock to the
exception-propagation test.

---

## Dashboard

`ThreatDatabaseCard` gains a third row. `knownAppEntryCount` is initialised to
`knownAppDatabase.size` (bundled snapshot count, via the `KnownAppDatabase.size` property
defined above) so the card shows a non-zero value on first launch before remote feeds load.

| Row | Count | Label |
|---|---|---|
| Package IOC | `iocEntryDao.count()` (+ bundled) | "Known malware packages" |
| Domain IOC | `domainIocEntryDao.count()` | "Known IOC domains" |
| Known apps | `knownAppEntryDao.count()` (init: `knownAppDatabase.size`) | "Known app signatures" |

`DashboardViewModel` adds `knownAppEntryCount`, `knownAppLastUpdated`, `isUpdatingKnownApps`
state flows — same pattern as the existing domain IOC state. `KnownAppDatabase` is injected
into `DashboardViewModel` so its `.size` is available for the initial value.

---

## DI (AppModule additions)

```kotlin
// DAO provider — no @Singleton, matches convention of all other DAO providers
@Provides
fun provideKnownAppEntryDao(db: AppDatabase): KnownAppEntryDao = db.knownAppEntryDao()

// Feed list for Hilt injection into KnownAppUpdater
@Provides @Singleton
fun provideKnownAppFeeds(): @JvmSuppressWildcards List<KnownAppFeed> =
    listOf(UadKnownAppFeed(), PlexusKnownAppFeed())
```

`KnownAppDatabase` and `KnownAppResolver` use `@Inject constructor` — no `@Provides` needed.

Also add `MIGRATION_3_4` to `AppModule.provideDatabase()`:

```kotlin
.addMigrations(MIGRATION_1_2, MIGRATION_2_3, MIGRATION_3_4)
```

---

## Testing

| Component | Tests |
|---|---|
| `UadKnownAppFeed` | parse OEM entry → `OEM`; parse AOSP entry → `AOSP`; parse Google entry → `GOOGLE`; parse Carrier/Misc entries → `OEM`; empty JSON object; malformed JSON |
| `PlexusKnownAppFeed` | parse single page (currentPage == totalPages); multi-page pagination (collects all pages); empty data array; HTTP error returns partial results; malformed JSON on page N returns partial |
| `KnownAppUpdater` | count returned; `upsertAll` called per feed; `deleteStaleEntries` called with correct sourceId and olderThan timestamp; `refreshCache` called after upsert; zero entries on all-empty feeds |
| `KnownAppResolverTest` | null cache falls back to bundled entry; populated cache returns cached entry; populated cache miss falls back to bundled; neither source has entry returns null |
| `IocUpdateWorkerTest` | rename `runBothUpdaters` → `runAllUpdaters`; add `mockKnownAppUpdater` returning 15; update total assertion to 45; update exception-propagation test to pass all three mocks |
| `AppScannerTest` | (1) Update `setUp()` to inject `mockKnownAppResolver = mockk()` with `every { lookup(any()) } returns null` as default; update all `AppScanner(mockContext, mockIocResolver)` constructor calls to `AppScanner(mockContext, mockIocResolver, mockKnownAppResolver)`. (2) Update existing OEM-prefix tests that currently rely on `knownSystemPrefixes`: `OEM-prefixed user app with null installer is not flagged as sideloaded` — stub `lookup("com.samsung.android.tvplus")` returning an `OEM` `KnownAppEntry`; `Samsung ecosystem installer is treated as trusted` — no stub needed (trusted-store path); `system app with known OEM prefix is not flagged` — stub `lookup("com.android.settings")` returning an `AOSP` `KnownAppEntry`. (3) Add new tests: OEM DB hit suppresses firmware-implant; OEM DB hit suppresses sideload flag; USER_APP DB hit from untrusted source → impersonation HIGH; USER_APP DB hit from trusted store → no flag; null lookup → existing behaviour unchanged |

---

## Files Changed / Created

| File | Change |
|---|---|
| `data/model/KnownAppEntry.kt` | new — domain model + category enum |
| `data/db/KnownAppDbEntry.kt` | new — Room entity |
| `data/db/KnownAppEntryDao.kt` | new — DAO |
| `data/db/AppDatabase.kt` | bump `version = 3` → `version = 4`; add `KnownAppDbEntry` entity; add `knownAppEntryDao()` abstract fun |
| `ioc/KnownAppFeed.kt` | new — interface |
| `ioc/feeds/UadKnownAppFeed.kt` | new |
| `ioc/feeds/PlexusKnownAppFeed.kt` | new |
| `ioc/KnownAppUpdater.kt` | new |
| `ioc/KnownAppDatabase.kt` | new — bundled fallback (loads `res/raw/known_good_apps.json`); exposes `val size: Int` |
| `ioc/KnownAppResolver.kt` | new |
| `ioc/IocUpdateWorker.kt` | rename `runBothUpdaters` → `runAllUpdaters`; add `KnownAppUpdater` constructor param; update `doWork()` call site |
| `scanner/AppScanner.kt` | inject `KnownAppResolver`; remove `knownSystemPrefixes`; add impersonation check |
| `ui/dashboard/DashboardViewModel.kt` | inject `KnownAppDatabase`; add known-app state flows; init count from `knownAppDatabase.size` |
| `ui/dashboard/DashboardScreen.kt` | third row in `ThreatDatabaseCard` |
| `di/AppModule.kt` | add DAO + feed list providers; add `MIGRATION_3_4` to `addMigrations` |
| `res/raw/known_good_apps.json` | new — bundled snapshot |
| `Migrations.kt` | add `MIGRATION_3_4` |
| `CLAUDE.md` | document `scripts/generate_known_good_apps.py` under "Common commands" |
| `scripts/generate_known_good_apps.py` | new — fetches UAD-ng + Plexus, writes `known_good_apps.json` |
| `app/src/test/java/com/androdr/ioc/IocUpdateWorkerTest.kt` | update for `runAllUpdaters` rename + third updater mock |
| `app/src/test/java/com/androdr/scanner/AppScannerTest.kt` | update constructor; update OEM-prefix tests with resolver stubs; add impersonation test cases |
| `app/src/test/java/com/androdr/ioc/KnownAppResolverTest.kt` | new |
