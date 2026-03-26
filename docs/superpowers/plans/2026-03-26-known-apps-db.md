# Known-App DB Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the hardcoded `knownSystemPrefixes` list in `AppScanner` with a data-driven, remotely-updatable known-app database that also detects impersonation of well-known apps.

**Architecture:** Two community feeds (UAD-ng for OEM/system apps, Plexus for user-facing apps) are fetched by `KnownAppUpdater` and stored in a Room table. `KnownAppResolver` provides synchronous O(1) lookups backed by an in-memory `AtomicReference` cache with a bundled-JSON fallback — identical to the existing `IocResolver` pattern. `AppScanner` calls the resolver to suppress OEM false positives and flag impersonation attempts.

**Tech Stack:** Kotlin, Room 2.x, Hilt, kotlinx.serialization, WorkManager, `java.net.HttpURLConnection` (no OkHttp, mirrors existing feeds), JUnit 4 + MockK

---

## File Map

### New files
| File | Responsibility |
|---|---|
| `app/src/main/java/com/androdr/data/model/KnownAppEntry.kt` | `@Serializable KnownAppCategory` enum + `@Serializable KnownAppEntry` domain model |
| `app/src/main/java/com/androdr/data/db/KnownAppDbEntry.kt` | Room `@Entity` for `known_app_entries` table |
| `app/src/main/java/com/androdr/data/db/KnownAppEntryDao.kt` | DAO: getAll, upsertAll, deleteStaleEntries, count, mostRecentFetchTime |
| `app/src/main/java/com/androdr/ioc/KnownAppFeed.kt` | `KnownAppFeed` interface |
| `app/src/main/java/com/androdr/ioc/feeds/UadKnownAppFeed.kt` | Fetches + parses UAD-ng `uad_lists.json` |
| `app/src/main/java/com/androdr/ioc/feeds/PlexusKnownAppFeed.kt` | Fetches + paginates Plexus app list |
| `app/src/main/java/com/androdr/ioc/KnownAppDatabase.kt` | Bundled-JSON fallback (lazy map, `val size`) |
| `app/src/main/java/com/androdr/ioc/KnownAppResolver.kt` | AtomicReference cache + bundled fallback |
| `app/src/main/java/com/androdr/ioc/KnownAppUpdater.kt` | Parallel feed fetch → Room upsert → cache refresh |
| `app/src/main/res/raw/known_good_apps.json` | Bundled snapshot (starts as `[]`, replaced by script) |
| `scripts/generate_known_good_apps.py` | Dev script: fetches UAD-ng + Plexus, writes JSON |
| `app/src/test/java/com/androdr/ioc/UadKnownAppFeedTest.kt` | Unit tests for UAD-ng parser |
| `app/src/test/java/com/androdr/ioc/PlexusKnownAppFeedTest.kt` | Unit tests for Plexus parser + pagination |
| `app/src/test/java/com/androdr/ioc/KnownAppResolverTest.kt` | Unit tests for cache fallback logic |
| `app/src/test/java/com/androdr/ioc/KnownAppUpdaterTest.kt` | Unit tests for updater orchestration |

### Modified files
| File | Change |
|---|---|
| `app/src/main/java/com/androdr/data/db/Migrations.kt` | Add `MIGRATION_3_4` |
| `app/src/main/java/com/androdr/data/db/AppDatabase.kt` | `version = 4`, add entity + abstract DAO |
| `app/src/main/java/com/androdr/di/AppModule.kt` | Add DAO provider, feed list provider, `MIGRATION_3_4` |
| `app/src/main/java/com/androdr/ioc/IocUpdateWorker.kt` | Rename `runBothUpdaters` → `runAllUpdaters`, add `KnownAppUpdater` |
| `app/src/main/java/com/androdr/scanner/AppScanner.kt` | Remove `knownSystemPrefixes`; inject + use `KnownAppResolver`; add impersonation check |
| `app/src/main/java/com/androdr/ui/dashboard/DashboardViewModel.kt` | Inject `KnownAppDatabase` + `KnownAppUpdater`; add known-app state flows |
| `app/src/main/java/com/androdr/ui/dashboard/DashboardScreen.kt` | Third row in `ThreatDatabaseCard` |
| `app/src/test/java/com/androdr/ioc/IocUpdateWorkerTest.kt` | Rename + add third updater mock |
| `app/src/test/java/com/androdr/scanner/AppScannerTest.kt` | Update constructor; stub OEM tests; add impersonation tests |
| `CLAUDE.md` | Document `scripts/generate_known_good_apps.py` |

---

## Task 1: Data model + Room migration

**Files:**
- Create: `app/src/main/java/com/androdr/data/model/KnownAppEntry.kt`
- Create: `app/src/main/java/com/androdr/data/db/KnownAppDbEntry.kt`
- Modify: `app/src/main/java/com/androdr/data/db/Migrations.kt`
- Modify: `app/src/main/java/com/androdr/data/db/AppDatabase.kt`
- Create: `app/src/main/res/raw/known_good_apps.json` (placeholder)

- [ ] **Step 1: Create the domain model**

```kotlin
// app/src/main/java/com/androdr/data/model/KnownAppEntry.kt
package com.androdr.data.model

import kotlinx.serialization.Serializable

@Serializable
enum class KnownAppCategory {
    AOSP,
    GOOGLE,
    OEM,
    USER_APP
}

@Serializable
data class KnownAppEntry(
    val packageName: String,
    val displayName: String,
    val category: KnownAppCategory,
    val sourceId: String,
    val fetchedAt: Long
)
```

- [ ] **Step 2: Create the Room entity**

```kotlin
// app/src/main/java/com/androdr/data/db/KnownAppDbEntry.kt
package com.androdr.data.db

import androidx.room.Entity
import androidx.room.PrimaryKey

@Entity(tableName = "known_app_entries")
data class KnownAppDbEntry(
    @PrimaryKey val packageName: String,
    val displayName: String,
    val category: String,   // KnownAppCategory.name
    val sourceId: String,
    val fetchedAt: Long
)
```

- [ ] **Step 3: Add MIGRATION_3_4 to Migrations.kt**

Append after the existing `MIGRATION_2_3` block:

```kotlin
val MIGRATION_3_4 = object : Migration(3, 4) {
    override fun migrate(database: SupportSQLiteDatabase) {
        database.execSQL(
            """
            CREATE TABLE IF NOT EXISTS known_app_entries (
                packageName TEXT NOT NULL PRIMARY KEY,
                displayName TEXT NOT NULL,
                category    TEXT NOT NULL,
                sourceId    TEXT NOT NULL,
                fetchedAt   INTEGER NOT NULL
            )
            """.trimIndent()
        )
    }
}
```

- [ ] **Step 4: Update AppDatabase**

Change the `@Database` annotation from `version = 3` to `version = 4`, add `KnownAppDbEntry::class` to the `entities` array, and add the abstract DAO method:

```kotlin
@Database(
    entities = [ScanResult::class, DnsEvent::class, IocEntry::class, DomainIocEntry::class,
                KnownAppDbEntry::class],
    version = 4,
    exportSchema = false
)
@TypeConverters(Converters::class)
abstract class AppDatabase : RoomDatabase() {
    abstract fun scanResultDao(): ScanResultDao
    abstract fun dnsEventDao(): DnsEventDao
    abstract fun iocEntryDao(): IocEntryDao
    abstract fun domainIocEntryDao(): DomainIocEntryDao
    abstract fun knownAppEntryDao(): KnownAppEntryDao
}
```

Add the import for `KnownAppDbEntry` and `KnownAppEntryDao` at the top of the file.

- [ ] **Step 5: Create placeholder bundled snapshot**

```json
[]
```

Save to `app/src/main/res/raw/known_good_apps.json`. This empty array lets `KnownAppDatabase` load cleanly; the real data is generated in Task 10.

- [ ] **Step 6: Verify the build compiles**

```bash
./gradlew assembleDebug
```

Expected: BUILD SUCCESSFUL. Fix any missing imports before continuing.

- [ ] **Step 7: Commit**

```bash
git add app/src/main/java/com/androdr/data/model/KnownAppEntry.kt \
        app/src/main/java/com/androdr/data/db/KnownAppDbEntry.kt \
        app/src/main/java/com/androdr/data/db/Migrations.kt \
        app/src/main/java/com/androdr/data/db/AppDatabase.kt \
        app/src/main/res/raw/known_good_apps.json
git commit -m "feat: add KnownAppEntry model, KnownAppDbEntry entity, Room migration 3→4"
```

---

## Task 2: KnownAppEntryDao + KnownAppDatabase

**Files:**
- Create: `app/src/main/java/com/androdr/data/db/KnownAppEntryDao.kt`
- Create: `app/src/main/java/com/androdr/ioc/KnownAppDatabase.kt`

- [ ] **Step 1: Create the DAO**

```kotlin
// app/src/main/java/com/androdr/data/db/KnownAppEntryDao.kt
package com.androdr.data.db

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query

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

- [ ] **Step 2: Create KnownAppDatabase (bundled fallback)**

```kotlin
// app/src/main/java/com/androdr/ioc/KnownAppDatabase.kt
package com.androdr.ioc

import android.content.Context
import com.androdr.R
import com.androdr.data.model.KnownAppEntry
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.serialization.json.Json
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class KnownAppDatabase @Inject constructor(
    @ApplicationContext private val context: Context,
) {
    private val json = Json { ignoreUnknownKeys = true }

    private val entries: List<KnownAppEntry> by lazy {
        val raw = context.resources
            .openRawResource(R.raw.known_good_apps)
            .bufferedReader()
            .use { it.readText() }
        json.decodeFromString(raw)
    }

    private val map: HashMap<String, KnownAppEntry> by lazy {
        HashMap<String, KnownAppEntry>(entries.size * 2).also { m ->
            entries.forEach { e -> m[e.packageName] = e }
        }
    }

    /** Number of bundled entries. Used to initialise UI counters before remote feeds load. */
    val size: Int get() = entries.size

    fun lookup(packageName: String): KnownAppEntry? = map[packageName]
    fun getAll(): List<KnownAppEntry> = entries
}
```

- [ ] **Step 3: Verify the build compiles**

```bash
./gradlew assembleDebug
```

Expected: BUILD SUCCESSFUL.

- [ ] **Step 4: Commit**

```bash
git add app/src/main/java/com/androdr/data/db/KnownAppEntryDao.kt \
        app/src/main/java/com/androdr/ioc/KnownAppDatabase.kt
git commit -m "feat: add KnownAppEntryDao and KnownAppDatabase bundled fallback"
```

---

## Task 3: KnownAppFeed interface

**Files:**
- Create: `app/src/main/java/com/androdr/ioc/KnownAppFeed.kt`

- [ ] **Step 1: Create the interface**

```kotlin
// app/src/main/java/com/androdr/ioc/KnownAppFeed.kt
package com.androdr.ioc

import com.androdr.data.model.KnownAppEntry

interface KnownAppFeed {
    val sourceId: String
    /** Returns all entries from this feed, or an empty list on any failure. */
    suspend fun fetch(): List<KnownAppEntry>
}
```

- [ ] **Step 2: Verify the build compiles**

```bash
./gradlew assembleDebug
```

Expected: BUILD SUCCESSFUL.

- [ ] **Step 3: Commit**

```bash
git add app/src/main/java/com/androdr/ioc/KnownAppFeed.kt
git commit -m "feat: add KnownAppFeed interface"
```

---

## Task 4: UadKnownAppFeed + tests

**Files:**
- Create: `app/src/test/java/com/androdr/ioc/UadKnownAppFeedTest.kt`
- Create: `app/src/main/java/com/androdr/ioc/feeds/UadKnownAppFeed.kt`

The UAD-ng JSON is a flat object keyed by package name. Each value has a `"list"` field
(`"OEM"`, `"Carrier"`, `"Misc"`, `"AOSP"`, `"Google"`) and a `"description"` field. Example:

```json
{
  "com.samsung.android.app.clockpackage": {
    "list": "OEM",
    "description": "Samsung Clock",
    "dependencies": [],
    "neededBy": []
  }
}
```

- [ ] **Step 1: Write the failing tests**

```kotlin
// app/src/test/java/com/androdr/ioc/UadKnownAppFeedTest.kt
package com.androdr.ioc

import com.androdr.data.model.KnownAppCategory
import com.androdr.ioc.feeds.UadKnownAppFeed
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class UadKnownAppFeedTest {

    private val feed = UadKnownAppFeed()

    // ── parseUadJson ───────────────────────────────────────────────────────────

    @Test
    fun `OEM entry maps to OEM category`() {
        val json = """{"com.samsung.clock":{"list":"OEM","description":"Samsung Clock"}}"""
        val results = feed.parseUadJson(json)
        assertEquals(1, results.size)
        assertEquals("com.samsung.clock", results[0].packageName)
        assertEquals("Samsung Clock", results[0].displayName)
        assertEquals(KnownAppCategory.OEM, results[0].category)
        assertEquals("uad_ng", results[0].sourceId)
    }

    @Test
    fun `Carrier entry maps to OEM category`() {
        val json = """{"com.att.service":{"list":"Carrier","description":"AT&T Service"}}"""
        val results = feed.parseUadJson(json)
        assertEquals(KnownAppCategory.OEM, results[0].category)
    }

    @Test
    fun `Misc entry maps to OEM category`() {
        val json = """{"com.example.misc":{"list":"Misc","description":"Misc App"}}"""
        val results = feed.parseUadJson(json)
        assertEquals(KnownAppCategory.OEM, results[0].category)
    }

    @Test
    fun `AOSP entry maps to AOSP category`() {
        val json = """{"com.android.settings":{"list":"AOSP","description":"Settings"}}"""
        val results = feed.parseUadJson(json)
        assertEquals(KnownAppCategory.AOSP, results[0].category)
    }

    @Test
    fun `Google entry maps to GOOGLE category`() {
        val json = """{"com.google.android.gms":{"list":"Google","description":"Play Services"}}"""
        val results = feed.parseUadJson(json)
        assertEquals(KnownAppCategory.GOOGLE, results[0].category)
    }

    @Test
    fun `empty JSON object returns empty list`() {
        val results = feed.parseUadJson("{}")
        assertTrue(results.isEmpty())
    }

    @Test
    fun `malformed JSON returns empty list`() {
        val results = feed.parseUadJson("not-json")
        assertTrue(results.isEmpty())
    }

    @Test
    fun `unknown list value is skipped`() {
        val json = """{"com.example.unknown":{"list":"UNKNOWN","description":"Unknown"}}"""
        val results = feed.parseUadJson(json)
        assertTrue(results.isEmpty())
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
./gradlew testDebugUnitTest --tests "com.androdr.ioc.UadKnownAppFeedTest" 2>&1 | tail -20
```

Expected: FAILED (class not found).

- [ ] **Step 3: Write UadKnownAppFeed**

```kotlin
// app/src/main/java/com/androdr/ioc/feeds/UadKnownAppFeed.kt
package com.androdr.ioc.feeds

import android.util.Log
import com.androdr.data.model.KnownAppCategory
import com.androdr.data.model.KnownAppEntry
import com.androdr.ioc.KnownAppFeed
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL

class UadKnownAppFeed : KnownAppFeed {

    override val sourceId = SOURCE_ID

    @Suppress("TooGenericExceptionCaught")
    override suspend fun fetch(): List<KnownAppEntry> = withContext(Dispatchers.IO) {
        try {
            val raw = httpGet(UAD_URL) ?: return@withContext emptyList()
            parseUadJson(raw)
        } catch (e: Exception) {
            Log.w(TAG, "UadKnownAppFeed.fetch failed: ${e.message}")
            emptyList()
        }
    }

    @Suppress("TooGenericExceptionCaught", "SwallowedException")
    internal fun parseUadJson(raw: String): List<KnownAppEntry> {
        return try {
            val root = JSONObject(raw)
            val now = System.currentTimeMillis()
            val results = mutableListOf<KnownAppEntry>()
            root.keys().forEach { packageName ->
                val obj = root.optJSONObject(packageName) ?: return@forEach
                val listField = obj.optString("list")
                val category = when (listField) {
                    "OEM", "Carrier", "Misc" -> KnownAppCategory.OEM
                    "AOSP"                   -> KnownAppCategory.AOSP
                    "Google"                 -> KnownAppCategory.GOOGLE
                    else                     -> return@forEach  // skip unknown list values
                }
                val displayName = obj.optString("description").ifBlank { packageName }
                results.add(
                    KnownAppEntry(
                        packageName = packageName,
                        displayName = displayName,
                        category    = category,
                        sourceId    = SOURCE_ID,
                        fetchedAt   = now
                    )
                )
            }
            results
        } catch (e: Exception) {
            Log.w(TAG, "parseUadJson failed: ${e.message}")
            emptyList()
        }
    }

    @Suppress("TooGenericExceptionCaught", "SwallowedException")
    private fun httpGet(url: String): String? = try {
        (URL(url).openConnection() as HttpURLConnection).run {
            connectTimeout = 15_000; readTimeout = 30_000
            requestMethod = "GET"
            setRequestProperty("User-Agent", "AndroDR/1.0")
            try {
                if (responseCode != HttpURLConnection.HTTP_OK) {
                    Log.w(TAG, "HTTP $responseCode from $url"); null
                } else {
                    inputStream.bufferedReader().readText()
                }
            } finally { disconnect() }
        }
    } catch (e: Exception) {
        Log.w(TAG, "httpGet failed for $url: ${e.message}"); null
    }

    companion object {
        private const val TAG = "UadKnownAppFeed"
        const val SOURCE_ID = "uad_ng"
        private const val UAD_URL =
            "https://raw.githubusercontent.com/Universal-Debloater-Alliance/" +
            "universal-android-debloater-next-generation/main/resources/assets/uad_lists.json"
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
./gradlew testDebugUnitTest --tests "com.androdr.ioc.UadKnownAppFeedTest" 2>&1 | tail -20
```

Expected: 8 tests, all PASSED.

- [ ] **Step 5: Commit**

```bash
git add app/src/main/java/com/androdr/ioc/feeds/UadKnownAppFeed.kt \
        app/src/test/java/com/androdr/ioc/UadKnownAppFeedTest.kt
git commit -m "feat: add UadKnownAppFeed with parser tests"
```

---

## Task 5: PlexusKnownAppFeed + tests

**Files:**
- Create: `app/src/test/java/com/androdr/ioc/PlexusKnownAppFeedTest.kt`
- Create: `app/src/main/java/com/androdr/ioc/feeds/PlexusKnownAppFeed.kt`

The Plexus API response shape:
```json
{
  "data": [{ "name": "WhatsApp", "package": "com.whatsapp" }],
  "meta": { "current_page": 1, "total_pages": 2, "per_page": 500, "total_apps": 600 }
}
```

Pagination: fetch page 1, then continue while `current_page < total_pages`, incrementing page
number each iteration.

- [ ] **Step 1: Write the failing tests**

```kotlin
// app/src/test/java/com/androdr/ioc/PlexusKnownAppFeedTest.kt
package com.androdr.ioc

import com.androdr.data.model.KnownAppCategory
import com.androdr.ioc.feeds.PlexusKnownAppFeed
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class PlexusKnownAppFeedTest {

    private val feed = PlexusKnownAppFeed()

    // ── parsePlexusPage ────────────────────────────────────────────────────────

    @Test
    fun `single page is parsed correctly`() {
        val json = """
            {
              "data": [
                {"name": "WhatsApp", "package": "com.whatsapp"},
                {"name": "Signal",   "package": "org.thoughtcrime.securesms"}
              ],
              "meta": {"current_page": 1, "total_pages": 1, "per_page": 500, "total_apps": 2}
            }
        """.trimIndent()
        val (entries, meta) = feed.parsePlexusPage(json)
        assertEquals(2, entries.size)
        assertEquals("com.whatsapp", entries[0].packageName)
        assertEquals("WhatsApp", entries[0].displayName)
        assertEquals(KnownAppCategory.USER_APP, entries[0].category)
        assertEquals("plexus", entries[0].sourceId)
        assertEquals(1, meta.currentPage)
        assertEquals(1, meta.totalPages)
    }

    @Test
    fun `empty data array returns no entries`() {
        val json = """
            {"data": [], "meta": {"current_page": 1, "total_pages": 1, "per_page": 500, "total_apps": 0}}
        """.trimIndent()
        val (entries, _) = feed.parsePlexusPage(json)
        assertTrue(entries.isEmpty())
    }

    @Test
    fun `multi-page meta is parsed correctly`() {
        val json = """
            {"data": [], "meta": {"current_page": 3, "total_pages": 19, "per_page": 500, "total_apps": 9333}}
        """.trimIndent()
        val (_, meta) = feed.parsePlexusPage(json)
        assertEquals(3, meta.currentPage)
        assertEquals(19, meta.totalPages)
    }

    @Test
    fun `malformed JSON returns null`() {
        val result = feed.parsePlexusPage("not-json")
        assertTrue(result == null)
    }

    // ── morePages ─────────────────────────────────────────────────────────────

    @Test
    fun `morePages is false when currentPage equals totalPages`() {
        val json = """
            {"data": [], "meta": {"current_page": 1, "total_pages": 1, "per_page": 500, "total_apps": 1}}
        """.trimIndent()
        val (_, meta) = feed.parsePlexusPage(json)!!
        assertTrue(meta.currentPage >= meta.totalPages)
    }

    @Test
    fun `morePages is true when currentPage is less than totalPages`() {
        val json = """
            {"data": [], "meta": {"current_page": 1, "total_pages": 2, "per_page": 500, "total_apps": 600}}
        """.trimIndent()
        val (_, meta) = feed.parsePlexusPage(json)!!
        assertTrue(meta.currentPage < meta.totalPages)
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
./gradlew testDebugUnitTest --tests "com.androdr.ioc.PlexusKnownAppFeedTest" 2>&1 | tail -20
```

Expected: FAILED (class not found).

- [ ] **Step 3: Write PlexusKnownAppFeed**

```kotlin
// app/src/main/java/com/androdr/ioc/feeds/PlexusKnownAppFeed.kt
package com.androdr.ioc.feeds

import android.util.Log
import com.androdr.data.model.KnownAppCategory
import com.androdr.data.model.KnownAppEntry
import com.androdr.ioc.KnownAppFeed
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL

class PlexusKnownAppFeed : KnownAppFeed {

    override val sourceId = SOURCE_ID

    data class PlexusMeta(val currentPage: Int, val totalPages: Int)

    @Suppress("TooGenericExceptionCaught")
    override suspend fun fetch(): List<KnownAppEntry> = withContext(Dispatchers.IO) {
        val collected = mutableListOf<KnownAppEntry>()
        var page = 1
        try {
            do {
                val raw = httpGet("$PLEXUS_BASE_URL&page=$page")
                    ?: break  // network failure — return what we have so far
                val parsed = parsePlexusPage(raw) ?: break  // parse failure
                collected.addAll(parsed.first)
                val meta = parsed.second
                if (meta.currentPage >= meta.totalPages) break
                page++
            } while (true)
        } catch (e: Exception) {
            Log.w(TAG, "PlexusKnownAppFeed.fetch failed on page $page: ${e.message}")
        }
        Log.i(TAG, "Plexus: collected ${collected.size} entries across $page page(s)")
        collected
    }

    /**
     * Parses one page of the Plexus API response.
     * Returns a pair of (entries, meta) or null on parse failure.
     */
    @Suppress("TooGenericExceptionCaught", "SwallowedException")
    internal fun parsePlexusPage(raw: String): Pair<List<KnownAppEntry>, PlexusMeta>? {
        return try {
            val root = JSONObject(raw)
            val dataArray = root.optJSONArray("data") ?: return null
            val metaObj   = root.optJSONObject("meta") ?: return null
            val now = System.currentTimeMillis()
            val entries = mutableListOf<KnownAppEntry>()
            for (i in 0 until dataArray.length()) {
                val app = dataArray.getJSONObject(i)
                val pkg = app.optString("package")
                if (pkg.isBlank()) continue
                val name = app.optString("name").ifBlank { pkg }
                entries.add(
                    KnownAppEntry(
                        packageName = pkg,
                        displayName = name,
                        category    = KnownAppCategory.USER_APP,
                        sourceId    = SOURCE_ID,
                        fetchedAt   = now
                    )
                )
            }
            val meta = PlexusMeta(
                currentPage = metaObj.optInt("current_page", 1),
                totalPages  = metaObj.optInt("total_pages", 1)
            )
            Pair(entries, meta)
        } catch (e: Exception) {
            Log.w(TAG, "parsePlexusPage failed: ${e.message}")
            null
        }
    }

    @Suppress("TooGenericExceptionCaught", "SwallowedException")
    private fun httpGet(url: String): String? = try {
        (URL(url).openConnection() as HttpURLConnection).run {
            connectTimeout = 15_000; readTimeout = 30_000
            requestMethod = "GET"
            setRequestProperty("User-Agent", "AndroDR/1.0")
            try {
                if (responseCode != HttpURLConnection.HTTP_OK) {
                    Log.w(TAG, "HTTP $responseCode from $url"); null
                } else {
                    inputStream.bufferedReader().readText()
                }
            } finally { disconnect() }
        }
    } catch (e: Exception) {
        Log.w(TAG, "httpGet failed for $url: ${e.message}"); null
    }

    companion object {
        private const val TAG = "PlexusKnownAppFeed"
        const val SOURCE_ID = "plexus"
        private const val PLEXUS_BASE_URL = "https://plexus.techlore.tech/api/v1/apps?limit=500"
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
./gradlew testDebugUnitTest --tests "com.androdr.ioc.PlexusKnownAppFeedTest" 2>&1 | tail -20
```

Expected: 6 tests, all PASSED.

- [ ] **Step 5: Commit**

```bash
git add app/src/main/java/com/androdr/ioc/feeds/PlexusKnownAppFeed.kt \
        app/src/test/java/com/androdr/ioc/PlexusKnownAppFeedTest.kt
git commit -m "feat: add PlexusKnownAppFeed with parser + pagination tests"
```

---

## Task 6: KnownAppResolver + tests

**Files:**
- Create: `app/src/test/java/com/androdr/ioc/KnownAppResolverTest.kt`
- Create: `app/src/main/java/com/androdr/ioc/KnownAppResolver.kt`

- [ ] **Step 1: Write the failing tests**

```kotlin
// app/src/test/java/com/androdr/ioc/KnownAppResolverTest.kt
package com.androdr.ioc

import com.androdr.data.model.KnownAppCategory
import com.androdr.data.model.KnownAppEntry
import io.mockk.coEvery
import io.mockk.every
import io.mockk.mockk
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Before
import org.junit.Test

class KnownAppResolverTest {

    private val mockDao = mockk<com.androdr.data.db.KnownAppEntryDao>()
    private val mockBundled = mockk<KnownAppDatabase>()
    private lateinit var resolver: KnownAppResolver

    private fun oemEntry(pkg: String) = KnownAppEntry(
        packageName = pkg, displayName = pkg, category = KnownAppCategory.OEM,
        sourceId = "bundled", fetchedAt = 0
    )

    @Before
    fun setUp() {
        resolver = KnownAppResolver(mockDao, mockBundled)
    }

    @Test
    fun `null cache falls back to bundled entry`() {
        // cache not yet populated (null) — should call bundled
        every { mockBundled.lookup("com.samsung.settings") } returns oemEntry("com.samsung.settings")

        val result = resolver.lookup("com.samsung.settings")

        assertEquals(KnownAppCategory.OEM, result?.category)
    }

    @Test
    fun `null cache returns null when bundled also misses`() {
        every { mockBundled.lookup("com.unknown.app") } returns null

        val result = resolver.lookup("com.unknown.app")

        assertNull(result)
    }

    @Test
    fun `populated cache returns cached entry`() = runTest {
        val dbEntry = com.androdr.data.db.KnownAppDbEntry(
            packageName = "com.whatsapp", displayName = "WhatsApp",
            category = "USER_APP", sourceId = "plexus", fetchedAt = 1000L
        )
        coEvery { mockDao.getAll() } returns listOf(dbEntry)

        resolver.refreshCache()
        val result = resolver.lookup("com.whatsapp")

        assertEquals(KnownAppCategory.USER_APP, result?.category)
        assertEquals("WhatsApp", result?.displayName)
    }

    @Test
    fun `populated cache miss falls back to bundled`() = runTest {
        coEvery { mockDao.getAll() } returns emptyList()
        every { mockBundled.lookup("com.samsung.settings") } returns oemEntry("com.samsung.settings")

        resolver.refreshCache()
        val result = resolver.lookup("com.samsung.settings")

        assertEquals(KnownAppCategory.OEM, result?.category)
    }

    @Test
    fun `neither source has entry returns null`() = runTest {
        coEvery { mockDao.getAll() } returns emptyList()
        every { mockBundled.lookup("com.mystery.app") } returns null

        resolver.refreshCache()
        val result = resolver.lookup("com.mystery.app")

        assertNull(result)
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
./gradlew testDebugUnitTest --tests "com.androdr.ioc.KnownAppResolverTest" 2>&1 | tail -20
```

Expected: FAILED (class not found).

- [ ] **Step 3: Write KnownAppResolver**

```kotlin
// app/src/main/java/com/androdr/ioc/KnownAppResolver.kt
package com.androdr.ioc

import com.androdr.data.db.KnownAppDbEntry
import com.androdr.data.db.KnownAppEntryDao
import com.androdr.data.model.KnownAppCategory
import com.androdr.data.model.KnownAppEntry
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.util.concurrent.atomic.AtomicReference
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Single lookup point for known-app checks.
 *
 * Priority:
 *  1. Dynamic entries fetched from remote feeds and stored in Room (most up-to-date).
 *  2. Bundled [KnownAppDatabase] (always available, used as fallback / cold-start).
 *
 * The cache is kept in an [AtomicReference] so that [lookup] stays synchronous and
 * can be called from non-coroutine contexts inside [AppScanner.scan].
 * [refreshCache] is called automatically at the end of each [KnownAppUpdater.update] run.
 */
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

- [ ] **Step 4: Run tests to verify they pass**

```bash
./gradlew testDebugUnitTest --tests "com.androdr.ioc.KnownAppResolverTest" 2>&1 | tail -20
```

Expected: 5 tests, all PASSED.

- [ ] **Step 5: Commit**

```bash
git add app/src/main/java/com/androdr/ioc/KnownAppResolver.kt \
        app/src/test/java/com/androdr/ioc/KnownAppResolverTest.kt
git commit -m "feat: add KnownAppResolver with cache + bundled fallback"
```

---

## Task 7: KnownAppUpdater + tests

**Files:**
- Create: `app/src/test/java/com/androdr/ioc/KnownAppUpdaterTest.kt`
- Create: `app/src/main/java/com/androdr/ioc/KnownAppUpdater.kt`

- [ ] **Step 1: Write the failing tests**

```kotlin
// app/src/test/java/com/androdr/ioc/KnownAppUpdaterTest.kt
package com.androdr.ioc

import com.androdr.data.db.KnownAppDbEntry
import com.androdr.data.db.KnownAppEntryDao
import com.androdr.data.model.KnownAppCategory
import com.androdr.data.model.KnownAppEntry
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.mockk
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Test

class KnownAppUpdaterTest {

    private val mockDao      = mockk<KnownAppEntryDao>(relaxed = true)
    private val mockResolver = mockk<KnownAppResolver>(relaxed = true)

    private fun makeEntry(pkg: String) = KnownAppEntry(
        packageName = pkg, displayName = pkg, category = KnownAppCategory.OEM,
        sourceId = "uad_ng", fetchedAt = 1000L
    )

    @Test
    fun `update returns total count from all feeds`() = runTest {
        val feed1 = mockk<KnownAppFeed>()
        val feed2 = mockk<KnownAppFeed>()
        coEvery { feed1.fetch() } returns listOf(makeEntry("com.a"), makeEntry("com.b"))
        coEvery { feed2.fetch() } returns listOf(makeEntry("com.c"))
        coEvery { feed1.sourceId } returns "uad_ng"
        coEvery { feed2.sourceId } returns "plexus"
        coEvery { mockDao.count() } returns 3

        val updater = KnownAppUpdater(mockDao, mockResolver, listOf(feed1, feed2))
        val total = updater.update()

        assertEquals(3, total)
    }

    @Test
    fun `upsertAll is called with mapped DB entries`() = runTest {
        val feed = mockk<KnownAppFeed>()
        coEvery { feed.fetch() } returns listOf(makeEntry("com.android.settings"))
        coEvery { feed.sourceId } returns "uad_ng"
        coEvery { mockDao.count() } returns 1

        val updater = KnownAppUpdater(mockDao, mockResolver, listOf(feed))
        updater.update()

        coVerify { mockDao.upsertAll(match { it.size == 1 && it[0].packageName == "com.android.settings" }) }
    }

    @Test
    fun `deleteStaleEntries is called with correct sourceId and timestamp`() = runTest {
        val feed = mockk<KnownAppFeed>()
        val entry = makeEntry("com.android.settings").copy(fetchedAt = 5000L)
        coEvery { feed.fetch() } returns listOf(entry)
        coEvery { feed.sourceId } returns "uad_ng"
        coEvery { mockDao.count() } returns 1

        val updater = KnownAppUpdater(mockDao, mockResolver, listOf(feed))
        updater.update()

        coVerify { mockDao.deleteStaleEntries("uad_ng", 4999L) }  // minOf(fetchedAt) - 1
    }

    @Test
    fun `refreshCache is called after upsert`() = runTest {
        val feed = mockk<KnownAppFeed>()
        coEvery { feed.fetch() } returns listOf(makeEntry("com.a"))
        coEvery { feed.sourceId } returns "uad_ng"
        coEvery { mockDao.count() } returns 1

        val updater = KnownAppUpdater(mockDao, mockResolver, listOf(feed))
        updater.update()

        coVerify { mockResolver.refreshCache() }
    }

    @Test
    fun `zero entries from all feeds returns 0`() = runTest {
        val feed = mockk<KnownAppFeed>()
        coEvery { feed.fetch() } returns emptyList()
        coEvery { feed.sourceId } returns "uad_ng"
        coEvery { mockDao.count() } returns 0

        val updater = KnownAppUpdater(mockDao, mockResolver, listOf(feed))
        val total = updater.update()

        assertEquals(0, total)
        coVerify(exactly = 0) { mockDao.upsertAll(any()) }
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
./gradlew testDebugUnitTest --tests "com.androdr.ioc.KnownAppUpdaterTest" 2>&1 | tail -20
```

Expected: FAILED (class not found).

- [ ] **Step 3: Write KnownAppUpdater**

```kotlin
// app/src/main/java/com/androdr/ioc/KnownAppUpdater.kt
package com.androdr.ioc

import android.util.Log
import com.androdr.data.db.KnownAppDbEntry
import com.androdr.data.db.KnownAppEntryDao
import com.androdr.data.model.KnownAppEntry
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.withContext
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Orchestrates all known-app feeds: runs them in parallel, upserts into Room,
 * prunes stale entries, then refreshes [KnownAppResolver].
 *
 * Mirrors [DomainIocUpdater] exactly.
 */
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

- [ ] **Step 4: Run tests to verify they pass**

```bash
./gradlew testDebugUnitTest --tests "com.androdr.ioc.KnownAppUpdaterTest" 2>&1 | tail -20
```

Expected: 5 tests, all PASSED.

- [ ] **Step 5: Commit**

```bash
git add app/src/main/java/com/androdr/ioc/KnownAppUpdater.kt \
        app/src/test/java/com/androdr/ioc/KnownAppUpdaterTest.kt
git commit -m "feat: add KnownAppUpdater with parallel feed orchestration"
```

---

## Task 8: DI wiring + IocUpdateWorker

**Files:**
- Modify: `app/src/main/java/com/androdr/di/AppModule.kt`
- Modify: `app/src/main/java/com/androdr/ioc/IocUpdateWorker.kt`
- Modify: `app/src/test/java/com/androdr/ioc/IocUpdateWorkerTest.kt`

- [ ] **Step 1: Update AppModule.kt**

Add the following to `AppModule`:

```kotlin
// After the existing provideDomainIocFeeds() method:

@Provides
fun provideKnownAppEntryDao(db: AppDatabase): KnownAppEntryDao = db.knownAppEntryDao()

@Provides
@Singleton
fun provideKnownAppFeeds(): @JvmSuppressWildcards List<KnownAppFeed> =
    listOf(UadKnownAppFeed(), PlexusKnownAppFeed())
```

Also update the import list and the `addMigrations` call:

```kotlin
.addMigrations(MIGRATION_1_2, MIGRATION_2_3, MIGRATION_3_4)
```

New imports needed in `AppModule.kt`:
```kotlin
import com.androdr.data.db.KnownAppEntryDao
import com.androdr.data.db.MIGRATION_3_4
import com.androdr.ioc.KnownAppFeed
import com.androdr.ioc.feeds.PlexusKnownAppFeed
import com.androdr.ioc.feeds.UadKnownAppFeed
```

- [ ] **Step 2: Update IocUpdateWorkerTest.kt first (TDD — write failing tests before implementation)**

Replace the entire file with:

```kotlin
package com.androdr.ioc

import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.mockk
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.fail
import org.junit.Test

class IocUpdateWorkerTest {

    private val remoteIocUpdater: RemoteIocUpdater = mockk()
    private val domainIocUpdater: DomainIocUpdater = mockk()
    private val knownAppUpdater:  KnownAppUpdater  = mockk()

    @Test
    fun `runAllUpdaters calls all three updaters and sums counts`() = runTest {
        coEvery { remoteIocUpdater.update() } returns 10
        coEvery { domainIocUpdater.update() } returns 20
        coEvery { knownAppUpdater.update()  } returns 15

        val total = runAllUpdaters(remoteIocUpdater, domainIocUpdater, knownAppUpdater)

        assertEquals(45, total)
        coVerify { remoteIocUpdater.update() }
        coVerify { domainIocUpdater.update() }
        coVerify { knownAppUpdater.update()  }
    }

    @Test
    fun `runAllUpdaters propagates exception when updater throws`() = runTest {
        coEvery { remoteIocUpdater.update() } throws RuntimeException("network error")
        coEvery { domainIocUpdater.update() } returns 5
        coEvery { knownAppUpdater.update()  } returns 15

        try {
            runAllUpdaters(remoteIocUpdater, domainIocUpdater, knownAppUpdater)
            fail("Expected RuntimeException to be thrown")
        } catch (e: RuntimeException) {
            assertEquals("network error", e.message)
        }
    }
}
```

- [ ] **Step 3: Run tests to verify they fail**

```bash
./gradlew testDebugUnitTest --tests "com.androdr.ioc.IocUpdateWorkerTest" 2>&1 | tail -20
```

Expected: FAILED — `runAllUpdaters` not found (still named `runBothUpdaters`).

- [ ] **Step 4: Update IocUpdateWorker.kt**

Replace the entire file with:

```kotlin
package com.androdr.ioc

import android.content.Context
import android.util.Log
import androidx.hilt.work.HiltWorker
import androidx.work.CoroutineWorker
import androidx.work.WorkerParameters
import dagger.assisted.Assisted
import dagger.assisted.AssistedInject
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope

@HiltWorker
class IocUpdateWorker @AssistedInject constructor(
    @Assisted context: Context,
    @Assisted params: WorkerParameters,
    private val remoteIocUpdater: RemoteIocUpdater,
    private val domainIocUpdater: DomainIocUpdater,
    private val knownAppUpdater: KnownAppUpdater
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

/** Runs all three updaters in parallel; returns combined entry count. Extracted for testability. */
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

- [ ] **Step 5: Run the updated tests**

```bash
./gradlew testDebugUnitTest --tests "com.androdr.ioc.IocUpdateWorkerTest" 2>&1 | tail -20
```

Expected: 2 tests, all PASSED.

- [ ] **Step 5: Verify full build + all tests**

```bash
./gradlew assembleDebug testDebugUnitTest 2>&1 | tail -30
```

Expected: BUILD SUCCESSFUL, all tests pass.

- [ ] **Step 6: Commit**

```bash
git add app/src/main/java/com/androdr/di/AppModule.kt \
        app/src/main/java/com/androdr/ioc/IocUpdateWorker.kt \
        app/src/test/java/com/androdr/ioc/IocUpdateWorkerTest.kt
git commit -m "feat: wire KnownAppUpdater into AppModule and IocUpdateWorker"
```

---

## Task 9: Bundled snapshot

**Files:**
- Create: `scripts/generate_known_good_apps.py`
- Modify: `app/src/main/res/raw/known_good_apps.json` (replace placeholder)
- Modify: `CLAUDE.md`

- [ ] **Step 1: Write the generation script**

```python
#!/usr/bin/env python3
"""
Generate res/raw/known_good_apps.json from UAD-ng + Plexus community sources.

Usage:
    python3 scripts/generate_known_good_apps.py

Output: app/src/main/res/raw/known_good_apps.json

Run this script and commit the updated JSON whenever you want to refresh the
bundled snapshot (e.g. before a release).
"""
import json
import urllib.request
from pathlib import Path

UAD_URL = (
    "https://raw.githubusercontent.com/Universal-Debloater-Alliance/"
    "universal-android-debloater-next-generation/main/resources/assets/uad_lists.json"
)
PLEXUS_BASE = "https://plexus.techlore.tech/api/v1/apps?limit=500"
OUT_PATH = Path(__file__).parent.parent / "app/src/main/res/raw/known_good_apps.json"

LIST_TO_CATEGORY = {
    "OEM":     "OEM",
    "Carrier": "OEM",
    "Misc":    "OEM",
    "AOSP":    "AOSP",
    "Google":  "GOOGLE",
}


def fetch(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "AndroDR-script/1.0"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return resp.read().decode()


def fetch_uad() -> list[dict]:
    print("Fetching UAD-ng …")
    data = json.loads(fetch(UAD_URL))
    entries = []
    for pkg, info in data.items():
        list_val = info.get("list", "")
        category = LIST_TO_CATEGORY.get(list_val)
        if category is None:
            continue
        entries.append({
            "packageName": pkg,
            "displayName": info.get("description") or pkg,
            "category": category,
            "sourceId": "bundled",
            "fetchedAt": 0,
        })
    print(f"  UAD-ng: {len(entries)} entries")
    return entries


def fetch_plexus() -> list[dict]:
    print("Fetching Plexus …")
    entries = []
    page = 1
    while True:
        data = json.loads(fetch(f"{PLEXUS_BASE}&page={page}"))
        apps = data.get("data", [])
        meta = data.get("meta", {})
        for app in apps:
            pkg = app.get("package", "").strip()
            if not pkg:
                continue
            entries.append({
                "packageName": pkg,
                "displayName": app.get("name") or pkg,
                "category": "USER_APP",
                "sourceId": "bundled",
                "fetchedAt": 0,
            })
        current = meta.get("current_page", 1)
        total   = meta.get("total_pages", 1)
        print(f"  Plexus page {current}/{total} …")
        if current >= total:
            break
        page += 1
    print(f"  Plexus: {len(entries)} entries")
    return entries


def main():
    uad     = fetch_uad()
    plexus  = fetch_plexus()

    # UAD-ng takes precedence over Plexus for the same package name
    merged: dict[str, dict] = {}
    for e in plexus:
        merged[e["packageName"]] = e
    for e in uad:
        merged[e["packageName"]] = e  # overwrite Plexus if same pkg

    result = sorted(merged.values(), key=lambda x: x["packageName"])
    OUT_PATH.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n")
    print(f"\nWrote {len(result)} entries to {OUT_PATH}")


if __name__ == "__main__":
    main()
```

- [ ] **Step 2: Run the script to generate the real snapshot**

```bash
python3 scripts/generate_known_good_apps.py
```

Expected output: "Wrote N entries to .../known_good_apps.json" (N ≈ 10,000+).

> Note: this requires network access. If running offline, commit the placeholder and run
> the script before the next release.

- [ ] **Step 3: Document the script in CLAUDE.md**

Add to the "Common commands" section in `CLAUDE.md`:

```markdown
# Refresh bundled known-good apps snapshot (requires network)
python3 scripts/generate_known_good_apps.py
```

- [ ] **Step 4: Verify the build still compiles**

```bash
./gradlew assembleDebug
```

Expected: BUILD SUCCESSFUL.

- [ ] **Step 5: Commit**

```bash
git add scripts/generate_known_good_apps.py \
        app/src/main/res/raw/known_good_apps.json \
        CLAUDE.md
git commit -m "feat: add bundled known_good_apps.json snapshot and generation script"
```

---

## Task 10: AppScanner integration

**Files:**
- Modify: `app/src/test/java/com/androdr/scanner/AppScannerTest.kt`
- Modify: `app/src/main/java/com/androdr/scanner/AppScanner.kt`

This task removes `knownSystemPrefixes` and `looksLikeKnownSystem` from `AppScanner` and
replaces them with `KnownAppResolver` lookups. It also adds impersonation detection.

- [ ] **Step 1: Update AppScannerTest — setUp and existing OEM-prefix tests**

Add these imports to the import block at the top of `AppScannerTest.kt`:

```kotlin
import com.androdr.data.model.KnownAppCategory
import com.androdr.data.model.KnownAppEntry
import com.androdr.ioc.KnownAppResolver
```

Then declare the new mock field:

```kotlin
private val mockKnownAppResolver: KnownAppResolver = mockk()
```

Update `setUp()`:

```kotlin
@Before
fun setUp() {
    every { mockContext.packageManager } returns mockPm
    every { mockIocResolver.isKnownBadPackage(any()) } returns null
    every { mockKnownAppResolver.lookup(any()) } returns null  // default: unknown app
    scanner = AppScanner(mockContext, mockIocResolver, mockKnownAppResolver)
}
```

Update all `AppScanner(mockContext, mockIocResolver)` constructor calls to:
`AppScanner(mockContext, mockIocResolver, mockKnownAppResolver)`
(There are none besides `setUp`, but double-check the file.)

Update the three existing tests that relied on `knownSystemPrefixes`:

**`OEM-prefixed user app with null installer is not flagged as sideloaded`** — add stub before scan:
```kotlin
every { mockKnownAppResolver.lookup("com.samsung.android.tvplus") } returns KnownAppEntry(
    packageName = "com.samsung.android.tvplus", displayName = "Samsung TV Plus",
    category = KnownAppCategory.OEM, sourceId = "bundled", fetchedAt = 0
)
```

**`system app with known OEM prefix is not flagged`** — add stub before scan:
```kotlin
every { mockKnownAppResolver.lookup("com.android.settings") } returns KnownAppEntry(
    packageName = "com.android.settings", displayName = "Settings",
    category = KnownAppCategory.AOSP, sourceId = "bundled", fetchedAt = 0
)
```

**`system app with unknown prefix is not scored for permission combinations`** — no stub needed
(default `lookup` returns null, which means `isKnownOemApp = false`, which is correct for the
firmware-implant check to fire).

- [ ] **Step 2: Add new impersonation test cases**

```kotlin
// ── Known-app DB integration ──────────────────────────────────────────────

@Test
fun `OEM DB hit suppresses sideload flag for user app with null installer`() = runTest {
    val pkgInfo = makePackageInfo("com.sec.android.app.sbrowser", installer = null)
    every { mockPm.getInstalledPackages(any<Int>()) } returns listOf(pkgInfo)
    every { mockKnownAppResolver.lookup("com.sec.android.app.sbrowser") } returns KnownAppEntry(
        packageName = "com.sec.android.app.sbrowser", displayName = "Samsung Internet",
        category = KnownAppCategory.OEM, sourceId = "uad_ng", fetchedAt = 0
    )

    val results = scanner.scan()

    assertTrue(results.isEmpty())
}

@Test
fun `OEM DB hit suppresses firmware-implant flag for system app`() = runTest {
    val pkgInfo = makePackageInfo("com.sec.android.app.launcher", isSystem = true)
    every { mockPm.getInstalledPackages(any<Int>()) } returns listOf(pkgInfo)
    every { mockKnownAppResolver.lookup("com.sec.android.app.launcher") } returns KnownAppEntry(
        packageName = "com.sec.android.app.launcher", displayName = "Samsung Launcher",
        category = KnownAppCategory.OEM, sourceId = "uad_ng", fetchedAt = 0
    )

    val results = scanner.scan()

    assertTrue(results.isEmpty())
}

@Test
fun `USER_APP DB hit from untrusted source raises impersonation HIGH`() = runTest {
    val pkgInfo = makePackageInfo("com.whatsapp", installer = null)
    every { mockPm.getInstalledPackages(any<Int>()) } returns listOf(pkgInfo)
    every { mockKnownAppResolver.lookup("com.whatsapp") } returns KnownAppEntry(
        packageName = "com.whatsapp", displayName = "WhatsApp",
        category = KnownAppCategory.USER_APP, sourceId = "plexus", fetchedAt = 0
    )

    val results = scanner.scan()

    assertEquals(1, results.size)
    assertEquals(RiskLevel.HIGH, results[0].riskLevel)
    assertTrue(results[0].reasons.any { it.contains("impersonation") })
}

@Test
fun `USER_APP DB hit from trusted store raises no flag`() = runTest {
    val pkgInfo = makePackageInfo("com.whatsapp", installer = "com.android.vending")
    every { mockPm.getInstalledPackages(any<Int>()) } returns listOf(pkgInfo)
    every { mockKnownAppResolver.lookup("com.whatsapp") } returns KnownAppEntry(
        packageName = "com.whatsapp", displayName = "WhatsApp",
        category = KnownAppCategory.USER_APP, sourceId = "plexus", fetchedAt = 0
    )

    val results = scanner.scan()

    assertTrue(results.isEmpty())
}
```

- [ ] **Step 3: Run the updated tests to verify they fail (because AppScanner not updated yet)**

```bash
./gradlew testDebugUnitTest --tests "com.androdr.scanner.AppScannerTest" 2>&1 | tail -30
```

Expected: compilation failure or test failures — `AppScanner` constructor still has 2 params.

- [ ] **Step 4: Update AppScanner.kt**

The changes to `AppScanner.kt` are:

**a) Add `KnownAppResolver` to the constructor:**
```kotlin
@Singleton
class AppScanner @Inject constructor(
    @ApplicationContext private val context: Context,
    private val iocResolver: IocResolver,
    private val knownAppResolver: KnownAppResolver
)
```

**b) In `scan()`, replace the `knownSystemPrefixes` block with a resolver call:**

Remove the entire `val knownSystemPrefixes = listOf(...)` block and the
`val looksLikeKnownSystem = ...` line.

After the `iocHit` block (check 1) and before the permission scoring block (check 2), add:

```kotlin
// ── Resolver lookup ────────────────────────────────────────────
val knownApp = knownAppResolver.lookup(packageName)
val isKnownOemApp = knownApp?.category in setOf(
    KnownAppCategory.OEM, KnownAppCategory.AOSP, KnownAppCategory.GOOGLE
)
```

**c) Update the permission-scoring condition:**
No change needed — it is already `if (matchedSurveillancePerms.size >= 2 && !isSystemApp && !fromTrustedStore)`.

**d) Add impersonation check (2b) after the permission-scoring block and before the sideload check:**

```kotlin
// ── 2b. Impersonation detection ───────────────────────────────
// A USER_APP entry sideloaded from an untrusted source is likely
// a spoofed APK masquerading as the legitimate app.
if (!isSystemApp && !fromTrustedStore &&
    knownApp?.category == KnownAppCategory.USER_APP) {
    val newLevel = RiskLevel.HIGH
    if (newLevel.score > riskLevel.score) riskLevel = newLevel
    reasons.add(
        "Package name matches well-known app '${knownApp.displayName}' but was not " +
            "installed from a trusted store — possible impersonation"
    )
}
```

**e) Replace `!looksLikeKnownSystem` with `!isKnownOemApp` in the sideload gate:**

```kotlin
if (!isSystemApp && !fromTrustedStore && !isKnownOemApp) {
```

**f) Replace `!looksLikeKnownSystem` with `!isKnownOemApp` in the firmware-implant check:**

```kotlin
if (isSystemApp) {
    if (!isKnownOemApp) {
```

Also add the import at the top:
```kotlin
import com.androdr.data.model.KnownAppCategory
import com.androdr.ioc.KnownAppResolver
```

- [ ] **Step 5: Run all AppScanner tests**

```bash
./gradlew testDebugUnitTest --tests "com.androdr.scanner.AppScannerTest" 2>&1 | tail -30
```

Expected: all tests PASSED (including newly added ones).

- [ ] **Step 6: Run the full test suite**

```bash
./gradlew testDebugUnitTest 2>&1 | tail -20
```

Expected: BUILD SUCCESSFUL, all tests pass.

- [ ] **Step 7: Commit**

```bash
git add app/src/main/java/com/androdr/scanner/AppScanner.kt \
        app/src/test/java/com/androdr/scanner/AppScannerTest.kt
git commit -m "feat: replace knownSystemPrefixes with KnownAppResolver; add impersonation detection"
```

---

## Task 11: Dashboard — ViewModel + Screen

**Files:**
- Modify: `app/src/main/java/com/androdr/ui/dashboard/DashboardViewModel.kt`
- Modify: `app/src/main/java/com/androdr/ui/dashboard/DashboardScreen.kt`

- [ ] **Step 1: Update DashboardViewModel.kt**

Add new constructor parameters after `domainIocUpdater`:

```kotlin
private val knownAppDatabase: KnownAppDatabase,
private val knownAppEntryDao: KnownAppEntryDao,
private val knownAppUpdater: KnownAppUpdater
```

Add new state flows after the domain IOC state section:

```kotlin
// ── Known-app state ────────────────────────────────────────────────────────

private val bundledKnownAppCount = knownAppDatabase.size

private val _knownAppEntryCount = MutableStateFlow(bundledKnownAppCount)
val knownAppEntryCount: StateFlow<Int> = _knownAppEntryCount.asStateFlow()

private val _knownAppLastUpdated = MutableStateFlow<Long?>(null)
val knownAppLastUpdated: StateFlow<Long?> = _knownAppLastUpdated.asStateFlow()

private val _isUpdatingKnownApps = MutableStateFlow(false)
val isUpdatingKnownApps: StateFlow<Boolean> = _isUpdatingKnownApps.asStateFlow()
```

Update the `init` block to also call `refreshKnownAppState()`:

```kotlin
init {
    viewModelScope.launch {
        refreshIocState()
        refreshDomainIocState()
        refreshKnownAppState()
    }
}
```

Add public function and private helpers:

```kotlin
fun updateKnownApps() {
    viewModelScope.launch { doUpdateKnownApps() }
}

@Suppress("TooGenericExceptionCaught")
private suspend fun doUpdateKnownApps() {
    _isUpdatingKnownApps.value = true
    try {
        val fetched = knownAppUpdater.update()
        if (fetched == 0) {
            _iocErrorEvent.tryEmit("Failed to update known-app database. Check your connection.")
        }
        refreshKnownAppState()
    } catch (e: Exception) {
        _iocErrorEvent.tryEmit("Known-app database update failed: ${e.message}")
    } finally {
        _isUpdatingKnownApps.value = false
    }
}

private suspend fun refreshKnownAppState() {
    // After remote data loads, show DB count alone (bundled entries are upserted into Room
    // with the same primary key, so adding bundledKnownAppCount here would double-count).
    // The initial MutableStateFlow(bundledKnownAppCount) covers the pre-load state.
    val dbCount = knownAppEntryDao.count()
    _knownAppEntryCount.value = if (dbCount > 0) dbCount else bundledKnownAppCount
    _knownAppLastUpdated.value = knownAppEntryDao.mostRecentFetchTime()
}
```

Add imports:
```kotlin
import com.androdr.data.db.KnownAppEntryDao
import com.androdr.ioc.KnownAppDatabase
import com.androdr.ioc.KnownAppUpdater
```

- [ ] **Step 2: Update DashboardScreen.kt**

**a)** In `DashboardScreen`, collect the new state:

```kotlin
val knownAppEntryCount by viewModel.knownAppEntryCount.collectAsStateWithLifecycle()
val knownAppLastUpdated by viewModel.knownAppLastUpdated.collectAsStateWithLifecycle()
val isUpdatingKnownApps by viewModel.isUpdatingKnownApps.collectAsStateWithLifecycle()
```

**b)** Update the `ThreatDatabaseCard` call site to pass the new arguments:

```kotlin
ThreatDatabaseCard(
    entryCount = iocEntryCount,
    lastUpdated = iocLastUpdated,
    isUpdating = isUpdatingIoc,
    onUpdateClick = { viewModel.updateIoc() },
    domainEntryCount = domainIocEntryCount,
    domainLastUpdated = domainIocLastUpdated,
    isUpdatingDomain = isUpdatingDomainIoc,
    onUpdateDomainClick = { viewModel.updateDomainIoc() },
    knownAppEntryCount = knownAppEntryCount,
    knownAppLastUpdated = knownAppLastUpdated,
    isUpdatingKnownApps = isUpdatingKnownApps,
    onUpdateKnownAppsClick = { viewModel.updateKnownApps() }
)
```

**c)** Update `ThreatDatabaseCard` signature to add 4 new parameters:

```kotlin
@Composable
private fun ThreatDatabaseCard(
    entryCount: Int,
    lastUpdated: Long?,
    isUpdating: Boolean,
    onUpdateClick: () -> Unit,
    domainEntryCount: Int,
    domainLastUpdated: Long?,
    isUpdatingDomain: Boolean,
    onUpdateDomainClick: () -> Unit,
    knownAppEntryCount: Int,
    knownAppLastUpdated: Long?,
    isUpdatingKnownApps: Boolean,
    onUpdateKnownAppsClick: () -> Unit
)
```

**d)** Inside `ThreatDatabaseCard`, after the closing brace of the domain IOC row+button block
(after the second `if (isDomainFresh)…else` block), add the new known-apps row.
Follow the exact same pattern as the domain IOC row:

```kotlin
// ── Known-app DB row ───────────────────────────────────────────────────────
val isKnownAppsNeverUpdated = knownAppLastUpdated == null
val isKnownAppsStale = knownAppLastUpdated != null && (now - knownAppLastUpdated) > 24 * 60 * 60 * 1000L
val isKnownAppsFresh = knownAppLastUpdated != null && !isKnownAppsStale

val knownAppsIconTint = if (isKnownAppsFresh) Color(0xFF00D4AA) else Color(0xFFFF9800)
val knownAppsIcon = when {
    isKnownAppsFresh        -> Icons.Filled.CheckCircle
    isKnownAppsNeverUpdated -> Icons.Filled.Warning
    else                    -> Icons.Filled.Refresh
}
val knownAppsStatusText = when {
    isKnownAppsNeverUpdated -> "$knownAppEntryCount app signatures · Remote update pending"
    isKnownAppsStale        -> "$knownAppEntryCount app signatures · Updated ${relativeTime(knownAppLastUpdated!!, now)} · Stale"
    else                    -> "$knownAppEntryCount app signatures · Updated ${relativeTime(knownAppLastUpdated!!, now)}"
}

Row(
    verticalAlignment = Alignment.CenterVertically,
    horizontalArrangement = Arrangement.spacedBy(8.dp)
) {
    Icon(imageVector = knownAppsIcon, contentDescription = null, tint = knownAppsIconTint,
        modifier = Modifier.size(20.dp))
    Text(text = knownAppsStatusText, style = MaterialTheme.typography.bodyMedium,
        fontWeight = FontWeight.SemiBold, color = MaterialTheme.colorScheme.onSurface)
}

if (isKnownAppsFresh) {
    OutlinedButton(onClick = onUpdateKnownAppsClick, enabled = !isUpdatingKnownApps,
        modifier = Modifier.fillMaxWidth()) {
        UpdateButtonContent(isUpdating = isUpdatingKnownApps)
    }
} else {
    Button(onClick = onUpdateKnownAppsClick, enabled = !isUpdatingKnownApps,
        modifier = Modifier.fillMaxWidth(),
        colors = ButtonDefaults.buttonColors(containerColor = Color(0xFFFF9800))) {
        UpdateButtonContent(isUpdating = isUpdatingKnownApps)
    }
}
```

- [ ] **Step 3: Build and run tests**

```bash
./gradlew assembleDebug testDebugUnitTest 2>&1 | tail -20
```

Expected: BUILD SUCCESSFUL, all tests pass.

- [ ] **Step 4: Commit**

```bash
git add app/src/main/java/com/androdr/ui/dashboard/DashboardViewModel.kt \
        app/src/main/java/com/androdr/ui/dashboard/DashboardScreen.kt
git commit -m "feat: add known-app DB row to DashboardViewModel and ThreatDatabaseCard"
```

---

## Task 12: Final verification and push

- [ ] **Step 1: Run the full test suite**

```bash
./gradlew testDebugUnitTest 2>&1 | tail -30
```

Expected: BUILD SUCCESSFUL with 0 failures.

- [ ] **Step 2: Run lint**

```bash
./gradlew lintDebug 2>&1 | grep -E "ERROR|error:" | head -20
```

Expected: no errors. Fix any warnings that appear as errors (lintDebug is configured to treat
some warnings as errors in this project).

- [ ] **Step 3: Build release APK to confirm ProGuard/R8 is happy**

```bash
./gradlew assembleRelease 2>&1 | tail -20
```

Expected: BUILD SUCCESSFUL.

- [ ] **Step 4: Push the branch**

```bash
git push origin claude/android-edr-setup-rl68Y
```

- [ ] **Step 5: Confirm**

Verify on GitHub that all commits are present and the branch is up to date with the plan.
