# MVT Domain IOC Feed + VPN Self-Exclusion Fix — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add Amnesty/MVT mercenary spyware domain indicators to the DNS monitor with configurable block/detect policy, and fix the VPN tunnel to exclude AndroDR's own HTTPS traffic.

**Architecture:** New `DomainIocEntry` Room table stores domains from MVT STIX2 feeds; `DomainIocResolver` provides O(k) label-stripping lookups; `DnsVpnService` checks each DNS hostname against both the static blocklist and the dynamic domain IOC cache with independent per-source policies stored in DataStore. The VPN fix is a single `.addDisallowedApplication(packageName)` call.

**Tech Stack:** Kotlin, Hilt, Room (manual migration), Jetpack DataStore (Preferences), Jetpack Compose, coroutines, mockk (tests)

**Test command:** `JAVA_HOME=/home/yasir/Applications/android-studio/jbr ./gradlew testDebugUnitTest`
**Build check:** `JAVA_HOME=/home/yasir/Applications/android-studio/jbr ./gradlew assembleDebug --quiet`

**Spec:** `docs/superpowers/specs/2026-03-25-mvt-feed-vpn-fix-design.md`

---

## File Map

| File | Status | Responsibility |
|------|--------|----------------|
| `app/src/main/java/com/androdr/network/DnsVpnService.kt` | Modify | VPN self-exclusion; domain IOC check; policy state flows |
| `app/src/main/java/com/androdr/data/model/DomainIocEntry.kt` | Create | Room entity for domain IOC rows |
| `app/src/main/java/com/androdr/data/db/DomainIocEntryDao.kt` | Create | Room DAO — upsert, getAll, count, deleteStale, mostRecentFetchTime |
| `app/src/main/java/com/androdr/data/db/Migrations.kt` | Modify | Add `MIGRATION_2_3` |
| `app/src/main/java/com/androdr/data/db/AppDatabase.kt` | Modify | Version 2→3; register migration; expose `DomainIocEntryDao` |
| `app/src/main/java/com/androdr/ioc/DomainIocFeed.kt` | Create | Interface mirroring `IocFeed` |
| `app/src/main/java/com/androdr/ioc/DomainIocResolver.kt` | Create | In-memory cache + hierarchical domain lookup |
| `app/src/main/java/com/androdr/ioc/feeds/MvtIndicatorsFeed.kt` | Create | Fetches indicators.yaml + STIX2 files; parses domain indicators |
| `app/src/main/java/com/androdr/ioc/DomainIocUpdater.kt` | Create | Orchestrates domain feeds; upserts to Room; prunes stale |
| `app/src/main/java/com/androdr/ioc/IocUpdateWorker.kt` | Modify | Inject `DomainIocUpdater`; run both updaters in parallel |
| `app/src/main/java/com/androdr/data/repo/SettingsRepository.kt` | Create | DataStore wrapper for two boolean policy keys |
| `app/src/main/java/com/androdr/di/AppModule.kt` | Modify | Provide DataStore, `SettingsRepository`, `DomainIocEntryDao` |
| `app/src/main/java/com/androdr/ui/settings/SettingsViewModel.kt` | Create | `@HiltViewModel` exposing policy toggles |
| `app/src/main/java/com/androdr/ui/settings/SettingsScreen.kt` | Create | Full settings screen with two Switch rows |
| `app/src/main/java/com/androdr/ui/network/DnsMonitorScreen.kt` | Modify | Add quick-toggle Switch rows above event list |
| `app/src/main/java/com/androdr/ui/dashboard/DashboardViewModel.kt` | Modify | Add domain IOC state + `updateDomainIoc()` |
| `app/src/main/java/com/androdr/ui/dashboard/DashboardScreen.kt` | Modify | `ThreatDatabaseCard` shows two rows; gear icon in header |
| `app/src/main/java/com/androdr/MainActivity.kt` | Modify | Add `settings` nav destination |
| `app/src/test/java/com/androdr/ioc/DomainIocResolverTest.kt` | Create | Unit tests for label-stripping lookup |
| `app/src/test/java/com/androdr/ioc/feeds/MvtIndicatorsFeedTest.kt` | Create | Unit tests for `parseIndicatorsYaml()` and `parseStix2()` |
| `app/src/test/java/com/androdr/ioc/DomainIocUpdaterTest.kt` | Create | Unit tests for update orchestration |
| `app/src/test/java/com/androdr/ioc/IocUpdateWorkerTest.kt` | Create | Unit test verifying both updaters are called |

---

## Task 1: VPN Self-Exclusion Fix

**Files:**
- Modify: `app/src/main/java/com/androdr/network/DnsVpnService.kt:107-113`

This is a one-line change with no unit test — it is a `VpnService.Builder` configuration that requires a live VPN tunnel to verify.

- [ ] **Step 1: Add `.addDisallowedApplication(packageName)` to `startVpn()`**

In `DnsVpnService.kt`, find the `Builder()` block in `startVpn()` (around line 107) and add one line:

```kotlin
val fd = try {
    Builder()
        .addAddress(TUN_ADDRESS, TUN_PREFIX_LEN)
        .addDnsServer(DNS_SERVER_IP)
        .addRoute("0.0.0.0", 0)
        .addDisallowedApplication(packageName)   // exclude AndroDR itself from the tunnel
        .setSession("AndroDR DNS Filter")
        .setBlocking(false)
        .establish()
```

- [ ] **Step 2: Build check**

```bash
JAVA_HOME=/home/yasir/Applications/android-studio/jbr ./gradlew assembleDebug --quiet
```
Expected: BUILD SUCCESSFUL

- [ ] **Step 3: Commit**

```bash
git add app/src/main/java/com/androdr/network/DnsVpnService.kt
git commit -m "fix: exclude AndroDR package from VPN tunnel to unblock IOC update HTTPS traffic"
```

---

## Task 2: DomainIocEntry, DomainIocEntryDao, Room Migration

**Files:**
- Create: `app/src/main/java/com/androdr/data/model/DomainIocEntry.kt`
- Create: `app/src/main/java/com/androdr/data/db/DomainIocEntryDao.kt`
- Modify: `app/src/main/java/com/androdr/data/db/Migrations.kt`
- Modify: `app/src/main/java/com/androdr/data/db/AppDatabase.kt`

- [ ] **Step 1: Create `DomainIocEntry.kt`**

```kotlin
package com.androdr.data.model

import androidx.room.Entity
import androidx.room.PrimaryKey

@Entity(tableName = "domain_ioc_entries")
data class DomainIocEntry(
    @PrimaryKey val domain: String,
    val campaignName: String,
    val severity: String,
    val source: String,
    val fetchedAt: Long
)
```

- [ ] **Step 2: Create `DomainIocEntryDao.kt`**

```kotlin
package com.androdr.data.db

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import com.androdr.data.model.DomainIocEntry

@Dao
interface DomainIocEntryDao {

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsertAll(entries: List<DomainIocEntry>)

    @Query("SELECT * FROM domain_ioc_entries")
    suspend fun getAll(): List<DomainIocEntry>

    @Query("SELECT COUNT(*) FROM domain_ioc_entries")
    suspend fun count(): Int

    @Query("DELETE FROM domain_ioc_entries WHERE source = :source AND fetchedAt < :olderThan")
    suspend fun deleteStaleEntries(source: String, olderThan: Long)

    @Query("SELECT MAX(fetchedAt) FROM domain_ioc_entries")
    suspend fun mostRecentFetchTime(): Long?
}
```

- [ ] **Step 3: Add `MIGRATION_2_3` to `Migrations.kt`**

Append to the end of `Migrations.kt`:

```kotlin
val MIGRATION_2_3 = object : Migration(2, 3) {
    override fun migrate(database: SupportSQLiteDatabase) {
        database.execSQL(
            """
            CREATE TABLE IF NOT EXISTS domain_ioc_entries (
                domain       TEXT NOT NULL PRIMARY KEY,
                campaignName TEXT NOT NULL,
                severity     TEXT NOT NULL,
                source       TEXT NOT NULL,
                fetchedAt    INTEGER NOT NULL
            )
            """.trimIndent()
        )
    }
}
```

- [ ] **Step 4: Update `AppDatabase.kt`**

```kotlin
package com.androdr.data.db

import androidx.room.Database
import androidx.room.RoomDatabase
import androidx.room.TypeConverters
import com.androdr.data.model.DnsEvent
import com.androdr.data.model.DomainIocEntry
import com.androdr.data.model.IocEntry
import com.androdr.data.model.ScanResult

@Database(
    entities = [ScanResult::class, DnsEvent::class, IocEntry::class, DomainIocEntry::class],
    version = 3,
    exportSchema = false
)
@TypeConverters(Converters::class)
abstract class AppDatabase : RoomDatabase() {

    abstract fun scanResultDao(): ScanResultDao
    abstract fun dnsEventDao(): DnsEventDao
    abstract fun iocEntryDao(): IocEntryDao
    abstract fun domainIocEntryDao(): DomainIocEntryDao
}
```

- [ ] **Step 5: Build check**

```bash
JAVA_HOME=/home/yasir/Applications/android-studio/jbr ./gradlew assembleDebug --quiet
```
Expected: BUILD SUCCESSFUL (Room annotation processor validates the schema)

- [ ] **Step 6: Commit**

```bash
git add app/src/main/java/com/androdr/data/model/DomainIocEntry.kt \
        app/src/main/java/com/androdr/data/db/DomainIocEntryDao.kt \
        app/src/main/java/com/androdr/data/db/Migrations.kt \
        app/src/main/java/com/androdr/data/db/AppDatabase.kt
git commit -m "feat: add DomainIocEntry Room entity, DAO, and MIGRATION_2_3"
```

---

## Task 3: DomainIocResolver

**Files:**
- Create: `app/src/test/java/com/androdr/ioc/DomainIocResolverTest.kt`
- Create: `app/src/main/java/com/androdr/ioc/DomainIocResolver.kt`

- [ ] **Step 1: Write the failing tests**

Create `app/src/test/java/com/androdr/ioc/DomainIocResolverTest.kt`:

```kotlin
package com.androdr.ioc

import com.androdr.data.db.DomainIocEntryDao
import com.androdr.data.model.DomainIocEntry
import io.mockk.coEvery
import io.mockk.mockk
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Before
import org.junit.Test

class DomainIocResolverTest {

    private val dao: DomainIocEntryDao = mockk()
    private lateinit var resolver: DomainIocResolver

    private val pegasusEntry = DomainIocEntry(
        domain = "evil.com",
        campaignName = "NSO Group Pegasus",
        severity = "CRITICAL",
        source = "mvt_pegasus",
        fetchedAt = 1000L
    )

    @Before
    fun setUp() {
        resolver = DomainIocResolver(dao)
    }

    @Test
    fun `isKnownBadDomain returns null before cache is loaded`() {
        assertNull(resolver.isKnownBadDomain("evil.com"))
    }

    @Test
    fun `isKnownBadDomain returns entry for exact apex match after refresh`() = runTest {
        coEvery { dao.getAll() } returns listOf(pegasusEntry)
        resolver.refreshCache()
        val result = resolver.isKnownBadDomain("evil.com")
        assertEquals("evil.com", result?.domain)
        assertEquals("NSO Group Pegasus", result?.campaignName)
    }

    @Test
    fun `isKnownBadDomain returns entry for subdomain via label-stripping`() = runTest {
        coEvery { dao.getAll() } returns listOf(pegasusEntry)
        resolver.refreshCache()
        assertNull(null, resolver.isKnownBadDomain("evil.com")?.let {
            assertNull(resolver.isKnownBadDomain("unrelated.com"))
            null
        })
        assertEquals("evil.com", resolver.isKnownBadDomain("c2.evil.com")?.domain)
        assertEquals("evil.com", resolver.isKnownBadDomain("deep.sub.evil.com")?.domain)
    }

    @Test
    fun `isKnownBadDomain returns null for unrelated domain`() = runTest {
        coEvery { dao.getAll() } returns listOf(pegasusEntry)
        resolver.refreshCache()
        assertNull(resolver.isKnownBadDomain("safe.com"))
        assertNull(resolver.isKnownBadDomain("notevil.com"))
    }

    @Test
    fun `isKnownBadDomain handles trailing dot in query`() = runTest {
        coEvery { dao.getAll() } returns listOf(pegasusEntry)
        resolver.refreshCache()
        assertEquals("evil.com", resolver.isKnownBadDomain("evil.com.")?.domain)
    }

    @Test
    fun `isKnownBadDomain returns null for empty cache after refresh with no entries`() = runTest {
        coEvery { dao.getAll() } returns emptyList()
        resolver.refreshCache()
        assertNull(resolver.isKnownBadDomain("evil.com"))
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
JAVA_HOME=/home/yasir/Applications/android-studio/jbr ./gradlew testDebugUnitTest \
  --tests "com.androdr.ioc.DomainIocResolverTest" --quiet 2>&1 | tail -10
```
Expected: FAILED (class not found)

- [ ] **Step 3: Implement `DomainIocResolver.kt`**

```kotlin
package com.androdr.ioc

import com.androdr.data.db.DomainIocEntryDao
import com.androdr.data.model.DomainIocEntry
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.util.concurrent.atomic.AtomicReference
import javax.inject.Inject
import javax.inject.Singleton

/**
 * In-memory lookup for domain-based IOC entries fetched from remote MVT feeds.
 *
 * Performs the same label-stripping hierarchy walk as [com.androdr.network.BlocklistManager]
 * so that a query for "c2.evil.com" matches an entry keyed on "evil.com".
 *
 * Call [refreshCache] after each [com.androdr.ioc.DomainIocUpdater] run and on app startup.
 */
@Singleton
class DomainIocResolver @Inject constructor(
    private val dao: DomainIocEntryDao
) {
    private val cache = AtomicReference<Map<String, DomainIocEntry>?>(null)

    /** Reloads all domain IOC rows from Room into the in-memory cache. */
    suspend fun refreshCache() = withContext(Dispatchers.IO) {
        val map = buildMap<String, DomainIocEntry> {
            dao.getAll().forEach { entry -> put(entry.domain, entry) }
        }
        cache.set(map)
    }

    /**
     * Returns the [DomainIocEntry] whose domain matches [domain] or any of its parent domains,
     * or `null` if no match is found or the cache has not yet been loaded.
     */
    @Suppress("ReturnCount") // Label-stripping walk uses early returns identical to BlocklistManager
    fun isKnownBadDomain(domain: String): DomainIocEntry? {
        val snapshot = cache.get() ?: return null
        if (domain.isBlank()) return null

        var candidate = domain.trimEnd('.').lowercase()
        while (candidate.isNotEmpty()) {
            snapshot[candidate]?.let { return it }
            val dot = candidate.indexOf('.')
            if (dot < 0) break
            candidate = candidate.substring(dot + 1)
        }
        return null
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
JAVA_HOME=/home/yasir/Applications/android-studio/jbr ./gradlew testDebugUnitTest \
  --tests "com.androdr.ioc.DomainIocResolverTest" --quiet 2>&1 | tail -10
```
Expected: BUILD SUCCESSFUL, 6 tests passed

- [ ] **Step 5: Commit**

```bash
git add app/src/main/java/com/androdr/ioc/DomainIocResolver.kt \
        app/src/test/java/com/androdr/ioc/DomainIocResolverTest.kt
git commit -m "feat: add DomainIocResolver with label-stripping hierarchy lookup"
```

---

## Task 4: MvtIndicatorsFeed — parseIndicatorsYaml()

**Files:**
- Create: `app/src/test/java/com/androdr/ioc/feeds/MvtIndicatorsFeedTest.kt`
- Create: `app/src/main/java/com/androdr/ioc/feeds/MvtIndicatorsFeed.kt` (partial — parse functions only)

- [ ] **Step 1: Write the failing tests**

Create `app/src/test/java/com/androdr/ioc/feeds/MvtIndicatorsFeedTest.kt`:

```kotlin
package com.androdr.ioc.feeds

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class MvtIndicatorsFeedTest {

    private val feed = MvtIndicatorsFeed()

    // ── parseIndicatorsYaml ────────────────────────────────────────────────────

    private val sampleYaml = """
        indicators:
          -
            type: github
            name: NSO Group Pegasus Indicators of Compromise
            github:
              owner: AmnestyTech
              repo: investigations
              branch: master
              path: 2021-07-18_nso/pegasus.stix2
          -
            type: github
            name: Predator Spyware Indicators of Compromise
            github:
              owner: mvt-project
              repo: mvt-indicators
              branch: main
              path: intellexa_predator/predator.stix2
          -
            type: other
            name: Some other feed
    """.trimIndent()

    @Test
    fun `parseIndicatorsYaml extracts github-type entries only`() {
        val campaigns = feed.parseIndicatorsYaml(sampleYaml)
        assertEquals(2, campaigns.size)
    }

    @Test
    fun `parseIndicatorsYaml builds correct raw github URLs`() {
        val campaigns = feed.parseIndicatorsYaml(sampleYaml)
        assertEquals(
            "https://raw.githubusercontent.com/AmnestyTech/investigations/master/2021-07-18_nso/pegasus.stix2",
            campaigns[0].url
        )
        assertEquals(
            "https://raw.githubusercontent.com/mvt-project/mvt-indicators/main/intellexa_predator/predator.stix2",
            campaigns[1].url
        )
    }

    @Test
    fun `parseIndicatorsYaml captures campaign names`() {
        val campaigns = feed.parseIndicatorsYaml(sampleYaml)
        assertEquals("NSO Group Pegasus Indicators of Compromise", campaigns[0].name)
        assertEquals("Predator Spyware Indicators of Compromise", campaigns[1].name)
    }

    @Test
    fun `parseIndicatorsYaml returns empty list for empty yaml`() {
        assertTrue(feed.parseIndicatorsYaml("").isEmpty())
    }

    // ── parseStix2 ─────────────────────────────────────────────────────────────

    private val singleDomainStix2 = """
        {
          "type": "bundle",
          "objects": [
            {
              "type": "indicator",
              "pattern_type": "stix",
              "pattern": "[domain-name:value = 'weather4free.com']",
              "indicator_types": ["malicious-activity"]
            }
          ]
        }
    """.trimIndent()

    private val compoundOrStix2 = """
        {
          "type": "bundle",
          "objects": [
            {
              "type": "indicator",
              "pattern_type": "stix",
              "pattern": "[domain-name:value = 'foo.com' OR domain-name:value = 'bar.com']",
              "indicator_types": ["malicious-activity"]
            }
          ]
        }
    """.trimIndent()

    private val mixedStix2 = """
        {
          "type": "bundle",
          "objects": [
            {
              "type": "malware",
              "name": "Pegasus"
            },
            {
              "type": "indicator",
              "pattern_type": "stix",
              "pattern": "[domain-name:value = 'spyware.io']",
              "indicator_types": ["malicious-activity"]
            },
            {
              "type": "indicator",
              "pattern_type": "pcre",
              "pattern": ".*spyware.*",
              "indicator_types": ["malicious-activity"]
            }
          ]
        }
    """.trimIndent()

    @Test
    fun `parseStix2 extracts single domain from simple indicator`() {
        val domains = feed.parseStix2(singleDomainStix2, "NSO Group Pegasus", "mvt_pegasus", 1000L)
        assertEquals(1, domains.size)
        assertEquals("weather4free.com", domains[0].domain)
    }

    @Test
    fun `parseStix2 extracts multiple domains from compound OR pattern`() {
        val domains = feed.parseStix2(compoundOrStix2, "Predator", "mvt_predator", 1000L)
        assertEquals(2, domains.size)
        val domainNames = domains.map { it.domain }.toSet()
        assertEquals(setOf("foo.com", "bar.com"), domainNames)
    }

    @Test
    fun `parseStix2 ignores non-stix pattern types and non-indicator objects`() {
        val domains = feed.parseStix2(mixedStix2, "NSO Group Pegasus", "mvt_pegasus", 1000L)
        assertEquals(1, domains.size)
        assertEquals("spyware.io", domains[0].domain)
    }

    @Test
    fun `parseStix2 sets correct metadata on entries`() {
        val domains = feed.parseStix2(singleDomainStix2, "NSO Group Pegasus", "mvt_pegasus", 9999L)
        val entry = domains[0]
        assertEquals("NSO Group Pegasus", entry.campaignName)
        assertEquals("CRITICAL", entry.severity)
        assertEquals("mvt_pegasus", entry.source)
        assertEquals(9999L, entry.fetchedAt)
    }

    @Test
    fun `parseStix2 returns empty list for malformed JSON`() {
        assertTrue(feed.parseStix2("not json", "test", "mvt_test", 0L).isEmpty())
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
JAVA_HOME=/home/yasir/Applications/android-studio/jbr ./gradlew testDebugUnitTest \
  --tests "com.androdr.ioc.feeds.MvtIndicatorsFeedTest" --quiet 2>&1 | tail -10
```
Expected: FAILED (class not found)

- [ ] **Step 3: Create `MvtIndicatorsFeed.kt` with parse functions**

```kotlin
package com.androdr.ioc.feeds

import android.util.Log
import com.androdr.data.model.DomainIocEntry
import com.androdr.ioc.DomainIocFeed
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL

/**
 * Fetches mercenary spyware domain indicators from the MVT project's indicators.yaml index,
 * which references multiple STIX2 files (Pegasus, Predator, RCS Lab, etc.).
 *
 * Both [parseIndicatorsYaml] and [parseStix2] are `internal` so unit tests can reach them
 * directly from the `test` source set without reflection.
 */
class MvtIndicatorsFeed : DomainIocFeed {

    override val sourceId = SOURCE_ID

    @Suppress("TooGenericExceptionCaught")
    override suspend fun fetch(): List<DomainIocEntry> = withContext(Dispatchers.IO) {
        try {
            val yaml = httpGet(INDICATORS_YAML_URL) ?: return@withContext emptyList()
            val campaigns = parseIndicatorsYaml(yaml)
            if (campaigns.isEmpty()) return@withContext emptyList()

            val now = System.currentTimeMillis()
            coroutineScope {
                campaigns.map { campaign ->
                    async {
                        try {
                            val stix2 = httpGet(campaign.url) ?: return@async emptyList()
                            parseStix2(stix2, campaign.name, toSlug(campaign.name), now)
                        } catch (e: Exception) {
                            Log.w(TAG, "Failed to fetch campaign '${campaign.name}': ${e.message}")
                            emptyList()
                        }
                    }
                }.flatMap { it.await() }
            }
        } catch (e: Exception) {
            Log.e(TAG, "MvtIndicatorsFeed.fetch failed: ${e.message}")
            emptyList()
        }
    }

    // ── Parsers (internal for testability) ────────────────────────────────────

    internal data class CampaignRef(val name: String, val url: String)

    /**
     * Parses `indicators.yaml` line-by-line and returns one [CampaignRef] per
     * `type: github` entry, with the raw GitHub URL constructed from the `github:` block.
     */
    internal fun parseIndicatorsYaml(yaml: String): List<CampaignRef> {
        val results = mutableListOf<CampaignRef>()
        var isGithubType = false
        var currentName = ""
        var owner = ""; var repo = ""; var branch = ""; var path = ""

        fun flush() {
            if (isGithubType && currentName.isNotEmpty() &&
                owner.isNotEmpty() && repo.isNotEmpty() && branch.isNotEmpty() && path.isNotEmpty()
            ) {
                results.add(CampaignRef(
                    name = currentName,
                    url = "https://raw.githubusercontent.com/$owner/$repo/$branch/$path"
                ))
            }
            isGithubType = false; currentName = ""; owner = ""; repo = ""; branch = ""; path = ""
        }

        for (line in yaml.lines()) {
            val trimmed = line.trim()
            when {
                trimmed == "-" -> flush()
                trimmed.startsWith("type:") -> {
                    val v = trimmed.removePrefix("type:").trim()
                    if (v == "github") isGithubType = true
                }
                trimmed.startsWith("name:") -> currentName = trimmed.removePrefix("name:").trim()
                trimmed.startsWith("owner:") -> owner = trimmed.removePrefix("owner:").trim()
                trimmed.startsWith("repo:")  -> repo  = trimmed.removePrefix("repo:").trim()
                trimmed.startsWith("branch:")-> branch= trimmed.removePrefix("branch:").trim()
                trimmed.startsWith("path:")  -> path  = trimmed.removePrefix("path:").trim()
            }
        }
        flush()
        return results
    }

    /**
     * Parses a STIX2 bundle JSON string and returns one [DomainIocEntry] per domain found
     * in `indicator` objects with `pattern_type == "stix"`.
     *
     * Handles both single-domain patterns `[domain-name:value = 'foo.com']`
     * and compound OR patterns `[... OR domain-name:value = 'bar.com']` via `findAll`.
     */
    @Suppress("TooGenericExceptionCaught", "SwallowedException")
    internal fun parseStix2(
        json: String,
        campaignName: String,
        source: String,
        fetchedAt: Long
    ): List<DomainIocEntry> {
        return try {
            val objects: JSONArray = JSONObject(json).optJSONArray("objects") ?: return emptyList()
            val results = mutableListOf<DomainIocEntry>()
            for (i in 0 until objects.length()) {
                val obj = objects.getJSONObject(i)
                if (obj.optString("type") != "indicator") continue
                if (obj.optString("pattern_type") != "stix") continue
                val pattern = obj.optString("pattern")
                DOMAIN_REGEX.findAll(pattern).forEach { match ->
                    results.add(DomainIocEntry(
                        domain = match.groupValues[1].lowercase(),
                        campaignName = campaignName,
                        severity = "CRITICAL",
                        source = source,
                        fetchedAt = fetchedAt
                    ))
                }
            }
            results
        } catch (e: Exception) {
            Log.w(TAG, "parseStix2 failed: ${e.message}")
            emptyList()
        }
    }

    // ── Private helpers ────────────────────────────────────────────────────────

    @Suppress("TooGenericExceptionCaught", "SwallowedException")
    private fun httpGet(url: String): String? = try {
        (URL(url).openConnection() as HttpURLConnection).run {
            connectTimeout = 15_000; readTimeout = 15_000
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

    private fun toSlug(name: String) =
        "mvt_" + name.lowercase().replace(Regex("[^a-z0-9]+"), "_").trim('_')

    companion object {
        private const val TAG = "MvtIndicatorsFeed"
        const val SOURCE_ID = "mvt_indicators"
        private const val INDICATORS_YAML_URL =
            "https://raw.githubusercontent.com/mvt-project/mvt-indicators/main/indicators.yaml"
        private val DOMAIN_REGEX = Regex("""domain-name:value\s*=\s*'([^']+)'""")
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
JAVA_HOME=/home/yasir/Applications/android-studio/jbr ./gradlew testDebugUnitTest \
  --tests "com.androdr.ioc.feeds.MvtIndicatorsFeedTest" --quiet 2>&1 | tail -10
```
Expected: BUILD SUCCESSFUL, all tests pass

- [ ] **Step 5: Commit**

```bash
git add app/src/main/java/com/androdr/ioc/feeds/MvtIndicatorsFeed.kt \
        app/src/test/java/com/androdr/ioc/feeds/MvtIndicatorsFeedTest.kt
git commit -m "feat: add MvtIndicatorsFeed with YAML index + STIX2 domain parser"
```

---

## Task 5: DomainIocFeed Interface + DomainIocUpdater

**Files:**
- Create: `app/src/main/java/com/androdr/ioc/DomainIocFeed.kt`
- Create: `app/src/main/java/com/androdr/ioc/DomainIocUpdater.kt`
- Create: `app/src/test/java/com/androdr/ioc/DomainIocUpdaterTest.kt`

- [ ] **Step 1: Write the failing test**

Create `app/src/test/java/com/androdr/ioc/DomainIocUpdaterTest.kt`:

```kotlin
package com.androdr.ioc

import com.androdr.data.db.DomainIocEntryDao
import com.androdr.data.model.DomainIocEntry
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.mockk
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Test

class DomainIocUpdaterTest {

    private val dao: DomainIocEntryDao = mockk(relaxed = true)
    private val resolver: DomainIocResolver = mockk(relaxed = true)

    private val entry = DomainIocEntry(
        domain = "evil.com", campaignName = "Test", severity = "CRITICAL",
        source = "mvt_test", fetchedAt = 1000L
    )

    @Test
    fun `update returns count of entries stored`() = runTest {
        val testFeed = object : DomainIocFeed {
            override val sourceId = "mvt_test"
            override suspend fun fetch() = listOf(entry)
        }
        val updater = DomainIocUpdater(dao, resolver, listOf(testFeed))
        coEvery { dao.count() } returns 1
        val result = updater.update()
        assertEquals(1, result)
    }

    @Test
    fun `update calls refreshCache after upsert`() = runTest {
        val testFeed = object : DomainIocFeed {
            override val sourceId = "mvt_test"
            override suspend fun fetch() = listOf(entry)
        }
        val updater = DomainIocUpdater(dao, resolver, listOf(testFeed))
        coEvery { dao.count() } returns 1
        updater.update()
        coVerify { resolver.refreshCache() }
    }

    @Test
    fun `update returns 0 when all feeds return empty`() = runTest {
        val testFeed = object : DomainIocFeed {
            override val sourceId = "mvt_test"
            override suspend fun fetch() = emptyList<DomainIocEntry>()
        }
        val updater = DomainIocUpdater(dao, resolver, listOf(testFeed))
        coEvery { dao.count() } returns 0
        assertEquals(0, updater.update())
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
JAVA_HOME=/home/yasir/Applications/android-studio/jbr ./gradlew testDebugUnitTest \
  --tests "com.androdr.ioc.DomainIocUpdaterTest" --quiet 2>&1 | tail -10
```
Expected: FAILED (class not found)

- [ ] **Step 3: Create `DomainIocFeed.kt`**

```kotlin
package com.androdr.ioc

import com.androdr.data.model.DomainIocEntry

/**
 * Common interface for domain-based IOC feed adapters.
 * Mirrors [IocFeed]; return an empty list on any failure (never throw).
 */
interface DomainIocFeed {
    val sourceId: String
    suspend fun fetch(): List<DomainIocEntry>
}
```

- [ ] **Step 4: Create `DomainIocUpdater.kt`**

Note: The production constructor (used by Hilt) takes only `dao` and `resolver`; the `feeds` parameter has a default for testability.

```kotlin
package com.androdr.ioc

import android.util.Log
import com.androdr.data.db.DomainIocEntryDao
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.withContext
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Orchestrates all domain IOC feeds: runs them in parallel, upserts results into Room,
 * prunes stale entries, then refreshes [DomainIocResolver] so new data takes effect immediately.
 *
 * Mirrors [RemoteIocUpdater] for package-based IOCs.
 */
@Singleton
class DomainIocUpdater @Inject constructor(
    private val domainIocEntryDao: DomainIocEntryDao,
    private val domainIocResolver: DomainIocResolver,
    private val feeds: List<DomainIocFeed> = listOf(MvtIndicatorsFeed())
) {

    @Suppress("TooGenericExceptionCaught") // Network I/O; swallow per-feed failures.
    suspend fun update(): Int = withContext(Dispatchers.IO) {
        var totalStored = 0
        coroutineScope {
            val deferreds = feeds.map { feed ->
                async {
                    val entries = feed.fetch()
                    if (entries.isNotEmpty()) {
                        domainIocEntryDao.upsertAll(entries)
                        val runStart = entries.minOf { it.fetchedAt } - 1
                        domainIocEntryDao.deleteStaleEntries(feed.sourceId, runStart)
                        Log.i(TAG, "Domain feed '${feed.sourceId}': ${entries.size} entries upserted")
                    } else {
                        Log.w(TAG, "Domain feed '${feed.sourceId}': no entries returned")
                    }
                    entries.size
                }
            }
            totalStored = deferreds.sumOf { it.await() }
        }
        domainIocResolver.refreshCache()
        Log.i(TAG, "Domain update complete — fetched: $totalStored, DB: ${domainIocEntryDao.count()}")
        totalStored
    }

    companion object {
        private const val TAG = "DomainIocUpdater"
    }
}
```

- [ ] **Step 5: Run tests to verify they pass**

```bash
JAVA_HOME=/home/yasir/Applications/android-studio/jbr ./gradlew testDebugUnitTest \
  --tests "com.androdr.ioc.DomainIocUpdaterTest" --quiet 2>&1 | tail -10
```
Expected: BUILD SUCCESSFUL, 3 tests pass

- [ ] **Step 6: Commit**

```bash
git add app/src/main/java/com/androdr/ioc/DomainIocFeed.kt \
        app/src/main/java/com/androdr/ioc/DomainIocUpdater.kt \
        app/src/test/java/com/androdr/ioc/DomainIocUpdaterTest.kt
git commit -m "feat: add DomainIocFeed interface and DomainIocUpdater orchestrator"
```

---

## Task 6: IocUpdateWorker — add DomainIocUpdater

**Files:**
- Modify: `app/src/main/java/com/androdr/ioc/IocUpdateWorker.kt`
- Create: `app/src/test/java/com/androdr/ioc/IocUpdateWorkerTest.kt`

- [ ] **Step 1: Write the failing test**

Create `app/src/test/java/com/androdr/ioc/IocUpdateWorkerTest.kt`:

```kotlin
package com.androdr.ioc

import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.mockk
import kotlinx.coroutines.test.runTest
import org.junit.Test

class IocUpdateWorkerTest {

    private val remoteIocUpdater: RemoteIocUpdater = mockk()
    private val domainIocUpdater: DomainIocUpdater = mockk()

    @Test
    fun `doWork calls both remoteIocUpdater and domainIocUpdater`() = runTest {
        coEvery { remoteIocUpdater.update() } returns 10
        coEvery { domainIocUpdater.update() } returns 20

        // Call the shared logic directly (extracted to internal fun for testability)
        runBothUpdaters(remoteIocUpdater, domainIocUpdater)

        coVerify { remoteIocUpdater.update() }
        coVerify { domainIocUpdater.update() }
    }
}
```

Because `CoroutineWorker.doWork()` requires Android WorkManager internals, extract the core logic into a package-private `suspend fun runBothUpdaters(...)` in the same file so it is testable without a WorkManager test harness.

- [ ] **Step 2: Run test to verify it fails**

```bash
JAVA_HOME=/home/yasir/Applications/android-studio/jbr ./gradlew testDebugUnitTest \
  --tests "com.androdr.ioc.IocUpdateWorkerTest" --quiet 2>&1 | tail -10
```
Expected: FAILED

- [ ] **Step 3: Update `IocUpdateWorker.kt`**

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
    private val domainIocUpdater: DomainIocUpdater
) : CoroutineWorker(context, params) {

    @Suppress("TooGenericExceptionCaught")
    override suspend fun doWork(): Result {
        return try {
            val fetched = runBothUpdaters(remoteIocUpdater, domainIocUpdater)
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

/** Runs both updaters in parallel; returns combined entry count. Extracted for testability. */
internal suspend fun runBothUpdaters(
    remoteIocUpdater: RemoteIocUpdater,
    domainIocUpdater: DomainIocUpdater
): Int = coroutineScope {
    val pkg    = async { remoteIocUpdater.update() }
    val domain = async { domainIocUpdater.update() }
    pkg.await() + domain.await()
}
```

- [ ] **Step 4: Run test to verify it passes**

```bash
JAVA_HOME=/home/yasir/Applications/android-studio/jbr ./gradlew testDebugUnitTest \
  --tests "com.androdr.ioc.IocUpdateWorkerTest" --quiet 2>&1 | tail -10
```
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add app/src/main/java/com/androdr/ioc/IocUpdateWorker.kt \
        app/src/test/java/com/androdr/ioc/IocUpdateWorkerTest.kt
git commit -m "feat: run domain IOC updater alongside package IOC updater in background worker"
```

---

## Task 7: SettingsRepository + AppModule wiring

**Files:**
- Create: `app/src/main/java/com/androdr/data/repo/SettingsRepository.kt`
- Modify: `app/src/main/java/com/androdr/di/AppModule.kt`

- [ ] **Step 1: Create `SettingsRepository.kt`**

```kotlin
package com.androdr.data.repo

import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.edit
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Persists two DNS policy settings in Jetpack DataStore (Preferences):
 *
 * - [blocklistBlockMode]: `true` = NXDOMAIN for static blocklist hits; `false` = detect-only
 * - [domainIocBlockMode]: `true` = NXDOMAIN for IOC domain hits; `false` = detect-only (default)
 */
@Singleton
class SettingsRepository @Inject constructor(
    private val dataStore: DataStore<Preferences>
) {

    val blocklistBlockMode: Flow<Boolean> = dataStore.data
        .map { prefs -> prefs[KEY_BLOCKLIST_BLOCK_MODE] ?: true }

    val domainIocBlockMode: Flow<Boolean> = dataStore.data
        .map { prefs -> prefs[KEY_DOMAIN_IOC_BLOCK_MODE] ?: false }

    suspend fun setBlocklistBlockMode(value: Boolean) {
        dataStore.edit { it[KEY_BLOCKLIST_BLOCK_MODE] = value }
    }

    suspend fun setDomainIocBlockMode(value: Boolean) {
        dataStore.edit { it[KEY_DOMAIN_IOC_BLOCK_MODE] = value }
    }

    companion object {
        private val KEY_BLOCKLIST_BLOCK_MODE  = booleanPreferencesKey("blocklist_block_mode")
        private val KEY_DOMAIN_IOC_BLOCK_MODE = booleanPreferencesKey("domain_ioc_block_mode")
    }
}
```

- [ ] **Step 2: Add DataStore dependency to `app/build.gradle.kts`**

In the `dependencies { }` block, add:

```kotlin
implementation("androidx.datastore:datastore-preferences:1.1.1")
```

- [ ] **Step 3: Update `AppModule.kt`**

Add imports and two new `@Provides` methods:

```kotlin
import android.content.Context
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.preferencesDataStore
import com.androdr.data.db.DomainIocEntryDao
import com.androdr.data.db.MIGRATION_2_3

// Add to AppModule object:

private val Context.settingsDataStore: DataStore<Preferences>
    by preferencesDataStore(name = "androdr_settings")

@Provides
@Singleton
fun provideSettingsDataStore(@ApplicationContext ctx: Context): DataStore<Preferences> =
    ctx.settingsDataStore

@Provides
fun provideDomainIocEntryDao(db: AppDatabase): DomainIocEntryDao = db.domainIocEntryDao()
```

Also add `MIGRATION_2_3` to the database builder:

```kotlin
Room.databaseBuilder(ctx, AppDatabase::class.java, "androdr.db")
    .addMigrations(MIGRATION_1_2, MIGRATION_2_3)
    .build()
```

- [ ] **Step 4: Build check**

```bash
JAVA_HOME=/home/yasir/Applications/android-studio/jbr ./gradlew assembleDebug --quiet
```
Expected: BUILD SUCCESSFUL

- [ ] **Step 5: Commit**

```bash
git add app/src/main/java/com/androdr/data/repo/SettingsRepository.kt \
        app/src/main/java/com/androdr/di/AppModule.kt \
        app/build.gradle.kts
git commit -m "feat: add SettingsRepository (DataStore) and wire DI for domain IOC + settings"
```

---

## Task 8: DnsVpnService — domain IOC check + policy integration

**Files:**
- Modify: `app/src/main/java/com/androdr/network/DnsVpnService.kt`

- [ ] **Step 1: Add injected fields**

In `DnsVpnService`, add two new `@Inject` fields after the existing ones (line ~68-70):

```kotlin
@Suppress("LateinitUsage")
@Inject lateinit var domainIocResolver: DomainIocResolver
@Suppress("LateinitUsage")
@Inject lateinit var settingsRepository: SettingsRepository
```

- [ ] **Step 2: Add policy state flows and collection in `startVpn()`**

Add two `MutableStateFlow` fields to the class (after `private var readLoopJob`):

```kotlin
private val blocklistBlockMode = MutableStateFlow(true)
private val domainIocBlockMode = MutableStateFlow(false)
```

In `startVpn()`, after `isRunning.value = true` and before `readLoopJob = ...`, add:

```kotlin
serviceScope.launch {
    settingsRepository.blocklistBlockMode.collect { blocklistBlockMode.value = it }
}
serviceScope.launch {
    settingsRepository.domainIocBlockMode.collect { domainIocBlockMode.value = it }
}
serviceScope.launch { domainIocResolver.refreshCache() }
```

Add missing imports: `com.androdr.data.repo.SettingsRepository`, `com.androdr.ioc.DomainIocResolver`.

- [ ] **Step 3: Update the query path in `processPacket()`**

Replace the `if (blocklistManager.isBlocked(hostname)) { ... } else { ... }` block with the new three-branch logic. The blocked path now respects `blocklistBlockMode`, and a new second check handles domain IOC hits with `domainIocBlockMode`:

```kotlin
val isBlocklisted = blocklistManager.isBlocked(hostname)
val iocHit = if (!isBlocklisted) domainIocResolver.isKnownBadDomain(hostname) else null

when {
    isBlocklisted && blocklistBlockMode.value -> {
        serviceScope.launch {
            runCatching {
                scanRepository.logDnsEvent(DnsEvent(
                    timestamp = System.currentTimeMillis(), domain = hostname,
                    appUid = -1, appName = null, isBlocked = true, reason = "blocklist"
                ))
            }
        }
        val nxResponse = buildNxdomainResponse(dnsPayload, txId)
        val responsePacket = wrapInIpUdp(nxResponse, intArrayOf(10,0,0,1),
            byteArrayToIntArray(srcIpBytes), DNS_PORT, srcPort)
        try { outputStream.write(responsePacket) } catch (_: Exception) {}
    }
    isBlocklisted -> {
        // detect-only: forward but log as flagged
        serviceScope.launch {
            val response = forwardToUpstreamDns(dnsPayload) ?: return@launch
            val responsePacket = wrapInIpUdp(response, intArrayOf(10,0,0,1),
                byteArrayToIntArray(srcIpBytes), DNS_PORT, srcPort)
            try { outputStream.write(responsePacket) } catch (_: Exception) {}
            runCatching {
                scanRepository.logDnsEvent(DnsEvent(
                    timestamp = System.currentTimeMillis(), domain = hostname,
                    appUid = -1, appName = null, isBlocked = false, reason = "blocklist_detect"
                ))
            }
        }
    }
    iocHit != null && domainIocBlockMode.value -> {
        serviceScope.launch {
            runCatching {
                scanRepository.logDnsEvent(DnsEvent(
                    timestamp = System.currentTimeMillis(), domain = hostname,
                    appUid = -1, appName = null, isBlocked = true,
                    reason = "IOC: ${iocHit.campaignName}"
                ))
            }
        }
        val nxResponse = buildNxdomainResponse(dnsPayload, txId)
        val responsePacket = wrapInIpUdp(nxResponse, intArrayOf(10,0,0,1),
            byteArrayToIntArray(srcIpBytes), DNS_PORT, srcPort)
        try { outputStream.write(responsePacket) } catch (_: Exception) {}
    }
    iocHit != null -> {
        // detect-only for IOC domain
        serviceScope.launch {
            val response = forwardToUpstreamDns(dnsPayload) ?: return@launch
            val responsePacket = wrapInIpUdp(response, intArrayOf(10,0,0,1),
                byteArrayToIntArray(srcIpBytes), DNS_PORT, srcPort)
            try { outputStream.write(responsePacket) } catch (_: Exception) {}
            runCatching {
                scanRepository.logDnsEvent(DnsEvent(
                    timestamp = System.currentTimeMillis(), domain = hostname,
                    appUid = -1, appName = null, isBlocked = false,
                    reason = "IOC_detect: ${iocHit.campaignName}"
                ))
            }
        }
    }
    else -> {
        // allowed — forward and log
        serviceScope.launch {
            val response = forwardToUpstreamDns(dnsPayload) ?: return@launch
            val responsePacket = wrapInIpUdp(response, intArrayOf(10,0,0,1),
                byteArrayToIntArray(srcIpBytes), DNS_PORT, srcPort)
            try { outputStream.write(responsePacket) } catch (_: Exception) {}
            runCatching {
                scanRepository.logDnsEvent(DnsEvent(
                    timestamp = System.currentTimeMillis(), domain = hostname,
                    appUid = -1, appName = null, isBlocked = false, reason = null
                ))
            }
        }
    }
}
```

- [ ] **Step 4: Build check + unit tests**

```bash
JAVA_HOME=/home/yasir/Applications/android-studio/jbr ./gradlew assembleDebug --quiet && \
JAVA_HOME=/home/yasir/Applications/android-studio/jbr ./gradlew testDebugUnitTest --quiet 2>&1 | tail -5
```
Expected: BUILD SUCCESSFUL, all tests pass

- [ ] **Step 5: Commit**

```bash
git add app/src/main/java/com/androdr/network/DnsVpnService.kt
git commit -m "feat: integrate domain IOC resolver and configurable block/detect policy into DnsVpnService"
```

---

## Task 9: SettingsViewModel + SettingsScreen

**Files:**
- Create: `app/src/main/java/com/androdr/ui/settings/SettingsViewModel.kt`
- Create: `app/src/main/java/com/androdr/ui/settings/SettingsScreen.kt`

- [ ] **Step 1: Create `SettingsViewModel.kt`**

```kotlin
package com.androdr.ui.settings

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.androdr.data.repo.SettingsRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import javax.inject.Inject

@HiltViewModel
class SettingsViewModel @Inject constructor(
    private val settingsRepository: SettingsRepository
) : ViewModel() {

    val blocklistBlockMode = settingsRepository.blocklistBlockMode
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), true)

    val domainIocBlockMode = settingsRepository.domainIocBlockMode
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), false)

    fun setBlocklistBlockMode(value: Boolean) {
        viewModelScope.launch { settingsRepository.setBlocklistBlockMode(value) }
    }

    fun setDomainIocBlockMode(value: Boolean) {
        viewModelScope.launch { settingsRepository.setDomainIocBlockMode(value) }
    }
}
```

- [ ] **Step 2: Create `SettingsScreen.kt`**

```kotlin
package com.androdr.ui.settings

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle

@Composable
fun SettingsScreen(viewModel: SettingsViewModel = hiltViewModel()) {
    val blocklistBlockMode by viewModel.blocklistBlockMode.collectAsStateWithLifecycle()
    val domainIocBlockMode by viewModel.domainIocBlockMode.collectAsStateWithLifecycle()

    Scaffold { innerPadding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding)
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            Text(
                text = "Settings",
                style = MaterialTheme.typography.headlineMedium,
                fontWeight = FontWeight.Bold,
                color = MaterialTheme.colorScheme.primary
            )

            Text(
                text = "DNS Blocklist",
                style = MaterialTheme.typography.titleMedium,
                modifier = Modifier.padding(top = 16.dp)
            )
            PolicyToggleRow(
                label = "Block matched domains",
                subtitle = "Off = detect and log only",
                checked = blocklistBlockMode,
                onCheckedChange = { viewModel.setBlocklistBlockMode(it) }
            )
            HorizontalDivider(modifier = Modifier.padding(vertical = 8.dp))

            Text(
                text = "Threat Intelligence Domains (MVT / Pegasus / Predator)",
                style = MaterialTheme.typography.titleMedium
            )
            PolicyToggleRow(
                label = "Block matched domains",
                subtitle = "Off = detect and log only (recommended for EDR)",
                checked = domainIocBlockMode,
                onCheckedChange = { viewModel.setDomainIocBlockMode(it) }
            )
        }
    }
}

@Composable
private fun PolicyToggleRow(
    label: String,
    subtitle: String,
    checked: Boolean,
    onCheckedChange: (Boolean) -> Unit
) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.SpaceBetween
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Text(text = label, style = MaterialTheme.typography.bodyLarge)
            Text(
                text = subtitle,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
        Switch(checked = checked, onCheckedChange = onCheckedChange)
    }
}
```

- [ ] **Step 3: Build check**

```bash
JAVA_HOME=/home/yasir/Applications/android-studio/jbr ./gradlew assembleDebug --quiet
```

- [ ] **Step 4: Commit**

```bash
git add app/src/main/java/com/androdr/ui/settings/SettingsViewModel.kt \
        app/src/main/java/com/androdr/ui/settings/SettingsScreen.kt
git commit -m "feat: add SettingsViewModel and SettingsScreen with DNS policy toggles"
```

---

## Task 10: NetworkScreen quick toggles

**Files:**
- Modify: `app/src/main/java/com/androdr/ui/network/DnsMonitorScreen.kt`

- [ ] **Step 1: Add policy toggles to `DnsMonitorScreen`**

In `DnsMonitorScreen`, add a `SettingsViewModel` parameter and collect its state, then insert two `PolicyToggleRow` composables (or inline Switch rows) above the event list. Add at the top of `DnsMonitorScreen`:

```kotlin
import com.androdr.ui.settings.SettingsViewModel
import androidx.hilt.navigation.compose.hiltViewModel   // already imported

@Composable
fun DnsMonitorScreen(
    viewModel: DnsMonitorViewModel = hiltViewModel(),
    settingsViewModel: SettingsViewModel = hiltViewModel(),
    onRequestVpnPermission: (Intent) -> Unit = {}
) {
    // ... existing state collection ...
    val blocklistBlockMode by settingsViewModel.blocklistBlockMode.collectAsStateWithLifecycle()
    val domainIocBlockMode by settingsViewModel.domainIocBlockMode.collectAsStateWithLifecycle()
```

Add two `Switch` rows inside the `Column`, just above where the event tab/list begins:

```kotlin
// Policy toggles
Card(modifier = Modifier.fillMaxWidth()) {
    Column(modifier = Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Text("DNS Policy", style = MaterialTheme.typography.labelLarge,
            color = MaterialTheme.colorScheme.onSurfaceVariant)
        Row(modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween) {
            Text("Blocklist: Block", style = MaterialTheme.typography.bodyMedium)
            Switch(checked = blocklistBlockMode,
                onCheckedChange = { settingsViewModel.setBlocklistBlockMode(it) })
        }
        Row(modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween) {
            Text("IOC Domains: Block", style = MaterialTheme.typography.bodyMedium)
            Switch(checked = domainIocBlockMode,
                onCheckedChange = { settingsViewModel.setDomainIocBlockMode(it) })
        }
    }
}
```

- [ ] **Step 2: Build check**

```bash
JAVA_HOME=/home/yasir/Applications/android-studio/jbr ./gradlew assembleDebug --quiet
```

- [ ] **Step 3: Commit**

```bash
git add app/src/main/java/com/androdr/ui/network/DnsMonitorScreen.kt
git commit -m "feat: add DNS policy quick-toggles to NetworkScreen"
```

---

## Task 11: DashboardViewModel + DashboardScreen domain IOC state

**Files:**
- Modify: `app/src/main/java/com/androdr/ui/dashboard/DashboardViewModel.kt`
- Modify: `app/src/main/java/com/androdr/ui/dashboard/DashboardScreen.kt`

- [ ] **Step 1: Update `DashboardViewModel.kt`**

Add `DomainIocEntryDao` and `DomainIocUpdater` to the constructor and add domain IOC state flows:

```kotlin
@HiltViewModel
class DashboardViewModel @Inject constructor(
    private val orchestrator: ScanOrchestrator,
    private val repository: ScanRepository,
    private val iocEntryDao: IocEntryDao,
    private val iocDatabase: IocDatabase,
    private val remoteIocUpdater: RemoteIocUpdater,
    private val domainIocEntryDao: DomainIocEntryDao,
    private val domainIocUpdater: DomainIocUpdater
) : ViewModel() {
```

Add alongside the existing IOC state block:

```kotlin
// ── Domain IOC state ──────────────────────────────────────────────────────

private val _domainIocEntryCount = MutableStateFlow(0)
val domainIocEntryCount: StateFlow<Int> = _domainIocEntryCount.asStateFlow()

private val _domainIocLastUpdated = MutableStateFlow<Long?>(null)
val domainIocLastUpdated: StateFlow<Long?> = _domainIocLastUpdated.asStateFlow()

private val _isUpdatingDomainIoc = MutableStateFlow(false)
val isUpdatingDomainIoc: StateFlow<Boolean> = _isUpdatingDomainIoc.asStateFlow()
```

Add `refreshDomainIocState()` and `updateDomainIoc()`:

```kotlin
fun updateDomainIoc() {
    viewModelScope.launch { doUpdateDomain() }
}

@Suppress("TooGenericExceptionCaught")
private suspend fun doUpdateDomain() {
    _isUpdatingDomainIoc.value = true
    try {
        val fetched = domainIocUpdater.update()
        if (fetched == 0) {
            _iocErrorEvent.tryEmit("Failed to update domain threat database. Check your connection.")
        }
        refreshDomainIocState()
    } catch (e: Exception) {
        _iocErrorEvent.tryEmit("Domain threat database update failed: ${e.message}")
    } finally {
        _isUpdatingDomainIoc.value = false
    }
}

private suspend fun refreshDomainIocState() {
    _domainIocEntryCount.value = domainIocEntryDao.count()
    _domainIocLastUpdated.value = domainIocEntryDao.mostRecentFetchTime()
}
```

Also call `refreshDomainIocState()` in the `init` block.

- [ ] **Step 2: Update `ThreatDatabaseCard` in `DashboardScreen.kt`**

Change `ThreatDatabaseCard` signature to accept domain IOC parameters:

```kotlin
ThreatDatabaseCard(
    entryCount = iocEntryCount,
    lastUpdated = iocLastUpdated,
    isUpdating = isUpdatingIoc,
    onUpdateClick = { viewModel.updateIoc() },
    domainEntryCount = domainIocEntryCount,
    domainLastUpdated = domainIocLastUpdated,
    isUpdatingDomain = isUpdatingDomainIoc,
    onUpdateDomainClick = { viewModel.updateDomainIoc() }
)
```

Collect the new state flows at the top of `DashboardScreen`:

```kotlin
val domainIocEntryCount by viewModel.domainIocEntryCount.collectAsStateWithLifecycle()
val domainIocLastUpdated by viewModel.domainIocLastUpdated.collectAsStateWithLifecycle()
val isUpdatingDomainIoc by viewModel.isUpdatingDomainIoc.collectAsStateWithLifecycle()
```

Update `ThreatDatabaseCard` to show two rows. Add the new parameters to the function signature and add a second row below the existing one, reusing `UpdateButtonContent`:

```kotlin
@Composable
private fun ThreatDatabaseCard(
    entryCount: Int, lastUpdated: Long?, isUpdating: Boolean, onUpdateClick: () -> Unit,
    domainEntryCount: Int, domainLastUpdated: Long?, isUpdatingDomain: Boolean,
    onUpdateDomainClick: () -> Unit
) {
    // ... existing card setup ...
    // Row 1 — package IOCs (existing content, unchanged)
    // Row 2 — domain IOCs (new):
    val now = System.currentTimeMillis()
    val isDomainStale = domainLastUpdated != null && (now - domainLastUpdated) > 24 * 60 * 60 * 1000L
    val isDomainNever = domainLastUpdated == null
    val domainStatusText = when {
        isDomainNever -> "$domainEntryCount domain indicators · Remote update pending"
        isDomainStale -> "$domainEntryCount domain indicators · Updated ${relativeTime(domainLastUpdated!!, now)} · Stale"
        else          -> "$domainEntryCount domain indicators · Updated ${relativeTime(domainLastUpdated!!, now)}"
    }
    // Add a second Card row (or HorizontalDivider + Row) inside the Column for domain IOCs
    // with its own update button following the same isFresh/isStale pattern.
}
```

- [ ] **Step 3: Build check + tests**

```bash
JAVA_HOME=/home/yasir/Applications/android-studio/jbr ./gradlew assembleDebug --quiet && \
JAVA_HOME=/home/yasir/Applications/android-studio/jbr ./gradlew testDebugUnitTest --quiet 2>&1 | tail -5
```

- [ ] **Step 4: Commit**

```bash
git add app/src/main/java/com/androdr/ui/dashboard/DashboardViewModel.kt \
        app/src/main/java/com/androdr/ui/dashboard/DashboardScreen.kt
git commit -m "feat: add domain IOC state to DashboardViewModel and split ThreatDatabaseCard into two rows"
```

---

## Task 12: Navigation — Settings destination + gear icon

**Files:**
- Modify: `app/src/main/java/com/androdr/MainActivity.kt`
- Modify: `app/src/main/java/com/androdr/ui/dashboard/DashboardScreen.kt`

- [ ] **Step 1: Add Settings import and composable to `MainActivity.kt`**

Add import:
```kotlin
import com.androdr.ui.settings.SettingsScreen
```

Add to `NavHost` block (after the `"bugreport"` composable):
```kotlin
composable("settings") {
    SettingsScreen()
}
```

- [ ] **Step 2: Add gear icon to DashboardScreen header**

In `DashboardScreen`, add `onNavigate` call to Settings and an `IconButton` in the header `Row`:

```kotlin
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.IconButton

// In the header Row, after the Text composable:
Spacer(modifier = Modifier.weight(1f))
IconButton(onClick = { onNavigate("settings") }) {
    Icon(
        imageVector = Icons.Filled.Settings,
        contentDescription = "Settings",
        tint = MaterialTheme.colorScheme.onSurfaceVariant
    )
}
```

- [ ] **Step 3: Final build check + full test run**

```bash
JAVA_HOME=/home/yasir/Applications/android-studio/jbr ./gradlew assembleDebug --quiet && \
JAVA_HOME=/home/yasir/Applications/android-studio/jbr ./gradlew testDebugUnitTest --quiet 2>&1 | tail -10
```
Expected: BUILD SUCCESSFUL, all tests pass

- [ ] **Step 4: Lint check**

```bash
JAVA_HOME=/home/yasir/Applications/android-studio/jbr ./gradlew lintDebug --quiet 2>&1 | tail -15
```
Expected: No new errors (fix any new warnings as needed)

- [ ] **Step 5: Commit**

```bash
git add app/src/main/java/com/androdr/MainActivity.kt \
        app/src/main/java/com/androdr/ui/dashboard/DashboardScreen.kt
git commit -m "feat: add Settings nav destination and gear icon shortcut from Dashboard"
```

---

## Task 13: Push and verify

- [ ] **Step 1: Run full test suite one last time**

```bash
JAVA_HOME=/home/yasir/Applications/android-studio/jbr ./gradlew testDebugUnitTest 2>&1 | tail -10
```
Expected: BUILD SUCCESSFUL

- [ ] **Step 2: Push**

```bash
git push
```
