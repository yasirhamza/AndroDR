# Cert Hash IOC Matching Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Detect malware by matching the SHA-256 of an installed app's signing certificate against a known-bad cert hash IOC database.

**Architecture:** New `CertHashIocEntry` Room entity + DAO + Resolver + Updater + Feed, following the existing `DomainIocEntry` pattern. `AppScanner` extracts signing cert SHA-256 during its package iteration loop and checks the resolver.

**Tech Stack:** Kotlin, Room (migration 4→5), Hilt DI, kotlinx.serialization, Android PackageInfo.signingInfo

**Spec:** `docs/superpowers/specs/2026-03-26-cert-hash-ioc-design.md`

---

## File Structure

```
# New files
app/src/main/java/com/androdr/data/model/CertHashIocEntry.kt
app/src/main/java/com/androdr/data/db/CertHashIocEntryDao.kt
app/src/main/java/com/androdr/ioc/CertHashIocDatabase.kt
app/src/main/java/com/androdr/ioc/CertHashIocResolver.kt
app/src/main/java/com/androdr/ioc/CertHashIocFeed.kt
app/src/main/java/com/androdr/ioc/CertHashIocUpdater.kt
app/src/main/java/com/androdr/ioc/feeds/MalwareBazaarCertFeed.kt
app/src/main/res/raw/known_bad_certs.json

# New test files
app/src/test/java/com/androdr/ioc/CertHashIocResolverTest.kt

# Modified files
app/src/main/java/com/androdr/data/db/AppDatabase.kt          # add entity + DAO
app/src/main/java/com/androdr/data/db/Migrations.kt            # add MIGRATION_4_5
app/src/main/java/com/androdr/di/AppModule.kt                  # wire new components
app/src/main/java/com/androdr/scanner/AppScanner.kt            # add cert hash check
app/src/main/java/com/androdr/ioc/IocUpdateWorker.kt           # add 4th updater
app/src/main/java/com/androdr/ui/dashboard/DashboardViewModel.kt # cert hash IOC state
test-adversary/run.sh                                          # fix cert seeding table
```

---

### Task 1: CertHashIocEntry + DAO + Migration

**Files:**
- Create: `app/src/main/java/com/androdr/data/model/CertHashIocEntry.kt`
- Create: `app/src/main/java/com/androdr/data/db/CertHashIocEntryDao.kt`
- Modify: `app/src/main/java/com/androdr/data/db/Migrations.kt`
- Modify: `app/src/main/java/com/androdr/data/db/AppDatabase.kt`

- [ ] **Step 1: Create `CertHashIocEntry.kt`**

```kotlin
// app/src/main/java/com/androdr/data/model/CertHashIocEntry.kt
package com.androdr.data.model

import androidx.room.Entity
import androidx.room.PrimaryKey

@Entity(tableName = "cert_hash_ioc_entries")
data class CertHashIocEntry(
    @PrimaryKey val certHash: String,
    val familyName: String,
    val category: String,
    val severity: String,
    val description: String,
    val source: String,
    val fetchedAt: Long
)
```

- [ ] **Step 2: Create `CertHashIocEntryDao.kt`**

```kotlin
// app/src/main/java/com/androdr/data/db/CertHashIocEntryDao.kt
package com.androdr.data.db

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import com.androdr.data.model.CertHashIocEntry

@Dao
interface CertHashIocEntryDao {

    @Query("SELECT * FROM cert_hash_ioc_entries WHERE certHash = :certHash LIMIT 1")
    suspend fun getByCertHash(certHash: String): CertHashIocEntry?

    @Query("SELECT * FROM cert_hash_ioc_entries")
    suspend fun getAll(): List<CertHashIocEntry>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsertAll(entries: List<CertHashIocEntry>)

    @Query("SELECT COUNT(*) FROM cert_hash_ioc_entries")
    suspend fun count(): Int

    @Query("SELECT MAX(fetchedAt) FROM cert_hash_ioc_entries WHERE source = :source")
    suspend fun lastFetchTime(source: String): Long?

    @Query("SELECT MAX(fetchedAt) FROM cert_hash_ioc_entries")
    suspend fun mostRecentFetchTime(): Long?

    @Query("DELETE FROM cert_hash_ioc_entries WHERE source = :source AND fetchedAt < :olderThan")
    suspend fun deleteStaleEntries(source: String, olderThan: Long)
}
```

- [ ] **Step 3: Add `MIGRATION_4_5` to `Migrations.kt`**

Add after `MIGRATION_3_4`:

```kotlin
val MIGRATION_4_5 = object : Migration(4, 5) {
    override fun migrate(database: SupportSQLiteDatabase) {
        database.execSQL(
            """
            CREATE TABLE IF NOT EXISTS cert_hash_ioc_entries (
                certHash    TEXT NOT NULL PRIMARY KEY,
                familyName  TEXT NOT NULL,
                category    TEXT NOT NULL,
                severity    TEXT NOT NULL,
                description TEXT NOT NULL,
                source      TEXT NOT NULL,
                fetchedAt   INTEGER NOT NULL
            )
            """.trimIndent()
        )
    }
}
```

- [ ] **Step 4: Update `AppDatabase.kt`**

Add `CertHashIocEntry` to the entities list, bump version to 5, add abstract DAO method:

```kotlin
// Add import
import com.androdr.data.model.CertHashIocEntry

// Change @Database annotation:
@Database(
    entities = [ScanResult::class, DnsEvent::class, IocEntry::class, DomainIocEntry::class, KnownAppDbEntry::class, CertHashIocEntry::class],
    version = 5,
    exportSchema = false
)

// Add abstract method:
abstract fun certHashIocEntryDao(): CertHashIocEntryDao
```

- [ ] **Step 5: Update `AppModule.kt` — add migration + DAO provider**

Add import and migration:
```kotlin
import com.androdr.data.db.CertHashIocEntryDao
import com.androdr.data.db.MIGRATION_4_5
```

Update `provideDatabase`:
```kotlin
.addMigrations(MIGRATION_1_2, MIGRATION_2_3, MIGRATION_3_4, MIGRATION_4_5)
```

Add DAO provider:
```kotlin
@Provides
fun provideCertHashIocEntryDao(db: AppDatabase): CertHashIocEntryDao = db.certHashIocEntryDao()
```

- [ ] **Step 6: Build**

Run: `export JAVA_HOME=/home/yasir/Applications/android-studio/jbr && ./gradlew assembleDebug`
Expected: BUILD SUCCESSFUL

- [ ] **Step 7: Commit**

```bash
git add app/src/main/java/com/androdr/data/model/CertHashIocEntry.kt \
       app/src/main/java/com/androdr/data/db/CertHashIocEntryDao.kt \
       app/src/main/java/com/androdr/data/db/Migrations.kt \
       app/src/main/java/com/androdr/data/db/AppDatabase.kt \
       app/src/main/java/com/androdr/di/AppModule.kt
git commit -m "feat: add CertHashIocEntry Room entity, DAO, and migration 4→5"
```

---

### Task 2: CertHashIocDatabase (bundled data)

**Files:**
- Create: `app/src/main/res/raw/known_bad_certs.json`
- Create: `app/src/main/java/com/androdr/ioc/CertHashIocDatabase.kt`

- [ ] **Step 1: Create bundled JSON**

Create `app/src/main/res/raw/known_bad_certs.json` with an empty array for now (will be seeded with real cert hashes in Task 8):

```json
[]
```

- [ ] **Step 2: Create `CertHashIocDatabase.kt`**

```kotlin
// app/src/main/java/com/androdr/ioc/CertHashIocDatabase.kt
package com.androdr.ioc

import android.content.Context
import com.androdr.R
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import javax.inject.Inject
import javax.inject.Singleton

@Serializable
data class CertHashInfo(
    val certHash: String,
    val familyName: String,
    val category: String,
    val severity: String,
    val description: String
)

@Singleton
class CertHashIocDatabase @Inject constructor(
    @ApplicationContext private val context: Context
) {
    private val json = Json { ignoreUnknownKeys = true }

    private val certHashList: List<CertHashInfo> by lazy {
        val raw = context.resources
            .openRawResource(R.raw.known_bad_certs)
            .bufferedReader()
            .use { it.readText() }
        json.decodeFromString(raw)
    }

    private val certHashMap: HashMap<String, CertHashInfo> by lazy {
        HashMap<String, CertHashInfo>(certHashList.size * 2).also { map ->
            certHashList.forEach { entry -> map[entry.certHash] = entry }
        }
    }

    fun isKnownBadCert(certHash: String): CertHashInfo? =
        certHashMap[certHash.lowercase()]

    fun getAllBadCerts(): List<CertHashInfo> = certHashList
}
```

- [ ] **Step 3: Build**

Run: `export JAVA_HOME=/home/yasir/Applications/android-studio/jbr && ./gradlew assembleDebug`
Expected: BUILD SUCCESSFUL

- [ ] **Step 4: Commit**

```bash
git add app/src/main/res/raw/known_bad_certs.json \
       app/src/main/java/com/androdr/ioc/CertHashIocDatabase.kt
git commit -m "feat: add CertHashIocDatabase with bundled known-bad cert hashes"
```

---

### Task 3: CertHashIocResolver + tests

**Files:**
- Create: `app/src/main/java/com/androdr/ioc/CertHashIocResolver.kt`
- Create: `app/src/test/java/com/androdr/ioc/CertHashIocResolverTest.kt`

- [ ] **Step 1: Create `CertHashIocResolver.kt`**

```kotlin
// app/src/main/java/com/androdr/ioc/CertHashIocResolver.kt
package com.androdr.ioc

import com.androdr.data.db.CertHashIocEntryDao
import com.androdr.data.model.CertHashIocEntry
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.util.concurrent.atomic.AtomicReference
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class CertHashIocResolver @Inject constructor(
    private val dao: CertHashIocEntryDao,
    private val bundled: CertHashIocDatabase
) {
    private val remoteCache = AtomicReference<Map<String, CertHashIocEntry>?>(null)

    suspend fun refreshCache() = withContext(Dispatchers.IO) {
        val map = buildMap<String, CertHashIocEntry> {
            dao.getAll().forEach { entry -> put(entry.certHash, entry) }
        }
        remoteCache.set(map)
    }

    fun isKnownBadCert(certHash: String): CertHashIocEntry? {
        val normalized = certHash.lowercase()
        val remoteHit = remoteCache.get()?.get(normalized)
        if (remoteHit != null) return remoteHit

        val bundledHit = bundled.isKnownBadCert(normalized) ?: return null
        return CertHashIocEntry(
            certHash = bundledHit.certHash,
            familyName = bundledHit.familyName,
            category = bundledHit.category,
            severity = bundledHit.severity,
            description = bundledHit.description,
            source = "bundled",
            fetchedAt = 0L
        )
    }

    suspend fun remoteEntryCount(): Int = dao.count()
}
```

- [ ] **Step 2: Create `CertHashIocResolverTest.kt`**

```kotlin
// app/src/test/java/com/androdr/ioc/CertHashIocResolverTest.kt
package com.androdr.ioc

import com.androdr.data.db.CertHashIocEntryDao
import com.androdr.data.model.CertHashIocEntry
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Before
import org.junit.Test
import org.mockito.kotlin.mock
import org.mockito.kotlin.whenever

class CertHashIocResolverTest {

    private lateinit var dao: CertHashIocEntryDao
    private lateinit var bundled: CertHashIocDatabase
    private lateinit var resolver: CertHashIocResolver

    private val testEntry = CertHashIocEntry(
        certHash = "abc123def456",
        familyName = "TestMalware",
        category = "RAT",
        severity = "CRITICAL",
        description = "Test malware cert",
        source = "test",
        fetchedAt = 1000L
    )

    @Before
    fun setup() {
        dao = mock()
        bundled = mock()
        resolver = CertHashIocResolver(dao, bundled)
    }

    @Test
    fun `returns null when cache is empty and bundled has no match`() {
        whenever(bundled.isKnownBadCert("unknown")).thenReturn(null)
        assertNull(resolver.isKnownBadCert("unknown"))
    }

    @Test
    fun `returns entry from remote cache after refresh`() = runTest {
        whenever(dao.getAll()).thenReturn(listOf(testEntry))
        resolver.refreshCache()
        val result = resolver.isKnownBadCert("abc123def456")
        assertNotNull(result)
        assertEquals("TestMalware", result!!.familyName)
    }

    @Test
    fun `falls back to bundled when remote cache has no match`() = runTest {
        whenever(dao.getAll()).thenReturn(emptyList())
        resolver.refreshCache()
        val bundledInfo = CertHashInfo(
            certHash = "bundled123",
            familyName = "BundledMalware",
            category = "STALKERWARE",
            severity = "HIGH",
            description = "Bundled cert"
        )
        whenever(bundled.isKnownBadCert("bundled123")).thenReturn(bundledInfo)
        val result = resolver.isKnownBadCert("bundled123")
        assertNotNull(result)
        assertEquals("BundledMalware", result!!.familyName)
    }

    @Test
    fun `normalizes cert hash to lowercase`() = runTest {
        whenever(dao.getAll()).thenReturn(listOf(testEntry))
        resolver.refreshCache()
        val result = resolver.isKnownBadCert("ABC123DEF456")
        assertNotNull(result)
        assertEquals("TestMalware", result!!.familyName)
    }

    @Test
    fun `remoteEntryCount delegates to dao`() = runTest {
        whenever(dao.count()).thenReturn(42)
        assertEquals(42, resolver.remoteEntryCount())
    }
}
```

- [ ] **Step 3: Run tests**

Run: `export JAVA_HOME=/home/yasir/Applications/android-studio/jbr && ./gradlew testDebugUnitTest --tests "com.androdr.ioc.CertHashIocResolverTest"`
Expected: 5 tests PASS

- [ ] **Step 4: Commit**

```bash
git add app/src/main/java/com/androdr/ioc/CertHashIocResolver.kt \
       app/src/test/java/com/androdr/ioc/CertHashIocResolverTest.kt
git commit -m "feat: add CertHashIocResolver with two-tier lookup and tests"
```

---

### Task 4: CertHashIocFeed + CertHashIocUpdater

**Files:**
- Create: `app/src/main/java/com/androdr/ioc/CertHashIocFeed.kt`
- Create: `app/src/main/java/com/androdr/ioc/CertHashIocUpdater.kt`
- Create: `app/src/main/java/com/androdr/ioc/feeds/MalwareBazaarCertFeed.kt`
- Modify: `app/src/main/java/com/androdr/di/AppModule.kt`

- [ ] **Step 1: Create `CertHashIocFeed.kt`**

```kotlin
// app/src/main/java/com/androdr/ioc/CertHashIocFeed.kt
package com.androdr.ioc

import com.androdr.data.model.CertHashIocEntry

interface CertHashIocFeed {
    val sourceId: String
    suspend fun fetch(): List<CertHashIocEntry>
}
```

- [ ] **Step 2: Create `MalwareBazaarCertFeed.kt`**

```kotlin
// app/src/main/java/com/androdr/ioc/feeds/MalwareBazaarCertFeed.kt
package com.androdr.ioc.feeds

import android.util.Log
import com.androdr.data.model.CertHashIocEntry
import com.androdr.ioc.CertHashIocFeed

/**
 * Fetches known-bad Android signing certificate hashes from the MalwareBazaar API.
 *
 * This feed is strictly optional — it returns an empty list if no API key is configured.
 * The bundled known_bad_certs.json provides baseline detection without this feed.
 */
class MalwareBazaarCertFeed : CertHashIocFeed {
    override val sourceId = "malwarebazaar_certs"

    override suspend fun fetch(): List<CertHashIocEntry> {
        // MalwareBazaar cert feed requires an API key.
        // For now, return empty — the bundled JSON provides baseline coverage.
        // Full API integration will query by malware family tag and extract cert hashes.
        Log.d(TAG, "MalwareBazaar cert feed: API integration pending, returning bundled-only")
        return emptyList()
    }

    companion object {
        private const val TAG = "MalwareBazaarCertFeed"
    }
}
```

- [ ] **Step 3: Create `CertHashIocUpdater.kt`**

```kotlin
// app/src/main/java/com/androdr/ioc/CertHashIocUpdater.kt
package com.androdr.ioc

import android.util.Log
import com.androdr.data.db.CertHashIocEntryDao
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.withContext
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class CertHashIocUpdater @Inject constructor(
    private val certHashIocEntryDao: CertHashIocEntryDao,
    private val certHashIocResolver: CertHashIocResolver,
    private val feeds: @JvmSuppressWildcards List<CertHashIocFeed>
) {

    private val updateMutex = Mutex()

    suspend fun update(): Int {
        if (!updateMutex.tryLock()) {
            Log.d(TAG, "Cert hash update already in progress — skipping concurrent call")
            return 0
        }
        return try { doUpdate() } finally { updateMutex.unlock() }
    }

    private suspend fun doUpdate(): Int = withContext(Dispatchers.IO) {
        var totalStored = 0
        coroutineScope {
            val deferreds = feeds.map { feed ->
                async {
                    val entries = feed.fetch()
                    if (entries.isNotEmpty()) {
                        certHashIocEntryDao.upsertAll(entries)
                        val runStart = entries.minOf { it.fetchedAt } - 1
                        certHashIocEntryDao.deleteStaleEntries(feed.sourceId, runStart)
                        Log.i(TAG, "Cert hash feed '${feed.sourceId}': ${entries.size} entries upserted")
                    } else {
                        Log.d(TAG, "Cert hash feed '${feed.sourceId}': no entries returned")
                    }
                    entries.size
                }
            }
            totalStored = deferreds.sumOf { it.await() }
        }
        certHashIocResolver.refreshCache()
        Log.i(TAG, "Cert hash update complete — fetched: $totalStored, DB: ${certHashIocEntryDao.count()}")
        totalStored
    }

    companion object {
        private const val TAG = "CertHashIocUpdater"
    }
}
```

- [ ] **Step 4: Update `AppModule.kt` — add cert hash feed provider**

Add import:
```kotlin
import com.androdr.ioc.CertHashIocFeed
import com.androdr.ioc.feeds.MalwareBazaarCertFeed
```

Add provider:
```kotlin
@Provides
@Singleton
fun provideCertHashIocFeeds(): @JvmSuppressWildcards List<CertHashIocFeed> =
    listOf(MalwareBazaarCertFeed())
```

- [ ] **Step 5: Build**

Run: `export JAVA_HOME=/home/yasir/Applications/android-studio/jbr && ./gradlew assembleDebug`
Expected: BUILD SUCCESSFUL

- [ ] **Step 6: Commit**

```bash
git add app/src/main/java/com/androdr/ioc/CertHashIocFeed.kt \
       app/src/main/java/com/androdr/ioc/CertHashIocUpdater.kt \
       app/src/main/java/com/androdr/ioc/feeds/MalwareBazaarCertFeed.kt \
       app/src/main/java/com/androdr/di/AppModule.kt
git commit -m "feat: add CertHashIocFeed interface, MalwareBazaarCertFeed, and CertHashIocUpdater"
```

---

### Task 5: AppScanner — cert hash extraction + IOC check

**Files:**
- Modify: `app/src/main/java/com/androdr/scanner/AppScanner.kt`

- [ ] **Step 1: Add `CertHashIocResolver` to constructor**

Add import:
```kotlin
import com.androdr.ioc.CertHashIocResolver
import java.security.MessageDigest
```

Change constructor:
```kotlin
@Singleton
class AppScanner @Inject constructor(
    @ApplicationContext private val context: Context,
    private val iocResolver: IocResolver,
    private val knownAppResolver: KnownAppResolver,
    private val certHashIocResolver: CertHashIocResolver
) {
```

- [ ] **Step 2: Update `getInstalledPackages` flags to include signing info**

Replace the existing `getInstalledPackages` call with a fallback pattern:

```kotlin
val signingFlag = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P)
    PackageManager.GET_SIGNING_CERTIFICATES
else
    @Suppress("DEPRECATION") PackageManager.GET_SIGNATURES

@Suppress("TooGenericExceptionCaught", "SwallowedException")
val installedPackages = try {
    pm.getInstalledPackages(PackageManager.GET_PERMISSIONS or signingFlag)
} catch (e: Exception) {
    Log.w(TAG, "AppScanner: getInstalledPackages with signing flag failed, retrying without: ${e.message}")
    try {
        pm.getInstalledPackages(PackageManager.GET_PERMISSIONS)
    } catch (e2: Exception) {
        Log.w(TAG, "AppScanner: getInstalledPackages failed: ${e2.message}")
        emptyList()
    }
}
```

- [ ] **Step 3: Add `extractCertHash` private method**

Add at the bottom of the class (before the closing brace):

```kotlin
private fun extractCertHash(packageInfo: android.content.pm.PackageInfo): String? {
    val signatures = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
        packageInfo.signingInfo?.apkContentsSigners
    } else {
        @Suppress("DEPRECATION")
        packageInfo.signatures
    }
    val cert = signatures?.firstOrNull() ?: return null
    val digest = MessageDigest.getInstance("SHA-256")
    return digest.digest(cert.toByteArray()).joinToString("") { "%02x".format(it) }
}
```

- [ ] **Step 4: Add cert hash IOC check after package name IOC check**

After the closing brace of the existing IOC check block (after `reasons.add("Package name matches...")`), add:

```kotlin
// ── 1b. Cert hash IOC check ─────────────────────────────
@Suppress("TooGenericExceptionCaught", "SwallowedException")
val certHash = try {
    extractCertHash(pkg)
} catch (e: Exception) {
    Log.w(TAG, "AppScanner: cert hash extraction failed for $packageName: ${e.message}")
    null
}
if (certHash != null) {
    val certHit = try {
        certHashIocResolver.isKnownBadCert(certHash)
    } catch (e: Exception) {
        Log.w(TAG, "AppScanner: cert hash IOC lookup failed for $packageName: ${e.message}")
        null
    }
    if (certHit != null) {
        isKnownMalware = true
        val newLevel = RiskLevel.CRITICAL
        if (newLevel.score > riskLevel.score) riskLevel = newLevel
        reasons.add("Known malicious signing certificate (${certHit.familyName})")
    }
}
```

- [ ] **Step 5: Build and run all tests**

Run: `export JAVA_HOME=/home/yasir/Applications/android-studio/jbr && ./gradlew testDebugUnitTest`
Expected: BUILD SUCCESSFUL, all tests pass

- [ ] **Step 6: Commit**

```bash
git add app/src/main/java/com/androdr/scanner/AppScanner.kt
git commit -m "feat: add signing cert hash extraction and IOC check to AppScanner"
```

---

### Task 6: IocUpdateWorker + DashboardViewModel integration

**Files:**
- Modify: `app/src/main/java/com/androdr/ioc/IocUpdateWorker.kt`
- Modify: `app/src/main/java/com/androdr/ui/dashboard/DashboardViewModel.kt`

- [ ] **Step 1: Update `IocUpdateWorker`**

Add `CertHashIocUpdater` to constructor and `runAllUpdaters`:

```kotlin
@HiltWorker
class IocUpdateWorker @AssistedInject constructor(
    @Assisted context: Context,
    @Assisted params: WorkerParameters,
    private val remoteIocUpdater: RemoteIocUpdater,
    private val domainIocUpdater: DomainIocUpdater,
    private val knownAppUpdater: KnownAppUpdater,
    private val certHashIocUpdater: CertHashIocUpdater
) : CoroutineWorker(context, params) {

    @Suppress("TooGenericExceptionCaught")
    override suspend fun doWork(): Result {
        return try {
            val fetched = runAllUpdaters(remoteIocUpdater, domainIocUpdater, knownAppUpdater, certHashIocUpdater)
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
    knownApp: KnownAppUpdater,
    certHashIoc: CertHashIocUpdater
): Int = coroutineScope {
    val a = async { remoteIoc.update() }
    val b = async { domainIoc.update() }
    val c = async { knownApp.update() }
    val d = async { certHashIoc.update() }
    a.await() + b.await() + c.await() + d.await()
}
```

Add import:
```kotlin
import com.androdr.ioc.CertHashIocUpdater
```

- [ ] **Step 2: Update `DashboardViewModel`**

Add `CertHashIocEntryDao` to the constructor. Read the existing constructor parameters first by checking the file. Add alongside existing DAO parameters:

```kotlin
private val certHashIocEntryDao: CertHashIocEntryDao,
```

Add state flows alongside existing IOC state:

```kotlin
private val _certHashIocEntryCount = MutableStateFlow(0)
val certHashIocEntryCount: StateFlow<Int> = _certHashIocEntryCount.asStateFlow()

private val _certHashIocLastUpdated = MutableStateFlow<Long?>(null)
val certHashIocLastUpdated: StateFlow<Long?> = _certHashIocLastUpdated.asStateFlow()
```

Add refresh method:

```kotlin
private suspend fun refreshCertHashIocState() {
    _certHashIocEntryCount.value = certHashIocEntryDao.count()
    _certHashIocLastUpdated.value = certHashIocEntryDao.mostRecentFetchTime()
}
```

Add `refreshCertHashIocState()` call in the `init` block alongside existing refresh calls.

Add import:
```kotlin
import com.androdr.data.db.CertHashIocEntryDao
```

- [ ] **Step 3: Build and run all tests**

Run: `export JAVA_HOME=/home/yasir/Applications/android-studio/jbr && ./gradlew testDebugUnitTest`
Expected: BUILD SUCCESSFUL (IocUpdateWorkerTest may fail — see Step 4)

- [ ] **Step 4: Fix `IocUpdateWorkerTest` if it fails**

The test constructs `runAllUpdaters` with 3 parameters — update it to pass a 4th mock `CertHashIocUpdater`. Find the test file and add the mock:

```kotlin
val certHashIocUpdater: CertHashIocUpdater = mock()
whenever(certHashIocUpdater.update()).thenReturn(0)
```

Update the `runAllUpdaters` call in the test to pass 4 arguments.

- [ ] **Step 5: Run tests again**

Run: `export JAVA_HOME=/home/yasir/Applications/android-studio/jbr && ./gradlew testDebugUnitTest`
Expected: BUILD SUCCESSFUL, all tests pass

- [ ] **Step 6: Commit**

```bash
git add app/src/main/java/com/androdr/ioc/IocUpdateWorker.kt \
       app/src/main/java/com/androdr/ui/dashboard/DashboardViewModel.kt \
       app/src/test/
git commit -m "feat: wire CertHashIocUpdater into IocUpdateWorker and add dashboard cert hash IOC state"
```

---

### Task 7: Seed bundled cert hashes from MalwareBazaar samples

**Files:**
- Modify: `app/src/main/res/raw/known_bad_certs.json`

**Context:** Download the pinned MalwareBazaar samples, extract their signing cert SHA-256 hashes, and populate the bundled JSON.

- [ ] **Step 1: Download and extract cert hashes**

For each pinned sample in `test-adversary/manifest.yml`, download via MalwareBazaar API, extract with 7z, and get the signing cert hash:

```bash
export MALWAREBAZAAR_API_KEY="REDACTED_MALWAREBAZAAR_KEY"
export JAVA_HOME=/home/yasir/Applications/android-studio/jbr
export PATH=$JAVA_HOME/bin:$PATH

for sha in \
  8beae1f6b21cec17eed82fb7af25e1782d5b7bf10fd22369603313f1b1a5e5e4 \
  17372844a0ecb548c70275a5e06f522a2445f2781410a246130757e0b7bc5396 \
  392272ef515d2f60f2c058675d637bf63a265800b8e4613ed9f72eeb8ebb323d \
  f690e30b6ee25c153effc5620fd7ec61481a449a127b54a67c7afc4c13d7917f \
  92c3337b3d74f2aab8f0ca3a6f045719a3301519810d535856ff11dd743b523c \
  4bcb6951c5f78c646c19771ff58c2ea749e734ae3fa916f130aeee8e083ca2e4; do
    curl -s -X POST https://mb-api.abuse.ch/api/v1/ \
      -d "query=get_file&sha256_hash=$sha" \
      -H "Auth-Key: $MALWAREBAZAAR_API_KEY" \
      -o /tmp/mb_$sha.zip
    7z x -pinfected -aoa -o/tmp/mb_extract /tmp/mb_$sha.zip >/dev/null 2>&1
    apk="/tmp/mb_extract/${sha}.apk"
    if [ -f "$apk" ]; then
      cert=$(keytool -printcert -jarfile "$apk" 2>/dev/null | grep SHA256 | head -1 | awk '{print $2}' | tr -d ':' | tr 'A-F' 'a-f')
      echo "$sha -> $cert"
    fi
    rm -rf /tmp/mb_extract /tmp/mb_$sha.zip
done
```

- [ ] **Step 2: Also extract the adversary simulation fixture cert hash**

```bash
cert=$(keytool -printcert -jarfile test-adversary/fixtures/mercenary/cert-hash-ioc.apk 2>/dev/null | grep SHA256 | head -1 | awk '{print $2}' | tr -d ':' | tr 'A-F' 'a-f')
echo "fixture -> $cert"
```

- [ ] **Step 3: Populate `known_bad_certs.json`**

Replace the empty array with the extracted cert hashes. Use the actual values from Steps 1-2. The format is:

```json
[
  {
    "certHash": "<extracted-hash>",
    "familyName": "Cerberus",
    "category": "BANKER",
    "severity": "CRITICAL",
    "description": "Cerberus Android banking trojan signing certificate"
  },
  ...
]
```

Include entries for: Cerberus, SpyNote, Anubis, BRATA, TheTruthSpy, TiSpy, and the adversary test fixture.

- [ ] **Step 4: Build and run tests**

Run: `export JAVA_HOME=/home/yasir/Applications/android-studio/jbr && ./gradlew testDebugUnitTest`
Expected: BUILD SUCCESSFUL

- [ ] **Step 5: Commit**

```bash
git add app/src/main/res/raw/known_bad_certs.json
git commit -m "feat: seed bundled cert hash IOC database from MalwareBazaar samples"
```

---

### Task 8: Update adversary simulation harness

**Files:**
- Modify: `test-adversary/run.sh`

- [ ] **Step 1: Update cert hash seeding in `run.sh`**

Find the `mercenary_cert_hash` seeding block in `run_scenario()` and update to use the new table schema:

Replace the existing seeding block:
```bash
    # Step 5: SEED IOC DB (cert-hash scenario only)
    if [ "$id" = "mercenary_cert_hash" ] && [ -n "$apk_path" ]; then
```

With:
```bash
    # Step 5: SEED IOC DB (cert-hash scenario only)
    if [ "$id" = "mercenary_cert_hash" ] && [ -n "$apk_path" ]; then
        echo "  Seeding cert hash into IOC DB..."
        local cert_hash
        cert_hash=$(keytool -printcert -jarfile "$apk_path" 2>/dev/null | grep "SHA256:" | head -1 | awk '{print $2}' | tr -d ':' | tr 'A-F' 'a-f')
        if [ -n "$cert_hash" ]; then
            local db_path="/data/data/com.androdr.debug/databases/androdr.db"
            $ADB shell "run-as com.androdr.debug sqlite3 $db_path \
                \"INSERT OR REPLACE INTO cert_hash_ioc_entries \
                (certHash, familyName, category, severity, description, source, fetchedAt) \
                VALUES ('$cert_hash', 'Test Fixture', 'TEST', 'CRITICAL', \
                'Adversary simulation test cert', 'adversary-test', $(date +%s000));\"" 2>/dev/null || \
                echo "  WARNING: Could not seed cert hash into DB"
        fi
    fi
```

- [ ] **Step 2: Syntax check**

Run: `bash -n test-adversary/run.sh`
Expected: No output (valid syntax)

- [ ] **Step 3: Commit**

```bash
git add test-adversary/run.sh
git commit -m "fix: update run.sh cert hash seeding to use cert_hash_ioc_entries table"
```

---

### Task 9: Final verification + push

- [ ] **Step 1: Run full unit test suite**

Run: `export JAVA_HOME=/home/yasir/Applications/android-studio/jbr && ./gradlew testDebugUnitTest`
Expected: BUILD SUCCESSFUL, all tests pass

- [ ] **Step 2: Build debug APK**

Run: `export JAVA_HOME=/home/yasir/Applications/android-studio/jbr && ./gradlew assembleDebug`
Expected: BUILD SUCCESSFUL

- [ ] **Step 3: Push**

```bash
git push origin main
```

- [ ] **Step 4: Run adversary simulation to verify `mercenary_cert_hash` passes**

```bash
export JAVA_HOME=/home/yasir/Applications/android-studio/jbr
export ANDROID_HOME=~/Android/Sdk
export PATH=$JAVA_HOME/bin:$ANDROID_HOME/platform-tools:$PATH
export MALWAREBAZAAR_API_KEY="REDACTED_MALWAREBAZAAR_KEY"
./gradlew installDebug
./test-adversary/run.sh --no-pause emulator-5554
```

Expected: `mercenary_cert_hash` transitions from EXPECTED FAIL to PASS. Track 1 commodity malware scenarios (Cerberus, SpyNote, etc.) should also show "Known malicious signing certificate" detection alongside sideload detection.
