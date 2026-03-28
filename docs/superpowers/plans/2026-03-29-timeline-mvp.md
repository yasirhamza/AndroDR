# Forensic Timeline MVP Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a persistent forensic timeline with Room storage, filtering UI, and plaintext/CSV export — covering the stalkerware investigation MVP from the spec (Section 1.4).

**Architecture:** Enhanced `TimelineEvent` Room entity replaces the transient DTO. Event source adapters convert `DnsEvent`, `Finding`, and bugreport results into timeline entries persisted to Room. `TimelineScreen` displays events with severity/source/package filter chips. Export via `TimelineExporter` in plaintext and CSV formats.

**Tech Stack:** Room, Hilt, Jetpack Compose (Material3), kotlinx.serialization, Flow

**Spec:** `docs/superpowers/specs/2026-03-28-timeline-ui-design.md` — Sections 1.4, 2, 3.1, 4, 5.1-5.2

**Scope:** This plan covers Data Layer + UI + Basic Export only. Correlation engine, package lifecycle monitor, deep-links, privacy controls, and STIX2/JSON export are separate plans.

---

## File Structure

### New Files
| File | Responsibility |
|------|---------------|
| `data/model/ForensicTimelineEvent.kt` | Enhanced Room entity with 24 fields |
| `data/db/ForensicTimelineEventDao.kt` | Room DAO with filtered queries |
| `data/db/TimelineAdapter.kt` | Extension functions: DnsEvent/Finding → ForensicTimelineEvent |
| `reporting/TimelineExporter.kt` | Plaintext + CSV export with FileProvider |
| `ui/timeline/TimelineScreen.kt` | Main timeline composable with filter chips |
| `ui/timeline/TimelineViewModel.kt` | ViewModel with filter state + export |
| `ui/timeline/TimelineEventCard.kt` | Event card composable |
| `ui/timeline/TimelineEventDetailSheet.kt` | Bottom sheet for event details |

### Modified Files
| File | Change |
|------|--------|
| `data/db/AppDatabase.kt` | Add ForensicTimelineEvent entity, bump version, add DAO |
| `data/db/Migrations.kt` | Add MIGRATION_6_7 |
| `scanner/ScanOrchestrator.kt` | Persist scan findings as timeline events |
| `scanner/BugReportAnalyzer.kt` | Persist bugreport timeline events |
| `MainActivity.kt` | Add Timeline to bottom nav + NavHost |
| `res/values/strings.xml` | Add timeline string resources |

---

## Task 1: ForensicTimelineEvent Room Entity

**Files:**
- Create: `app/src/main/java/com/androdr/data/model/ForensicTimelineEvent.kt`

- [ ] **Step 1: Create the entity**

```kotlin
package com.androdr.data.model

import androidx.room.Entity
import androidx.room.PrimaryKey

@Entity(tableName = "forensic_timeline")
data class ForensicTimelineEvent(
    @PrimaryKey(autoGenerate = true)
    val id: Long = 0,

    // -- When --
    val timestamp: Long,
    val timestampPrecision: String = "exact",

    // -- What --
    val source: String,
    val category: String,
    val description: String,
    val details: String = "",

    // -- Severity --
    val severity: String,

    // -- Attribution --
    val packageName: String = "",
    val appName: String = "",
    val processUid: Int = -1,

    // -- IOC Context --
    val iocIndicator: String = "",
    val iocType: String = "",
    val iocSource: String = "",
    val campaignName: String = "",

    // -- Linkage --
    val correlationId: String = "",
    val ruleId: String = "",
    val scanResultId: Long = -1,

    // -- MITRE ATT&CK --
    val attackTechniqueId: String = "",

    // -- Metadata --
    val isFromBugreport: Boolean = false,
    val isFromRuntime: Boolean = false,
    val createdAt: Long = System.currentTimeMillis()
)
```

- [ ] **Step 2: Build**

Run: `./gradlew assembleDebug`
Expected: BUILD SUCCESSFUL

- [ ] **Step 3: Commit**

```bash
git add app/src/main/java/com/androdr/data/model/ForensicTimelineEvent.kt
git commit -m "feat: add ForensicTimelineEvent Room entity (#41)"
```

---

## Task 2: ForensicTimelineEventDao

**Files:**
- Create: `app/src/main/java/com/androdr/data/db/ForensicTimelineEventDao.kt`

- [ ] **Step 1: Create the DAO**

```kotlin
package com.androdr.data.db

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import com.androdr.data.model.ForensicTimelineEvent
import kotlinx.coroutines.flow.Flow

@Dao
interface ForensicTimelineEventDao {

    @Query("SELECT * FROM forensic_timeline ORDER BY timestamp DESC LIMIT :limit")
    fun getRecentEvents(limit: Int = 500): Flow<List<ForensicTimelineEvent>>

    @Query("""
        SELECT * FROM forensic_timeline
        WHERE severity IN (:severities)
        ORDER BY timestamp DESC LIMIT :limit
    """)
    fun getEventsBySeverity(
        severities: List<String>,
        limit: Int = 500
    ): Flow<List<ForensicTimelineEvent>>

    @Query("""
        SELECT * FROM forensic_timeline
        WHERE source = :source
        ORDER BY timestamp DESC LIMIT :limit
    """)
    fun getEventsBySource(source: String, limit: Int = 500): Flow<List<ForensicTimelineEvent>>

    @Query("""
        SELECT * FROM forensic_timeline
        WHERE packageName = :packageName
        ORDER BY timestamp DESC
    """)
    fun getEventsByPackage(packageName: String): Flow<List<ForensicTimelineEvent>>

    @Query("SELECT DISTINCT source FROM forensic_timeline ORDER BY source")
    suspend fun getDistinctSources(): List<String>

    @Query("""
        SELECT DISTINCT packageName FROM forensic_timeline
        WHERE packageName != '' ORDER BY packageName
    """)
    suspend fun getDistinctPackages(): List<String>

    @Query("SELECT * FROM forensic_timeline ORDER BY timestamp ASC")
    suspend fun getAllForExport(): List<ForensicTimelineEvent>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertAll(events: List<ForensicTimelineEvent>)

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insert(event: ForensicTimelineEvent)

    @Query("DELETE FROM forensic_timeline WHERE createdAt < :cutoff")
    suspend fun deleteOlderThan(cutoff: Long)

    @Query("SELECT COUNT(*) FROM forensic_timeline")
    suspend fun count(): Int
}
```

- [ ] **Step 2: Build**

Run: `./gradlew assembleDebug`
Expected: BUILD SUCCESSFUL

- [ ] **Step 3: Commit**

```bash
git add app/src/main/java/com/androdr/data/db/ForensicTimelineEventDao.kt
git commit -m "feat: add ForensicTimelineEventDao with filtered queries (#41)"
```

---

## Task 3: Database Migration + Wiring

**Files:**
- Modify: `app/src/main/java/com/androdr/data/db/AppDatabase.kt`
- Modify: `app/src/main/java/com/androdr/data/db/Migrations.kt`
- Modify: `app/src/main/java/com/androdr/di/AppModule.kt` (add DAO provider)

- [ ] **Step 1: Add migration**

In `Migrations.kt`, add after the last migration:

```kotlin
val MIGRATION_6_7 = object : Migration(6, 7) {
    override fun migrate(database: SupportSQLiteDatabase) {
        database.execSQL("""
            CREATE TABLE IF NOT EXISTS forensic_timeline (
                id                  INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
                timestamp           INTEGER NOT NULL,
                timestampPrecision  TEXT NOT NULL DEFAULT 'exact',
                source              TEXT NOT NULL,
                category            TEXT NOT NULL,
                description         TEXT NOT NULL,
                details             TEXT NOT NULL DEFAULT '',
                severity            TEXT NOT NULL,
                packageName         TEXT NOT NULL DEFAULT '',
                appName             TEXT NOT NULL DEFAULT '',
                processUid          INTEGER NOT NULL DEFAULT -1,
                iocIndicator        TEXT NOT NULL DEFAULT '',
                iocType             TEXT NOT NULL DEFAULT '',
                iocSource           TEXT NOT NULL DEFAULT '',
                campaignName        TEXT NOT NULL DEFAULT '',
                correlationId       TEXT NOT NULL DEFAULT '',
                ruleId              TEXT NOT NULL DEFAULT '',
                scanResultId        INTEGER NOT NULL DEFAULT -1,
                attackTechniqueId   TEXT NOT NULL DEFAULT '',
                isFromBugreport     INTEGER NOT NULL DEFAULT 0,
                isFromRuntime       INTEGER NOT NULL DEFAULT 0,
                createdAt           INTEGER NOT NULL
            )
        """.trimIndent())
        database.execSQL(
            "CREATE INDEX IF NOT EXISTS index_forensic_timeline_timestamp ON forensic_timeline(timestamp)"
        )
        database.execSQL(
            "CREATE INDEX IF NOT EXISTS index_forensic_timeline_severity ON forensic_timeline(severity)"
        )
        database.execSQL(
            "CREATE INDEX IF NOT EXISTS index_forensic_timeline_packageName ON forensic_timeline(packageName)"
        )
    }
}
```

- [ ] **Step 2: Update AppDatabase**

In `AppDatabase.kt`:
- Add `ForensicTimelineEvent::class` to the entities array (import `com.androdr.data.model.ForensicTimelineEvent`)
- Change `version = 6` to `version = 7`
- Add `abstract fun forensicTimelineEventDao(): ForensicTimelineEventDao`

- [ ] **Step 3: Wire migration in AppModule**

In `app/src/main/java/com/androdr/di/AppModule.kt`, find where the database is built (look for `Room.databaseBuilder`) and add `.addMigrations(MIGRATION_6_7)`. Also add a `@Provides` for `ForensicTimelineEventDao`:

```kotlin
@Provides
fun provideForensicTimelineEventDao(db: AppDatabase): ForensicTimelineEventDao =
    db.forensicTimelineEventDao()
```

- [ ] **Step 4: Build**

Run: `./gradlew assembleDebug`
Expected: BUILD SUCCESSFUL

- [ ] **Step 5: Commit**

```bash
git add app/src/main/java/com/androdr/data/db/AppDatabase.kt \
       app/src/main/java/com/androdr/data/db/Migrations.kt \
       app/src/main/java/com/androdr/di/AppModule.kt
git commit -m "feat: add forensic_timeline table with migration 6→7 (#41)"
```

---

## Task 4: Event Source Adapters

**Files:**
- Create: `app/src/main/java/com/androdr/data/db/TimelineAdapter.kt`
- Create: `app/src/test/java/com/androdr/data/db/TimelineAdapterTest.kt`

- [ ] **Step 1: Write failing tests**

Create `app/src/test/java/com/androdr/data/db/TimelineAdapterTest.kt`:

```kotlin
package com.androdr.data.db

import com.androdr.data.model.DnsEvent
import com.androdr.data.model.ForensicTimelineEvent
import com.androdr.data.model.ScanResult
import com.androdr.sigma.Evidence
import com.androdr.sigma.Finding
import com.androdr.sigma.FindingCategory
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class TimelineAdapterTest {

    @Test
    fun `DnsEvent with IOC match maps to HIGH timeline event`() {
        val dns = DnsEvent(
            id = 1, timestamp = 1000L, domain = "evil.com",
            appUid = 10100, appName = "SuspectApp",
            isBlocked = true, reason = "IOC: Pegasus C2"
        )
        val event = dns.toForensicTimelineEvent()
        assertEquals("dns_monitor", event.source)
        assertEquals("ioc_match", event.category)
        assertEquals("HIGH", event.severity)
        assertEquals("evil.com", event.iocIndicator)
        assertEquals("domain", event.iocType)
        assertTrue(event.isFromRuntime)
    }

    @Test
    fun `DnsEvent without match maps to INFO timeline event`() {
        val dns = DnsEvent(
            id = 2, timestamp = 2000L, domain = "google.com",
            appUid = 10200, appName = "Chrome",
            isBlocked = false, reason = null
        )
        val event = dns.toForensicTimelineEvent()
        assertEquals("INFO", event.severity)
        assertEquals("", event.iocIndicator)
    }

    @Test
    fun `Finding maps to timeline event with rule and scan context`() {
        val finding = Finding(
            ruleId = "androdr-060",
            title = "Active Accessibility Service",
            description = "com.evil.spy has accessibility enabled",
            level = "high",
            category = FindingCategory.APP_RISK,
            tags = listOf("attack.t1626"),
            matchContext = mapOf("package_name" to "com.evil.spy")
        )
        val scanResult = ScanResult(
            id = 5000L, timestamp = 3000L,
            findings = listOf(finding),
            bugReportFindings = emptyList(),
            riskySideloadCount = 0, knownMalwareCount = 0
        )
        val event = finding.toForensicTimelineEvent(scanResult)
        assertEquals("app_scanner", event.source)
        assertEquals("app_risk", event.category)
        assertEquals("high", event.severity)
        assertEquals("androdr-060", event.ruleId)
        assertEquals(5000L, event.scanResultId)
        assertEquals("com.evil.spy", event.packageName)
        assertTrue(event.isFromRuntime)
    }

    @Test
    fun `bugreport TimelineEvent maps to forensic event`() {
        val legacy = com.androdr.data.model.TimelineEvent(
            timestamp = 4000L, source = "appops",
            category = "permission_use",
            description = "com.spy used CAMERA at 14:30",
            severity = "MEDIUM"
        )
        val event = legacy.toForensicTimelineEvent(scanResultId = 9000L)
        assertEquals("appops", event.source)
        assertEquals("permission_use", event.category)
        assertEquals(9000L, event.scanResultId)
        assertTrue(event.isFromBugreport)
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `./gradlew testDebugUnitTest --tests "com.androdr.data.db.TimelineAdapterTest" 2>&1 | tail -5`
Expected: FAILED (class not found)

- [ ] **Step 3: Implement adapters**

Create `app/src/main/java/com/androdr/data/db/TimelineAdapter.kt`:

```kotlin
package com.androdr.data.db

import com.androdr.data.model.DnsEvent
import com.androdr.data.model.ForensicTimelineEvent
import com.androdr.data.model.ScanResult
import com.androdr.data.model.TimelineEvent
import com.androdr.sigma.Finding
import com.androdr.sigma.FindingCategory

/** Converts a DNS event to a forensic timeline event. */
fun DnsEvent.toForensicTimelineEvent(): ForensicTimelineEvent = ForensicTimelineEvent(
    timestamp = this.timestamp,
    source = "dns_monitor",
    category = if (this.reason != null) "ioc_match" else "dns_query",
    description = "DNS: ${this.domain}" +
        (this.reason?.let { " [MATCHED: $it]" } ?: ""),
    severity = if (this.reason != null) "HIGH" else "INFO",
    packageName = this.appName ?: "",
    processUid = this.appUid,
    iocIndicator = if (this.reason != null) this.domain else "",
    iocType = if (this.reason != null) "domain" else "",
    isFromRuntime = true
)

/** Converts a SIGMA finding from a scan result to a forensic timeline event. */
fun Finding.toForensicTimelineEvent(scanResult: ScanResult): ForensicTimelineEvent =
    ForensicTimelineEvent(
        timestamp = scanResult.timestamp,
        source = "app_scanner",
        category = when (this.category) {
            FindingCategory.APP_RISK -> "app_risk"
            FindingCategory.DEVICE_POSTURE -> "device_posture"
            FindingCategory.NETWORK -> "network_anomaly"
        },
        description = this.title,
        details = this.description,
        severity = this.level,
        packageName = this.matchContext["package_name"] ?: "",
        ruleId = this.ruleId,
        scanResultId = scanResult.id,
        attackTechniqueId = this.tags.firstOrNull { it.startsWith("attack.t") }
            ?.removePrefix("attack.") ?: "",
        isFromRuntime = true
    )

/** Converts a bugreport module TimelineEvent DTO to a forensic timeline event. */
fun TimelineEvent.toForensicTimelineEvent(scanResultId: Long = -1): ForensicTimelineEvent =
    ForensicTimelineEvent(
        timestamp = this.timestamp,
        source = this.source,
        category = this.category,
        description = this.description,
        severity = this.severity,
        scanResultId = scanResultId,
        isFromBugreport = true
    )
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `./gradlew testDebugUnitTest --tests "com.androdr.data.db.TimelineAdapterTest" 2>&1 | tail -5`
Expected: BUILD SUCCESSFUL, all tests pass

- [ ] **Step 5: Commit**

```bash
git add app/src/main/java/com/androdr/data/db/TimelineAdapter.kt \
       app/src/test/java/com/androdr/data/db/TimelineAdapterTest.kt
git commit -m "feat: add event source adapters for forensic timeline (#41)"
```

---

## Task 5: Persist Timeline Events from Scans and Bugreports

**Files:**
- Modify: `app/src/main/java/com/androdr/scanner/ScanOrchestrator.kt`
- Modify: `app/src/main/java/com/androdr/scanner/BugReportAnalyzer.kt`

- [ ] **Step 1: Wire timeline persistence into ScanOrchestrator**

Add `ForensicTimelineEventDao` as a constructor parameter to `ScanOrchestrator`. In `runFullScan()`, after saving the ScanResult, persist findings as timeline events:

```kotlin
// After: runCatching { scanRepository.saveScan(result) }
runCatching {
    val timelineEvents = allFindings
        .filter { it.triggered }
        .map { it.toForensicTimelineEvent(result) }
    forensicTimelineEventDao.insertAll(timelineEvents)
}
```

Import `com.androdr.data.db.toForensicTimelineEvent`.

In `analyzeBugReport()`, after saving the ScanResult, persist both SIGMA findings and bugreport timeline events:

```kotlin
// After: runCatching { scanRepository.saveScan(scanResult) }
runCatching {
    val timelineEvents = mutableListOf<ForensicTimelineEvent>()
    // SIGMA findings
    timelineEvents.addAll(result.findings.filter { it.triggered }
        .map { it.toForensicTimelineEvent(scanResult) })
    // Bugreport module timeline events
    timelineEvents.addAll(result.timeline.map { it.toForensicTimelineEvent(scanResult.id) })
    forensicTimelineEventDao.insertAll(timelineEvents)
}
```

Import `com.androdr.data.model.ForensicTimelineEvent`, `com.androdr.data.db.ForensicTimelineEventDao`, and `com.androdr.data.db.toForensicTimelineEvent`.

- [ ] **Step 2: Build and run tests**

Run: `./gradlew testDebugUnitTest 2>&1 | tail -5`
Expected: BUILD SUCCESSFUL

- [ ] **Step 3: Commit**

```bash
git add app/src/main/java/com/androdr/scanner/ScanOrchestrator.kt \
       app/src/main/java/com/androdr/scanner/BugReportAnalyzer.kt
git commit -m "feat: persist scan and bugreport findings to forensic timeline (#41)"
```

---

## Task 6: TimelineExporter (Plaintext + CSV)

**Files:**
- Create: `app/src/main/java/com/androdr/reporting/TimelineExporter.kt`
- Create: `app/src/test/java/com/androdr/reporting/TimelineExporterTest.kt`

- [ ] **Step 1: Write failing tests**

Create `app/src/test/java/com/androdr/reporting/TimelineExporterTest.kt`:

```kotlin
package com.androdr.reporting

import com.androdr.data.model.ForensicTimelineEvent
import org.junit.Assert.assertTrue
import org.junit.Test

class TimelineExporterTest {

    private val events = listOf(
        ForensicTimelineEvent(
            id = 1, timestamp = 1711900800000, source = "app_scanner",
            category = "ioc_match", description = "IOC: com.evil.spy",
            severity = "CRITICAL", packageName = "com.evil.spy",
            iocIndicator = "com.evil.spy", iocType = "package_name",
            campaignName = "Pegasus", ruleId = "androdr-001",
            isFromRuntime = true
        ),
        ForensicTimelineEvent(
            id = 2, timestamp = 1711900860000, source = "appops",
            category = "permission_use", description = "com.evil.spy used CAMERA",
            severity = "MEDIUM", packageName = "com.evil.spy",
            isFromBugreport = true
        )
    )

    @Test
    fun `plaintext export contains header and events`() {
        val text = TimelineExporter.formatPlaintext(events)
        assertTrue(text.contains("AndroDR Forensic Timeline"))
        assertTrue(text.contains("IOC: com.evil.spy"))
        assertTrue(text.contains("CRITICAL"))
        assertTrue(text.contains("com.evil.spy used CAMERA"))
    }

    @Test
    fun `CSV export has header row and data rows`() {
        val csv = TimelineExporter.formatCsv(events)
        val lines = csv.lines()
        assertTrue(lines[0].contains("timestamp"))
        assertTrue(lines[0].contains("module"))  // MVT-compatible column name
        assertTrue(lines[0].contains("event"))
        assertTrue(lines.size >= 3) // header + 2 data rows
    }

    @Test
    fun `CSV export escapes commas in descriptions`() {
        val eventsWithComma = listOf(
            ForensicTimelineEvent(
                id = 3, timestamp = 1000L, source = "test",
                category = "test", description = "value with, comma",
                severity = "INFO"
            )
        )
        val csv = TimelineExporter.formatCsv(eventsWithComma)
        assertTrue(csv.contains("\"value with, comma\""))
    }

    @Test
    fun `empty events produce valid output`() {
        val text = TimelineExporter.formatPlaintext(emptyList())
        assertTrue(text.contains("No timeline events"))
        val csv = TimelineExporter.formatCsv(emptyList())
        assertTrue(csv.lines().size >= 1) // at least header
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `./gradlew testDebugUnitTest --tests "com.androdr.reporting.TimelineExporterTest" 2>&1 | tail -5`
Expected: FAILED

- [ ] **Step 3: Implement TimelineExporter**

Create `app/src/main/java/com/androdr/reporting/TimelineExporter.kt`:

```kotlin
package com.androdr.reporting

import android.os.Build
import com.androdr.data.model.ForensicTimelineEvent
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

object TimelineExporter {

    private const val RULE = "============================================================"
    private const val THIN = "------------------------------------------------------------"
    private val timestampFmt = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US)
    private val dateFmt = SimpleDateFormat("yyyy-MM-dd", Locale.US)

    fun formatPlaintext(events: List<ForensicTimelineEvent>): String = buildString {
        appendLine(RULE)
        appendLine("  AndroDR Forensic Timeline")
        appendLine("  Generated: ${timestampFmt.format(Date())}")
        appendLine("  Android: ${Build.VERSION.RELEASE} (API ${Build.VERSION.SDK_INT})")
        appendLine("  Device: ${Build.MANUFACTURER} ${Build.MODEL}")
        appendLine("  Events: ${events.size}")
        appendLine(RULE)
        appendLine()

        if (events.isEmpty()) {
            appendLine("  No timeline events recorded.")
            appendLine()
            appendLine(RULE)
            return@buildString
        }

        // Group by date
        val sorted = events.sortedByDescending { it.timestamp }
        var currentDate = ""
        for (event in sorted) {
            val date = if (event.timestamp > 0) dateFmt.format(Date(event.timestamp)) else "Unknown"
            if (date != currentDate) {
                currentDate = date
                appendLine(THIN)
                appendLine("  $date")
                appendLine(THIN)
            }
            val time = if (event.timestamp > 0) {
                SimpleDateFormat("HH:mm:ss", Locale.US).format(Date(event.timestamp))
            } else "??:??:??"
            val sev = event.severity.uppercase().padEnd(8)
            appendLine("  [$sev] $time  ${event.description}")
            if (event.packageName.isNotEmpty()) {
                appendLine("             Package: ${event.packageName}")
            }
            if (event.iocIndicator.isNotEmpty()) {
                appendLine("             IOC: ${event.iocIndicator} (${event.iocType})")
            }
            if (event.campaignName.isNotEmpty()) {
                appendLine("             Campaign: ${event.campaignName}")
            }
            if (event.details.isNotEmpty()) {
                appendLine("             ${event.details}")
            }
        }

        appendLine()
        appendLine(RULE)
        appendLine("  End of timeline \u00b7 AndroDR")
        appendLine(RULE)
    }

    /** MVT-compatible CSV with standard column headers. */
    fun formatCsv(events: List<ForensicTimelineEvent>): String = buildString {
        // Header row (MVT-compatible column names)
        appendLine("timestamp,isodate,module,event,data,package,severity,ioc_indicator,ioc_type,campaign")

        for (event in events.sortedBy { it.timestamp }) {
            val ts = event.timestamp.toString()
            val iso = if (event.timestamp > 0) timestampFmt.format(Date(event.timestamp)) else ""
            val module = csvEscape(event.source)
            val eventType = csvEscape(event.category)
            val data = csvEscape(event.description)
            val pkg = csvEscape(event.packageName)
            val sev = event.severity
            val ioc = csvEscape(event.iocIndicator)
            val iocType = csvEscape(event.iocType)
            val campaign = csvEscape(event.campaignName)
            appendLine("$ts,$iso,$module,$eventType,$data,$pkg,$sev,$ioc,$iocType,$campaign")
        }
    }

    private fun csvEscape(value: String): String =
        if (value.contains(',') || value.contains('"') || value.contains('\n')) {
            "\"${value.replace("\"", "\"\"")}\""
        } else value
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `./gradlew testDebugUnitTest --tests "com.androdr.reporting.TimelineExporterTest" 2>&1 | tail -5`
Expected: BUILD SUCCESSFUL

- [ ] **Step 5: Commit**

```bash
git add app/src/main/java/com/androdr/reporting/TimelineExporter.kt \
       app/src/test/java/com/androdr/reporting/TimelineExporterTest.kt
git commit -m "feat: add TimelineExporter with plaintext and MVT-compatible CSV (#41)"
```

---

## Task 7: TimelineViewModel

**Files:**
- Create: `app/src/main/java/com/androdr/ui/timeline/TimelineViewModel.kt`

- [ ] **Step 1: Create the ViewModel**

```kotlin
package com.androdr.ui.timeline

import android.content.Context
import android.net.Uri
import androidx.core.content.FileProvider
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.androdr.data.db.ForensicTimelineEventDao
import com.androdr.data.model.ForensicTimelineEvent
import com.androdr.reporting.TimelineExporter
import dagger.hilt.android.lifecycle.HiltViewModel
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.flatMapLatest
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import javax.inject.Inject

@HiltViewModel
class TimelineViewModel @Inject constructor(
    @ApplicationContext private val appContext: Context,
    private val dao: ForensicTimelineEventDao
) : ViewModel() {

    // -- Filter state --
    private val _severityFilter = MutableStateFlow<String?>(null) // null = all
    val severityFilter: StateFlow<String?> = _severityFilter.asStateFlow()

    private val _sourceFilter = MutableStateFlow<String?>(null)
    val sourceFilter: StateFlow<String?> = _sourceFilter.asStateFlow()

    private val _packageFilter = MutableStateFlow<String?>(null)
    val packageFilter: StateFlow<String?> = _packageFilter.asStateFlow()

    // -- Reactive events based on current filter --
    @OptIn(ExperimentalCoroutinesApi::class)
    val events: StateFlow<List<ForensicTimelineEvent>> = _severityFilter
        .flatMapLatest { severity ->
            when {
                _packageFilter.value != null -> dao.getEventsByPackage(_packageFilter.value!!)
                _sourceFilter.value != null -> dao.getEventsBySource(_sourceFilter.value!!)
                severity != null -> dao.getEventsBySeverity(listOf(severity))
                else -> dao.getRecentEvents()
            }
        }
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())

    // -- Filter dropdowns --
    private val _availableSources = MutableStateFlow<List<String>>(emptyList())
    val availableSources: StateFlow<List<String>> = _availableSources.asStateFlow()

    private val _availablePackages = MutableStateFlow<List<String>>(emptyList())
    val availablePackages: StateFlow<List<String>> = _availablePackages.asStateFlow()

    // -- Export --
    private val _shareUri = MutableStateFlow<Uri?>(null)
    val shareUri: StateFlow<Uri?> = _shareUri.asStateFlow()

    private val _exporting = MutableStateFlow(false)
    val exporting: StateFlow<Boolean> = _exporting.asStateFlow()

    init {
        viewModelScope.launch {
            _availableSources.value = dao.getDistinctSources()
            _availablePackages.value = dao.getDistinctPackages()
        }
    }

    fun setSeverityFilter(severity: String?) {
        _packageFilter.value = null
        _sourceFilter.value = null
        _severityFilter.value = severity
    }

    fun setSourceFilter(source: String?) {
        _packageFilter.value = null
        _severityFilter.value = null
        _sourceFilter.value = source
    }

    fun setPackageFilter(pkg: String?) {
        _severityFilter.value = null
        _sourceFilter.value = null
        _packageFilter.value = pkg
    }

    fun clearFilters() {
        _severityFilter.value = null
        _sourceFilter.value = null
        _packageFilter.value = null
    }

    fun exportPlaintext() = export("txt") { TimelineExporter.formatPlaintext(it) }
    fun exportCsv() = export("csv") { TimelineExporter.formatCsv(it) }

    private fun export(extension: String, formatter: (List<ForensicTimelineEvent>) -> String) {
        if (_exporting.value) return
        viewModelScope.launch {
            _exporting.value = true
            try {
                val allEvents = withContext(Dispatchers.IO) { dao.getAllForExport() }
                val text = formatter(allEvents)
                _shareUri.value = withContext(Dispatchers.IO) {
                    val reportsDir = File(appContext.cacheDir, "reports").apply { mkdirs() }
                    val ts = SimpleDateFormat("yyyyMMdd_HHmmss", Locale.US).format(Date())
                    val file = File(reportsDir, "androdr_timeline_$ts.$extension")
                    file.writeText(text, Charsets.UTF_8)
                    FileProvider.getUriForFile(
                        appContext, "${appContext.packageName}.fileprovider", file
                    )
                }
            } finally {
                _exporting.value = false
            }
        }
    }

    fun onShareConsumed() { _shareUri.value = null }
}
```

- [ ] **Step 2: Build**

Run: `./gradlew assembleDebug`
Expected: BUILD SUCCESSFUL

- [ ] **Step 3: Commit**

```bash
git add app/src/main/java/com/androdr/ui/timeline/TimelineViewModel.kt
git commit -m "feat: add TimelineViewModel with filter state and export (#41)"
```

---

## Task 8: TimelineEventCard + DetailSheet

**Files:**
- Create: `app/src/main/java/com/androdr/ui/timeline/TimelineEventCard.kt`

- [ ] **Step 1: Create the card and detail sheet composables**

```kotlin
package com.androdr.ui.timeline

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Error
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.SuggestionChip
import androidx.compose.material3.SuggestionChipDefaults
import androidx.compose.material3.Text
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.androdr.data.model.ForensicTimelineEvent
import com.androdr.ui.common.SeverityChip
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

@OptIn(ExperimentalLayoutApi::class)
@Composable
fun TimelineEventCard(
    event: ForensicTimelineEvent,
    onClick: () -> Unit
) {
    val (icon, color) = severityIconAndColor(event.severity)

    Card(
        modifier = Modifier.fillMaxWidth().clickable(onClick = onClick),
        colors = CardDefaults.cardColors(
            containerColor = color.copy(alpha = 0.08f)
        )
    ) {
        Row(
            modifier = Modifier.padding(12.dp),
            horizontalArrangement = Arrangement.spacedBy(10.dp)
        ) {
            Icon(
                imageVector = icon,
                contentDescription = event.severity,
                tint = color,
                modifier = Modifier.size(20.dp)
            )
            Column(
                modifier = Modifier.weight(1f),
                verticalArrangement = Arrangement.spacedBy(4.dp)
            ) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        text = formatTime(event.timestamp),
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    SeverityChip(level = event.severity, active = true)
                }
                Text(
                    text = event.description,
                    style = MaterialTheme.typography.bodySmall,
                    maxLines = 2,
                    overflow = TextOverflow.Ellipsis
                )
                // Context chips
                FlowRow(horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                    if (event.campaignName.isNotEmpty()) {
                        TagChip(event.campaignName, Color(0xFFCF6679))
                    }
                    if (event.iocType.isNotEmpty()) {
                        TagChip(event.iocType, Color(0xFFFF9800))
                    }
                    TagChip(event.source, MaterialTheme.colorScheme.primary)
                }
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun TimelineEventDetailSheet(
    event: ForensicTimelineEvent,
    onDismiss: () -> Unit
) {
    ModalBottomSheet(
        onDismissRequest = onDismiss,
        sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)
    ) {
        Column(
            modifier = Modifier.padding(horizontal = 24.dp, vertical = 16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(event.category, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
                SeverityChip(level = event.severity, active = true)
            }
            Text(
                text = "${formatTime(event.timestamp)}  ${formatDate(event.timestamp)}",
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            HorizontalDivider()

            Section("Description", event.description)
            if (event.details.isNotEmpty()) Section("Details", event.details)
            if (event.packageName.isNotEmpty()) Section("Package", event.packageName)
            if (event.iocIndicator.isNotEmpty()) {
                Section("IOC Match", "${event.iocIndicator} (${event.iocType})")
            }
            if (event.campaignName.isNotEmpty()) Section("Campaign", event.campaignName)
            if (event.ruleId.isNotEmpty()) Section("Rule", event.ruleId)
            if (event.attackTechniqueId.isNotEmpty()) Section("MITRE ATT&CK", event.attackTechniqueId)

            Spacer(modifier = Modifier.height(32.dp))
        }
    }
}

@Composable
private fun Section(label: String, value: String) {
    Column {
        Text(label, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Text(value, style = MaterialTheme.typography.bodyMedium)
    }
}

@Composable
private fun TagChip(text: String, color: Color) {
    SuggestionChip(
        onClick = {},
        label = { Text(text, style = MaterialTheme.typography.labelSmall) },
        colors = SuggestionChipDefaults.suggestionChipColors(
            containerColor = color.copy(alpha = 0.15f),
            labelColor = color
        ),
        modifier = Modifier.height(24.dp)
    )
}

private fun severityIconAndColor(severity: String) = when (severity.uppercase()) {
    "CRITICAL" -> Icons.Filled.Error to Color(0xFFCF6679)
    "HIGH" -> Icons.Filled.Warning to Color(0xFFFF9800)
    "MEDIUM" -> Icons.Filled.Warning to Color(0xFFFFD600)
    else -> Icons.Filled.Info to Color(0xFF00D4AA)
}

private val timeFmt = SimpleDateFormat("HH:mm:ss", Locale.US)
private val dateFmt = SimpleDateFormat("MMM dd, yyyy", Locale.US)
private fun formatTime(ts: Long) = if (ts > 0) timeFmt.format(Date(ts)) else "??:??:??"
private fun formatDate(ts: Long) = if (ts > 0) dateFmt.format(Date(ts)) else "Unknown"
```

- [ ] **Step 2: Build**

Run: `./gradlew assembleDebug`
Expected: BUILD SUCCESSFUL

- [ ] **Step 3: Commit**

```bash
git add app/src/main/java/com/androdr/ui/timeline/TimelineEventCard.kt
git commit -m "feat: add TimelineEventCard and detail bottom sheet (#41)"
```

---

## Task 9: TimelineScreen + Navigation

**Files:**
- Create: `app/src/main/java/com/androdr/ui/timeline/TimelineScreen.kt`
- Modify: `app/src/main/java/com/androdr/MainActivity.kt`
- Modify: `app/src/main/res/values/strings.xml`

- [ ] **Step 1: Add string resources**

In `strings.xml`, add after the navigation labels:

```xml
    <!-- Timeline -->
    <string name="nav_timeline" tools:ignore="UnusedResources">Timeline</string>
    <string name="timeline_empty">No timeline events yet</string>
    <string name="timeline_empty_hint">Run a scan or analyze a bug report to populate the timeline</string>
    <string name="timeline_export_txt">Export Text</string>
    <string name="timeline_export_csv">Export CSV</string>
    <string name="timeline_filter_all">All</string>
```

- [ ] **Step 2: Create TimelineScreen**

Create `app/src/main/java/com/androdr/ui/timeline/TimelineScreen.kt`:

```kotlin
package com.androdr.ui.timeline

import android.content.Intent
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.FilterList
import androidx.compose.material.icons.filled.Share
import androidx.compose.material.icons.filled.Timeline
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.androdr.R
import com.androdr.data.model.ForensicTimelineEvent
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

@Suppress("LongMethod")
@Composable
fun TimelineScreen(
    viewModel: TimelineViewModel = hiltViewModel()
) {
    val events by viewModel.events.collectAsStateWithLifecycle()
    val severityFilter by viewModel.severityFilter.collectAsStateWithLifecycle()
    val sourceFilter by viewModel.sourceFilter.collectAsStateWithLifecycle()
    val packageFilter by viewModel.packageFilter.collectAsStateWithLifecycle()
    val shareUri by viewModel.shareUri.collectAsStateWithLifecycle()
    val exporting by viewModel.exporting.collectAsStateWithLifecycle()

    val context = LocalContext.current
    var showExportMenu by remember { mutableStateOf(false) }
    var selectedEvent by remember { mutableStateOf<ForensicTimelineEvent?>(null) }

    // Launch share intent
    LaunchedEffect(shareUri) {
        shareUri?.let { uri ->
            val intent = Intent(Intent.ACTION_SEND).apply {
                type = "text/plain"
                putExtra(Intent.EXTRA_STREAM, uri)
                putExtra(Intent.EXTRA_SUBJECT, "AndroDR Forensic Timeline")
                addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
            }
            context.startActivity(Intent.createChooser(intent, "Share Timeline"))
            viewModel.onShareConsumed()
        }
    }

    Column(modifier = Modifier.fillMaxSize()) {
        // Top bar
        Row(
            modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 8.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text(
                "Timeline",
                style = MaterialTheme.typography.titleLarge,
                fontWeight = FontWeight.Bold
            )
            Row {
                Box {
                    IconButton(onClick = { showExportMenu = true }, enabled = !exporting) {
                        Icon(Icons.Filled.Share, contentDescription = "Export")
                    }
                    DropdownMenu(expanded = showExportMenu, onDismissRequest = { showExportMenu = false }) {
                        DropdownMenuItem(
                            text = { Text(stringResource(R.string.timeline_export_txt)) },
                            onClick = { viewModel.exportPlaintext(); showExportMenu = false }
                        )
                        DropdownMenuItem(
                            text = { Text(stringResource(R.string.timeline_export_csv)) },
                            onClick = { viewModel.exportCsv(); showExportMenu = false }
                        )
                    }
                }
            }
        }

        // Filter chips
        Row(
            modifier = Modifier.fillMaxWidth().horizontalScroll(rememberScrollState())
                .padding(horizontal = 16.dp, vertical = 4.dp),
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            FilterChip(
                selected = severityFilter == null && sourceFilter == null && packageFilter == null,
                onClick = { viewModel.clearFilters() },
                label = { Text(stringResource(R.string.timeline_filter_all)) }
            )
            listOf("CRITICAL", "HIGH", "MEDIUM").forEach { sev ->
                FilterChip(
                    selected = severityFilter == sev,
                    onClick = { viewModel.setSeverityFilter(if (severityFilter == sev) null else sev) },
                    label = { Text(sev) }
                )
            }
        }

        // Events list
        if (events.isEmpty()) {
            Box(
                modifier = Modifier.fillMaxSize().padding(32.dp),
                contentAlignment = Alignment.Center
            ) {
                Column(horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    Icon(Icons.Filled.Timeline, contentDescription = null, modifier = Modifier.size(64.dp), tint = MaterialTheme.colorScheme.onSurfaceVariant)
                    Text(stringResource(R.string.timeline_empty), style = MaterialTheme.typography.titleMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    Text(stringResource(R.string.timeline_empty_hint), style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
            }
        } else {
            // Group by date
            val grouped = events.groupBy { e ->
                if (e.timestamp > 0) SimpleDateFormat("yyyy-MM-dd", Locale.US).format(Date(e.timestamp))
                else "Unknown"
            }

            LazyColumn(
                modifier = Modifier.fillMaxSize(),
                contentPadding = PaddingValues(horizontal = 16.dp, vertical = 8.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                grouped.forEach { (date, dateEvents) ->
                    item {
                        Text(
                            text = date,
                            style = MaterialTheme.typography.labelLarge,
                            fontWeight = FontWeight.Bold,
                            color = MaterialTheme.colorScheme.primary,
                            modifier = Modifier.padding(top = 8.dp, bottom = 4.dp)
                        )
                    }
                    items(dateEvents) { event ->
                        TimelineEventCard(event = event, onClick = { selectedEvent = event })
                    }
                }
            }
        }
    }

    // Detail sheet
    selectedEvent?.let { event ->
        TimelineEventDetailSheet(event = event, onDismiss = { selectedEvent = null })
    }
}
```

- [ ] **Step 3: Add Timeline to bottom navigation**

In `MainActivity.kt`, add Timeline to `bottomNavDestinations`:

```kotlin
private val bottomNavDestinations = listOf(
    NavDestination("dashboard", "Dashboard", Icons.Filled.Dashboard),
    NavDestination("apps", "Apps", Icons.Outlined.Apps),
    NavDestination("device", "Device", Icons.Filled.PhoneAndroid),
    NavDestination("network", "Network", Icons.Filled.Wifi),
    NavDestination("timeline", "Timeline", Icons.Filled.Timeline),
)
```

Remove `"history"` from bottom nav — it moves to a secondary access point (settings or dashboard). Add the `timeline` composable to NavHost:

```kotlin
composable("timeline") {
    TimelineScreen()
}
```

Add imports for `Icons.Filled.Timeline` and `com.androdr.ui.timeline.TimelineScreen`.

Update the bottom bar visibility check at line 99 to include `"bugreport"` and `"history"`:
```kotlin
val showBottomBar = bottomNavDestinations.any { it.route == currentRoute }
```
(This already excludes non-nav routes — just make sure `history` still has its `composable` entry in NavHost even though it's no longer in bottom nav.)

- [ ] **Step 4: Build**

Run: `./gradlew assembleDebug`
Expected: BUILD SUCCESSFUL

- [ ] **Step 5: Commit**

```bash
git add app/src/main/java/com/androdr/ui/timeline/TimelineScreen.kt \
       app/src/main/java/com/androdr/MainActivity.kt \
       app/src/main/res/values/strings.xml
git commit -m "feat: add TimelineScreen with filter chips, date grouping, and export (#41)"
```

---

## Task 10: Full Test Suite + Integration Verification

- [ ] **Step 1: Run full test suite**

Run: `./gradlew testDebugUnitTest 2>&1 | tail -20`
Expected: BUILD SUCCESSFUL, all tests pass

- [ ] **Step 2: Run lint**

Run: `./gradlew lintDebug 2>&1 | tail -10`
Expected: No new errors

- [ ] **Step 3: Build release**

Run: `./gradlew assembleDebug`
Expected: BUILD SUCCESSFUL

- [ ] **Step 4: Commit any fixes**

```bash
git add -A
git commit -m "fix: resolve lint/test issues from timeline MVP"
```
