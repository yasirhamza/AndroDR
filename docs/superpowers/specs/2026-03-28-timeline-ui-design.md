# Forensic Timeline UI -- Design Spec

## Goal

Build a unified forensic timeline view that aggregates all event sources (bugreport analysis, runtime scans, DNS monitoring, app lifecycle) into a single chronological view with severity filtering, source grouping, correlation highlighting, and multi-format export. The timeline is the primary investigation surface for DFIR analysts using AndroDR on-device.

## Motivation

- AndroDR currently scatters forensic data across four separate screens (Dashboard, Apps, DNS Monitor, Bug Report) with no cross-source correlation
- The existing TimelineEvent model is bugreport-only and lacks fields essential for investigation (package attribution, event linkage, IOC references)
- DFIR analysts investigating stalkerware or nation-state spyware need a single chronological view to identify behavioral patterns across data sources
- MVT's output is a flat CSV timeline -- AndroDR can surpass it with on-device interactive filtering while also exporting MVT-compatible formats
- No mobile forensic tool provides an on-device interactive timeline; this is a differentiated capability

## Non-Goals

- Full disk forensics (requires root or ADB extraction)
- Network packet capture beyond DNS (would require VpnService rewrite)
- Integration with commercial DFIR platforms (Cellebrite, Magnet) beyond standard export formats
- Real-time streaming timeline (events are added on scan/analysis completion, not live)

---

## 1. DFIR Requirements Analysis

### 1.1 What Events Matter Most

From 15 years of mobile compromise investigations, these are the event categories ranked by forensic value. The ranking reflects how frequently each category provides the pivotal evidence in real cases.

**Tier 1 -- Smoking Gun (direct evidence of compromise)**

| Event Type | Why It Matters | Example |
|---|---|---|
| IOC match (package, cert, domain) | Direct indicator of known malware/spyware | com.network.android matches Pegasus IOC |
| Suspicious app install from unknown source | Initial access vector for most stalkerware | Sideloaded app installed outside Play Store |
| Accessibility service abuse | Primary persistence mechanism for stalkerware | Non-system app with AccessibilityService enabled |
| Device admin abuse | Prevents uninstall, enables wipe | Unknown app registered as device administrator |
| C2 domain resolution | Active command-and-control communication | DNS query to cdn-edge.net (known Predator C2) |

**Tier 2 -- Strong Signal (behavioral indicators)**

| Event Type | Why It Matters | Example |
|---|---|---|
| Surveillance permission use (CAMERA, RECORD_AUDIO, READ_SMS) | Active data collection | com.helper.service accessed CAMERA at 03:14 |
| Abnormal wakelock pattern | Persistent background surveillance | 47 wakelock acquisitions in 200 lines |
| Crash loop | Aggressive respawn after kill attempt | Process crashed 8 times in logcat |
| Base64 data blob in logs | Data exfiltration payload | 2048-char base64 blob in process output |

**Tier 3 -- Contextual (support correlation)**

| Event Type | Why It Matters | Example |
|---|---|---|
| Device posture change | Weakened security enables exploitation | ADB enabled, bootloader unlocked |
| App update/uninstall | Covers tracks or delivers payload update | App uninstalled minutes after data access |
| DNS resolution (benign) | Establishes baseline communication patterns | Normal app DNS traffic for comparison |
| Scan result change | Tracks security posture over time | New finding appeared since last scan |

### 1.2 Organization Strategy

A forensic timeline must support multiple views because different investigation phases require different perspectives:

1. **Chronological (default)** -- What happened and when. Primary view for establishing sequence of events. Critical for answering "was the phone compromised before or after the trip?"
2. **Severity-filtered** -- Show only HIGH/CRITICAL. The analyst's triage view: "show me what needs attention right now."
3. **Source-grouped** -- Group by data source (appops, dns, bugreport, scan). Useful for deep-dive into one artifact type.
4. **Package-focused** -- Filter to one package name. The key question: "show me everything this app did."
5. **Correlation clusters** -- Auto-grouped events that are temporally or logically related. "This app was installed, then accessed the camera, then resolved a known C2 domain -- all within 10 minutes."

### 1.3 Correlation Highlighting

The following correlations should be visually highlighted when detected:

| Correlation Pattern | Detection Logic | Visual Treatment |
|---|---|---|
| Install-then-permission-use | App installed (timeline) + permission use (appops) within 1 hour, same package | Linked with vertical connector line |
| Permission-use-then-C2 | Surveillance permission used + IOC domain resolved, same package, within 30 min | Red cluster box |
| Multi-permission burst | Same package uses 3+ surveillance permissions within 5 minutes | Orange cluster box |
| Install-from-unknown-then-admin | Sideloaded app install + device admin registration, same package | Red cluster box |

### 1.4 Minimum Viable Timeline: Stalkerware Investigation

A stalkerware investigation requires answering: "Is someone monitoring this phone, and since when?"

**Required events (MVP):**
- App installs from unknown sources (with timestamp, installer package)
- Accessibility service registrations by non-system apps
- Device admin registrations by non-system apps
- Surveillance permission usage (CAMERA, RECORD_AUDIO, READ_SMS, READ_CONTACTS, ACCESS_FINE_LOCATION)
- DNS queries matching known stalkerware C2 domains
- Crash loops (stalkerware often crashes and restarts aggressively)

**Required filters:**
- Filter by severity >= MEDIUM
- Filter by package name
- Date range selection

**Required export:**
- Plaintext report (for victim advocacy organizations)
- CSV (for law enforcement)

### 1.5 Minimum Viable Timeline: Nation-State Spyware Investigation

A nation-state investigation requires answering: "Was this device targeted with zero-click or one-click exploits, and what data was accessed?"

**Required events (all stalkerware events plus):**
- Unpatched CVE exposure (especially CVEs linked to known campaigns: Pegasus, Predator, Graphite)
- IOC matches across all types (package name, cert hash, domain)
- Wakelock anomalies (Pegasus-class implants maintain persistent wakelocks)
- Base64 data blobs in process output (exfiltration indicators)
- C2 beacon patterns in logcat
- Process anomalies from bugreport analysis

**Required filters:**
- Filter by MITRE ATT&CK tags
- Filter by spyware campaign name (Pegasus, Predator, Graphite)
- Filter by IOC source (AmnestyTech, CitizenLab, abuse.ch)

**Required export:**
- STIX 2.1 bundle (for threat intelligence sharing with Amnesty, Citizen Lab)
- CSV with MVT-compatible column headers
- JSON (for programmatic analysis)

---

## 2. Enhanced Data Model

### 2.1 Extended TimelineEvent

The current TimelineEvent is too sparse for forensic use. The enhanced model adds attribution, linkage, and IOC context while remaining backward-compatible.

```kotlin
@Entity
@Serializable
data class TimelineEvent(
    @PrimaryKey(autoGenerate = true)
    val id: Long = 0,

    // -- When --
    val timestamp: Long,           // epoch millis, -1 if undetermined
    val timestampEnd: Long = -1,   // for duration events (e.g., wakelock held)
    val timestampPrecision: String = "exact",  // "exact", "approximate", "date_only", "undetermined"

    // -- What --
    val source: String,            // "appops", "battery_daily", "dns_monitor", "app_scanner",
                                   // "device_auditor", "bugreport_legacy", "user_action"
    val category: String,          // "permission_use", "package_install", "ioc_match",
                                   // "device_posture", "dns_query", "process_anomaly",
                                   // "data_exfiltration", "persistence_mechanism"
    val description: String,       // human-readable one-line summary
    val details: String = "",      // extended detail (log line, raw evidence)

    // -- Severity --
    val severity: String,          // INFO, MEDIUM, HIGH, CRITICAL

    // -- Attribution --
    val packageName: String = "",  // Android package name (empty if not app-specific)
    val appName: String = "",      // human-readable app name
    val processUid: Int = -1,      // UID of the process, -1 if unknown

    // -- IOC Context --
    val iocIndicator: String = "", // matched IOC value (domain, hash, package name)
    val iocType: String = "",      // "domain", "package_name", "cert_hash", "ip"
    val iocSource: String = "",    // "amnesty", "citizenlab", "abusech", "stalkerware-indicators"
    val campaignName: String = "", // "Pegasus", "Predator", "Graphite", ""

    // -- Linkage --
    val correlationId: String = "",  // shared ID for correlated events (UUID)
    val ruleId: String = "",         // SIGMA rule ID that generated this event
    val scanResultId: Long = -1,     // FK to ScanResult.id, -1 if from bugreport

    // -- MITRE ATT&CK --
    val attackTacticId: String = "",    // e.g., "TA0003" (Persistence)
    val attackTechniqueId: String = "", // e.g., "T1626.001" (Abuse Elevation Control)

    // -- Metadata --
    val isFromBugreport: Boolean = false,  // true if extracted from bugreport analysis
    val isFromRuntime: Boolean = false,    // true if from live runtime scan
    val createdAt: Long = System.currentTimeMillis()  // when AndroDR recorded this event
)
```

### 2.2 Room DAO

```kotlin
@Dao
interface TimelineEventDao {

    // -- Chronological queries --

    @Query("SELECT * FROM TimelineEvent ORDER BY timestamp DESC LIMIT :limit")
    fun getRecentEvents(limit: Int = 500): Flow<List<TimelineEvent>>

    @Query("""
        SELECT * FROM TimelineEvent
        WHERE timestamp BETWEEN :startMs AND :endMs
        ORDER BY timestamp ASC
    """)
    fun getEventsInRange(startMs: Long, endMs: Long): Flow<List<TimelineEvent>>

    // -- Severity filtering --

    @Query("""
        SELECT * FROM TimelineEvent
        WHERE severity IN (:severities)
        ORDER BY timestamp DESC
        LIMIT :limit
    """)
    fun getEventsBySeverity(
        severities: List<String>,
        limit: Int = 500
    ): Flow<List<TimelineEvent>>

    // -- Source filtering --

    @Query("""
        SELECT * FROM TimelineEvent
        WHERE source = :source
        ORDER BY timestamp DESC
        LIMIT :limit
    """)
    fun getEventsBySource(source: String, limit: Int = 500): Flow<List<TimelineEvent>>

    // -- Package filtering --

    @Query("""
        SELECT * FROM TimelineEvent
        WHERE packageName = :packageName
        ORDER BY timestamp DESC
    """)
    fun getEventsByPackage(packageName: String): Flow<List<TimelineEvent>>

    // -- IOC events only --

    @Query("""
        SELECT * FROM TimelineEvent
        WHERE iocIndicator != ''
        ORDER BY timestamp DESC
    """)
    fun getIocEvents(): Flow<List<TimelineEvent>>

    // -- Campaign-specific --

    @Query("""
        SELECT * FROM TimelineEvent
        WHERE campaignName = :campaign
        ORDER BY timestamp DESC
    """)
    fun getEventsByCampaign(campaign: String): Flow<List<TimelineEvent>>

    // -- Correlation --

    @Query("""
        SELECT * FROM TimelineEvent
        WHERE correlationId = :correlationId
        ORDER BY timestamp ASC
    """)
    fun getCorrelatedEvents(correlationId: String): Flow<List<TimelineEvent>>

    // -- Distinct values for filter dropdowns --

    @Query("SELECT DISTINCT source FROM TimelineEvent ORDER BY source")
    suspend fun getDistinctSources(): List<String>

    @Query("SELECT DISTINCT packageName FROM TimelineEvent WHERE packageName != '' ORDER BY packageName")
    suspend fun getDistinctPackages(): List<String>

    @Query("SELECT DISTINCT campaignName FROM TimelineEvent WHERE campaignName != '' ORDER BY campaignName")
    suspend fun getDistinctCampaigns(): List<String>

    // -- Export snapshot (non-Flow) --

    @Query("SELECT * FROM TimelineEvent ORDER BY timestamp ASC")
    suspend fun getAllForExport(): List<TimelineEvent>

    @Query("""
        SELECT * FROM TimelineEvent
        WHERE severity IN (:severities)
        ORDER BY timestamp ASC
    """)
    suspend fun getFilteredForExport(severities: List<String>): List<TimelineEvent>

    // -- Write operations --

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertAll(events: List<TimelineEvent>)

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insert(event: TimelineEvent)

    @Query("DELETE FROM TimelineEvent WHERE createdAt < :cutoff")
    suspend fun deleteOlderThan(cutoff: Long)

    @Query("DELETE FROM TimelineEvent WHERE scanResultId = :scanId")
    suspend fun deleteForScan(scanId: Long)

    @Query("SELECT COUNT(*) FROM TimelineEvent")
    suspend fun count(): Int
}
```

### 2.3 Backward Compatibility

The existing TimelineEvent data class (used by bugreport modules) maps to the enhanced model:

```kotlin
// In BugReportAnalyzer.processModuleResult():
fun legacyToEnhanced(legacy: TimelineEvent, scanId: Long): EnhancedTimelineEvent {
    return EnhancedTimelineEvent(
        timestamp = legacy.timestamp,
        source = legacy.source,
        category = legacy.category,
        description = legacy.description,
        severity = legacy.severity,
        isFromBugreport = true,
        scanResultId = scanId
    )
}
```

The existing TimelineEvent data class in data/model/ will be renamed to LegacyTimelineEvent and kept as a transient DTO for bugreport module output. The Room entity becomes the enhanced version.

### 2.4 Event Source Adapters

Each existing data source produces TimelineEvent entries through an adapter:

**DNS Events -> Timeline:**
```kotlin
fun DnsEvent.toTimelineEvent(): TimelineEvent = TimelineEvent(
    timestamp = this.timestamp,
    source = "dns_monitor",
    category = if (this.reason != null) "ioc_match" else "dns_query",
    description = "DNS query: ${this.domain}" +
        (this.reason?.let { " [MATCHED: $it]" } ?: ""),
    severity = if (this.reason != null) "HIGH" else "INFO",
    packageName = this.appName ?: "",
    processUid = this.appUid,
    iocIndicator = if (this.reason != null) this.domain else "",
    iocType = if (this.reason != null) "domain" else "",
    isFromRuntime = true
)
```

**ScanResult Findings -> Timeline:**
```kotlin
fun Finding.toTimelineEvent(scanResult: ScanResult): TimelineEvent = TimelineEvent(
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
    ruleId = this.ruleId,
    scanResultId = scanResult.id,
    isFromRuntime = true
)
```

---

## 3. Timeline Data Sources

### 3.1 Currently Available Sources

| Source | Data Type | Already Collected | Storage |
|---|---|---|---|
| appops | Permission usage from bugreport | Yes (AppOpsModule) | Transient (bugreport analysis) |
| bugreport_legacy | Spyware keywords, base64, C2, crashes, wakelocks | Yes (LegacyScanModule) | Transient |
| accessibility | Accessibility service registration | Yes (AccessibilityModule) | Transient |
| receivers | Broadcast receiver registration | Yes (ReceiverModule) | Transient |
| dns_monitor | DNS queries + IOC matches | Yes (VPN service) | Room (DnsEvent) |
| app_scanner | App risk findings | Yes (ScanOrchestrator) | Room (ScanResult) |
| device_auditor | Device posture checks | Yes (ScanOrchestrator) | Room (ScanResult) |

### 3.2 Additional Sources to Implement

These sources are available on Android without root and provide high forensic value:

**Tier 1 -- High value, implement in MVP:**

| Source | API | Events Produced | Forensic Value |
|---|---|---|---|
| Package install/uninstall | PackageManager + ACTION_PACKAGE_ADDED/REMOVED BroadcastReceiver | App installed, app uninstalled, app updated | Establishes initial access timeline |
| Usage stats | UsageStatsManager.queryEvents() (requires PACKAGE_USAGE_STATS permission) | App foreground/background transitions with timestamps | Correlates app activity with permission use |
| Notification listener | NotificationListenerService (requires user grant) | App posted notification (package, timestamp, channel) | Detects stalkerware notification suppression |

**Tier 2 -- Medium value, implement post-MVP:**

| Source | API | Events Produced | Forensic Value |
|---|---|---|---|
| Battery stats | BatteryManager + ACTION_BATTERY_CHANGED | Battery drain events, charging state | Abnormal drain = background surveillance |
| Network stats | NetworkStatsManager.queryDetailsForUid() | Data usage per UID per time bucket | Exfiltration volume detection |
| Job scheduler audit | JobScheduler.getAllPendingJobs() | Scheduled jobs by package | Persistence mechanism detection |
| Settings changes | Settings.Secure/Global polling | ADB state, developer options, unknown sources | Security posture regression detection |

**Tier 3 -- Lower value or higher implementation cost:**

| Source | API | Events Produced | Forensic Value |
|---|---|---|---|
| Account manager | AccountManager.getAccounts() | Account additions/removals | Social engineering indicator |
| Content provider queries | ContentResolver (if apps expose data) | Data access by third-party apps | Data harvesting indicator |
| Logcat (own PID) | Runtime.getRuntime().exec("logcat --pid=...") | AndroDR's own log lines | Debugging + audit trail |

### 3.3 Package Lifecycle Monitor (Tier 1 Implementation)

```kotlin
/**
 * BroadcastReceiver that captures package install/uninstall/update events
 * and writes them to the timeline database.
 *
 * Registered in AndroidManifest.xml with intent filters:
 *   ACTION_PACKAGE_ADDED, ACTION_PACKAGE_REMOVED,
 *   ACTION_PACKAGE_REPLACED, ACTION_PACKAGE_FULLY_REMOVED
 */
@AndroidEntryPoint
class PackageLifecycleReceiver : BroadcastReceiver() {

    @Inject lateinit var timelineEventDao: TimelineEventDao

    override fun onReceive(context: Context, intent: Intent) {
        val packageName = intent.data?.schemeSpecificPart ?: return
        val isReplacing = intent.getBooleanExtra(Intent.EXTRA_REPLACING, false)

        val (category, description, severity) = when (intent.action) {
            Intent.ACTION_PACKAGE_ADDED -> {
                if (isReplacing) {
                    Triple("package_update", "App updated: $packageName", "INFO")
                } else {
                    val installer = context.packageManager
                        .getInstallSourceInfo(packageName)
                        .installingPackageName
                    val isSideloaded = installer == null ||
                        installer == "com.android.shell" ||
                        installer == "com.google.android.packageinstaller"
                    Triple(
                        "package_install",
                        "App installed: $packageName" +
                            " (installer: ${installer ?: "unknown"})" +
                            if (isSideloaded) " [SIDELOADED]" else "",
                        if (isSideloaded) "HIGH" else "INFO"
                    )
                }
            }
            Intent.ACTION_PACKAGE_FULLY_REMOVED -> {
                Triple("package_uninstall", "App uninstalled: $packageName", "INFO")
            }
            else -> return
        }

        val event = TimelineEvent(
            timestamp = System.currentTimeMillis(),
            source = "package_monitor",
            category = category,
            description = description,
            severity = severity,
            packageName = packageName,
            isFromRuntime = true
        )

        // Insert on IO dispatcher (BroadcastReceiver has ~10s limit)
        CoroutineScope(Dispatchers.IO).launch {
            timelineEventDao.insert(event)
        }
    }
}
```

---

## 4. UI Design

### 4.1 Design Principles for Mobile Forensic Timelines

Traditional forensic timelines (Plaso/log2timeline, Cellebrite PA) are designed for 27-inch monitors with 100+ columns. A phone screen is ~6 inches with room for maybe 3-4 columns. The design must:

1. **Prioritize vertical scanning** -- Analysts scan downward through time. Each event must be readable in a single glance without horizontal scrolling.
2. **Use color as the primary severity signal** -- Faster than reading text labels.
3. **Support "thumb-driven" filtering** -- Filter chips at the top, reachable with one thumb.
4. **Show density indicators** -- A cluster of 20 events in 5 minutes is more suspicious than 20 events over 24 hours. Visual density matters.
5. **Enable progressive disclosure** -- Summary visible in the list, details on tap.

### 4.2 Screen Layout

```
+--------------------------------------------------+
|  [<] Timeline                    [Export] [Filter] |
+--------------------------------------------------+
|                                                    |
|  +-filter chip row (horizontally scrollable)-----+ |
|  | [ALL] [CRITICAL] [HIGH] [MEDIUM]  [dns_monitor]| |
|  | [appops] [app_scanner] [com.suspect.app]       | |
|  +-----------------------------------------------+ |
|                                                    |
|  Date header: "2026-03-27"                         |
|  ------------------------------------------------ |
|                                                    |
|  +-- Event Card (CRITICAL) ---------------------+ |
|  | [!] 14:32:05  IOC Match                       | |
|  |     com.network.android matches Pegasus IOC   | |
|  |     [Pegasus] [package_name] [amnesty]        | |
|  |                                    [CRITICAL] | |
|  +----------------------------------------------+ |
|                                                    |
|  +-- Correlation Cluster (red border) ----------+ |
|  | [~] Correlated events (3)          14:30-14:35| |
|  |                                               | |
|  | | 14:30:12  App installed: com.network.android| |
|  | |           Sideloaded from unknown source    | |
|  | |                                      [HIGH] | |
|  | |                                             | |
|  | | 14:31:45  com.network.android used CAMERA   | |
|  | |           at 14:31                          | |
|  | |                                    [MEDIUM] | |
|  | |                                             | |
|  | | 14:32:05  IOC Match: Pegasus domain         | |
|  | |           cdn-edge.net resolved             | |
|  | |                                  [CRITICAL] | |
|  +----------------------------------------------+ |
|                                                    |
|  +-- Event Card (INFO) -------------------------+ |
|  | [i] 14:28:33  DNS Query                       | |
|  |     google.com resolved (Chrome)              | |
|  |                                       [INFO]  | |
|  +----------------------------------------------+ |
|                                                    |
|  Date header: "2026-03-26"                         |
|  ------------------------------------------------ |
|                                                    |
|  +-- Event Card (HIGH) -------------------------+ |
|  | [!] 09:15:22  Device Posture                  | |
|  |     ADB debugging enabled                    | |
|  |                                       [HIGH]  | |
|  +----------------------------------------------+ |
|                                                    |
|  ... (scrollable)                                  |
+--------------------------------------------------+
|  [Dashboard] [Apps] [Device] [DNS] [Timeline]     |
+--------------------------------------------------+
```

### 4.3 Event Card Component

Each timeline event renders as a card with consistent structure:

```
+-- TimelineEventCard --------------------------------+
|                                                      |
|  [severity_icon]  HH:MM:SS   category_label         |
|                                                      |
|  description text (1-2 lines, ellipsized)            |
|                                                      |
|  [tag_chip] [tag_chip] [tag_chip]    [SEVERITY_CHIP] |
|                                                      |
+------------------------------------------------------+
```

**Color coding (reuses existing severity palette from SeverityChip.kt):**

| Severity | Icon | Background | Text Color | Hex |
|---|---|---|---|---|
| CRITICAL | Icons.Filled.Error | #CF6679 at 8% | #CF6679 | Existing ErrorColor |
| HIGH | Icons.Filled.Warning | #FF9800 at 8% | #FF9800 | Orange |
| MEDIUM | Icons.Filled.Warning | #FFD600 at 8% | #FFD600 | Yellow |
| INFO | Icons.Filled.Info | surfaceContainerHigh | #00D4AA | TealPrimary |

**Tag chips** appear contextually:
- Campaign name chip (red background): [Pegasus], [Predator]
- IOC type chip (orange background): [domain], [cert_hash], [package_name]
- IOC source chip (gray background): [amnesty], [citizenlab]
- MITRE ATT&CK chip (blue/tertiary background): [T1626.001]
- Source chip (teal background): [appops], [dns_monitor]

### 4.4 Event Detail Bottom Sheet

Tapping an event card opens a ModalBottomSheet (consistent with EvidenceSheet and ScanReportBottomSheet patterns already in the codebase):

```
+-- TimelineEventDetailSheet -------------------------+
|                                                      |
|  category_label                       [SEVERITY_CHIP]|
|  HH:MM:SS  MMM dd, yyyy                             |
|  -------------------------------------------------- |
|                                                      |
|  Description                                         |
|  Full description text without truncation.           |
|                                                      |
|  Details                                             |
|  Extended evidence / raw log line in monospace font.  |
|                                                      |
|  Attribution                                         |
|  Package: com.suspect.app                            |
|  App Name: Suspect Helper                            |
|  UID: 10145                                          |
|                                                      |
|  IOC Match                                           |
|  Indicator: cdn-edge.net                             |
|  Type: domain                                        |
|  Source: amnesty                                      |
|  Campaign: Pegasus                                   |
|                                                      |
|  MITRE ATT&CK                                       |
|  Tactic: TA0011 (Command and Control)                |
|  Technique: T1071.001 (Web Protocols)                |
|                                                      |
|  Related Events (3)                                  |
|  > App installed: com.suspect.app (14:30:12)         |
|  > CAMERA access by com.suspect.app (14:31:45)       |
|  > IOC Match: cdn-edge.net (14:32:05)                |
|                                                      |
|  -------------------------------------------------- |
|  [Copy Event]                    [Share Event]       |
|  [Dismiss]                                           |
+------------------------------------------------------+
```

### 4.5 Correlation Cluster Rendering

When the correlation engine groups events (shared correlationId), they render as a visually distinct cluster:

```kotlin
@Composable
fun CorrelationCluster(
    events: List<TimelineEvent>,
    onEventTap: (TimelineEvent) -> Unit
) {
    val maxSeverity = events.maxOf { severityOrdinal(it.severity) }
    val clusterColor = severityColor(ordinalToLevel(maxSeverity))
    val timeRange = formatTimeRange(events.first().timestamp, events.last().timestamp)

    Card(
        modifier = Modifier.fillMaxWidth(),
        border = BorderStroke(2.dp, clusterColor.copy(alpha = 0.5f)),
        colors = CardDefaults.cardColors(
            containerColor = clusterColor.copy(alpha = 0.04f)
        )
    ) {
        Column(modifier = Modifier.padding(12.dp)) {
            // Cluster header
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Text("Correlated events (${events.size})")
                Text(timeRange, style = labelSmall)
            }
            Spacer(height = 8.dp)
            // Vertical connector line with embedded event summaries
            events.forEach { event ->
                CorrelatedEventRow(event, onTap = { onEventTap(event) })
            }
        }
    }
}
```

### 4.6 Filter Bar

Horizontal scrollable row of FilterChip composables, consistent with Material 3:

```kotlin
data class TimelineFilter(
    val severities: Set<String> = setOf("CRITICAL", "HIGH", "MEDIUM", "INFO"),
    val sources: Set<String> = emptySet(),    // empty = all
    val packageName: String? = null,           // null = all
    val campaign: String? = null,              // null = all
    val dateRange: Pair<Long, Long>? = null,   // null = all time
    val searchQuery: String = ""               // free text search in description
)
```

**Filter chips order:**
1. Severity chips (always visible): ALL, CRITICAL, HIGH, MEDIUM
2. Source chips (shown after first analysis): dns_monitor, appops, app_scanner, ...
3. Package chips (shown when multiple packages have events)
4. Campaign chips (shown when IOC matches exist)
5. Search icon (opens search bar overlay)

The filter state persists across the ViewModel lifecycle (not across app restart -- timeline filters are session-scoped).

### 4.7 Date Headers and Density Indicators

Events are grouped by date with sticky headers. Each date header shows an event count and density indicator:

```
+-- Date Header -----------------------------------+
|  Mar 27, 2026            47 events  [|||||| ]    |
+--------------------------------------------------+
```

The density bar is a small horizontal bar showing event density across 24 hours (6 segments of 4 hours each). Darker segments have more events. This immediately reveals "most activity happened between midnight and 4 AM" -- classic stalkerware behavior.

### 4.8 Empty State

When no timeline events exist yet:

```
+--------------------------------------------------+
|                                                    |
|           [Timeline icon - 64dp]                   |
|                                                    |
|         No Timeline Events Yet                     |
|                                                    |
|  Run a scan or analyze a bug report to             |
|  populate the forensic timeline.                   |
|                                                    |
|  [Run Scan]        [Analyze Bug Report]            |
|                                                    |
+--------------------------------------------------+
```

---

## 5. Export Formats

### 5.1 Format Comparison

| Format | Use Case | Audience | Compatibility |
|---|---|---|---|
| Plaintext | Quick sharing, victim support | Advocacy orgs, non-technical | Universal |
| CSV | Spreadsheet analysis, law enforcement | LEA analysts, paralegals | Excel, Google Sheets, MVT |
| JSON | Programmatic analysis, SIEM ingestion | SOC analysts, developers | Splunk, Elastic, custom tools |
| STIX 2.1 | Threat intelligence sharing | CTI teams, Amnesty, Citizen Lab | MISP, OpenCTI, TAXII |

### 5.2 CSV Export (MVT-Compatible)

MVT's timeline output uses these columns. AndroDR's CSV export should be compatible:

```csv
timestamp,source,event_type,description,package_name,severity,ioc_indicator,ioc_type,ioc_source,campaign,mitre_tactic,mitre_technique,details
2026-03-27T14:32:05.000Z,appops,permission_use,"com.network.android used CAMERA at 14:31",com.network.android,MEDIUM,,,,,,,
2026-03-27T14:32:05.000Z,dns_monitor,ioc_match,"DNS query: cdn-edge.net [MATCHED: Pegasus C2]",com.network.android,CRITICAL,cdn-edge.net,domain,amnesty,Pegasus,,,
```

**Column definitions:**

| Column | Type | Description |
|---|---|---|
| timestamp | ISO 8601 | Event timestamp (UTC) |
| source | String | Data source identifier |
| event_type | String | Event category |
| description | String | Human-readable description |
| package_name | String | Attributed Android package (empty if N/A) |
| severity | String | INFO/MEDIUM/HIGH/CRITICAL |
| ioc_indicator | String | Matched IOC value (empty if none) |
| ioc_type | String | IOC type (empty if none) |
| ioc_source | String | IOC database source |
| campaign | String | Associated campaign name |
| mitre_tactic | String | ATT&CK tactic ID |
| mitre_technique | String | ATT&CK technique ID |
| details | String | Extended evidence text |

### 5.3 JSON Export

```json
{
  "androdr_version": "1.0.0",
  "export_timestamp": "2026-03-28T10:00:00Z",
  "device": {
    "manufacturer": "Google",
    "model": "Pixel 8",
    "android_version": "15",
    "api_level": 35,
    "patch_level": "2026-03-01"
  },
  "filters_applied": {
    "severities": ["CRITICAL", "HIGH"],
    "date_range": null,
    "package_name": null
  },
  "event_count": 142,
  "events": [
    {
      "id": 1,
      "timestamp": "2026-03-27T14:32:05.000Z",
      "timestamp_precision": "exact",
      "source": "dns_monitor",
      "category": "ioc_match",
      "description": "DNS query: cdn-edge.net [MATCHED: Pegasus C2]",
      "details": "DNS response 172.67.xxx.xxx for cdn-edge.net",
      "severity": "CRITICAL",
      "package_name": "com.network.android",
      "app_name": "Network Service",
      "process_uid": 10145,
      "ioc": {
        "indicator": "cdn-edge.net",
        "type": "domain",
        "source": "amnesty",
        "campaign": "Pegasus"
      },
      "mitre_attack": {
        "tactic": "TA0011",
        "technique": "T1071.001"
      },
      "correlation_id": "a1b2c3d4-...",
      "rule_id": "sigma_dns_pegasus_c2",
      "is_from_bugreport": false,
      "is_from_runtime": true
    }
  ]
}
```

### 5.4 STIX 2.1 Export

For threat intelligence sharing with organizations like Amnesty Tech, Citizen Lab, and EFF. Only IOC-relevant events are included (not benign DNS queries or INFO-level posture checks).

```json
{
  "type": "bundle",
  "id": "bundle--uuid",
  "objects": [
    {
      "type": "observed-data",
      "id": "observed-data--uuid",
      "created": "2026-03-28T10:00:00Z",
      "modified": "2026-03-28T10:00:00Z",
      "first_observed": "2026-03-27T14:30:00Z",
      "last_observed": "2026-03-27T14:35:00Z",
      "number_observed": 1,
      "object_refs": ["domain-name--uuid"]
    },
    {
      "type": "domain-name",
      "id": "domain-name--uuid",
      "value": "cdn-edge.net"
    },
    {
      "type": "indicator",
      "id": "indicator--uuid",
      "created": "2026-03-28T10:00:00Z",
      "modified": "2026-03-28T10:00:00Z",
      "name": "Pegasus C2 Domain",
      "pattern": "[domain-name:value = 'cdn-edge.net']",
      "pattern_type": "stix",
      "valid_from": "2026-03-27T14:32:05Z",
      "labels": ["malicious-activity"],
      "external_references": [
        {
          "source_name": "amnesty",
          "description": "Pegasus C2 infrastructure"
        }
      ]
    },
    {
      "type": "malware",
      "id": "malware--uuid",
      "created": "2026-03-28T10:00:00Z",
      "modified": "2026-03-28T10:00:00Z",
      "name": "Pegasus",
      "is_family": true,
      "malware_types": ["spyware"]
    },
    {
      "type": "relationship",
      "id": "relationship--uuid",
      "created": "2026-03-28T10:00:00Z",
      "modified": "2026-03-28T10:00:00Z",
      "relationship_type": "indicates",
      "source_ref": "indicator--uuid",
      "target_ref": "malware--uuid"
    }
  ]
}
```

### 5.5 Plaintext Export

Extends the existing TimelineFormatter format. Adds the enhanced fields:

```
============================================================
  AndroDR Forensic Timeline Report
  Generated: 2026-03-28 10:00:00
  Android: 15 (API 35)
  Device: Google Pixel 8
  Patch Level: 2026-03-01
  Events: 142 (filtered: CRITICAL, HIGH)
============================================================

------------------------------------------------------------
  CRITICAL FINDINGS (3)
------------------------------------------------------------
  [CRITICAL] IOC Match: cdn-edge.net (Pegasus C2)
    Package: com.network.android
    Source: dns_monitor / amnesty
    ATT&CK: TA0011 / T1071.001
    Time: 2026-03-27 14:32:05

  [CRITICAL] Known spyware package installed
    Package: com.network.android
    Source: app_scanner / stalkerware-indicators
    Time: 2026-03-27 14:30:12

  [CRITICAL] C2 beacon pattern detected
    Source: bugreport_legacy
    Time: 2026-03-27 14:33:00

------------------------------------------------------------
  TIMELINE (142 events)
------------------------------------------------------------
  2026-03-27
  ----------
  CRITICAL  14:32:05  [dns_monitor] DNS query: cdn-edge.net [MATCHED: Pegasus C2]
                      Package: com.network.android
  HIGH      14:31:45  [appops] com.network.android used CAMERA
  HIGH      14:30:12  [package_monitor] App installed: com.network.android [SIDELOADED]
  INFO      14:28:33  [dns_monitor] DNS query: google.com (Chrome)
  ...

============================================================
  End of timeline report -- AndroDR
============================================================
```

### 5.6 Export Implementation

```kotlin
@Singleton
class TimelineExporter @Inject constructor(
    @ApplicationContext private val context: Context,
    private val timelineEventDao: TimelineEventDao
) {
    enum class ExportFormat { PLAINTEXT, CSV, JSON, STIX }

    suspend fun export(
        format: ExportFormat,
        filter: TimelineFilter = TimelineFilter()
    ): Uri = withContext(Dispatchers.IO) {
        val events = fetchFiltered(filter)
        val text = when (format) {
            ExportFormat.PLAINTEXT -> formatPlaintext(events)
            ExportFormat.CSV -> formatCsv(events)
            ExportFormat.JSON -> formatJson(events)
            ExportFormat.STIX -> formatStix(events)
        }
        val extension = when (format) {
            ExportFormat.PLAINTEXT -> "txt"
            ExportFormat.CSV -> "csv"
            ExportFormat.JSON -> "json"
            ExportFormat.STIX -> "json"
        }
        val reportsDir = File(context.cacheDir, "reports").apply { mkdirs() }
        val timestamp = SimpleDateFormat("yyyyMMdd_HHmmss", Locale.US).format(Date())
        val filename = "androdr_timeline_$timestamp.$extension"
        val file = File(reportsDir, filename)
        file.writeText(text, Charsets.UTF_8)

        FileProvider.getUriForFile(
            context,
            "${context.packageName}.fileprovider",
            file
        )
    }
}
```

---

## 6. Privacy and Security

### 6.1 Data Sensitivity Classification

Timeline data contains sensitive information. Each field has a classification:

| Field | Sensitivity | Rationale |
|---|---|---|
| DNS queries (domain names) | HIGH | Reveals browsing habits, interests, health queries |
| App install history | HIGH | Reveals personal app choices (dating, health, political) |
| Permission usage timestamps | MEDIUM | Reveals when camera/mic was used |
| Package names | LOW | Public information (available on Play Store) |
| Device posture flags | LOW | Generic security state |
| IOC matches | LOW | Indicator values are already public threat intelligence |

### 6.2 Storage Security

**Encryption at rest:**
- Room database uses SQLCipher via net.zetetic:android-database-sqlcipher
- Encryption key stored in Android Keystore (AndroidKeyStore provider)
- Key is hardware-backed on devices with Strongbox/TEE
- Key is generated on first launch and never leaves the device

```kotlin
@Provides
@Singleton
fun provideAppDatabase(
    @ApplicationContext context: Context,
    keyProvider: DatabaseKeyProvider
): AppDatabase {
    val factory = SupportFactory(keyProvider.getOrCreateKey())
    return Room.databaseBuilder(context, AppDatabase::class.java, "androdr.db")
        .openHelperFactory(factory)
        .build()
}
```

**Auto-expiry:**
- Timeline events auto-delete after a configurable retention period (default: 90 days)
- User can set retention to 30, 60, 90, or 180 days in Settings
- DNS events retain existing 7-day auto-delete via DnsEventDao.deleteOlderThan()
- "Delete All Timeline Data" button in Settings for immediate wipe

```kotlin
// In PeriodicScanWorker or dedicated TimelineMaintenanceWorker:
val retentionDays = settingsRepository.timelineRetentionDays.first()
val cutoff = System.currentTimeMillis() - (retentionDays * 24 * 60 * 60 * 1000L)
timelineEventDao.deleteOlderThan(cutoff)
```

### 6.3 Export Controls

**Who can export:**
- Export requires the user to actively tap "Export" and choose a format
- No automatic export, no background sync, no cloud upload
- Export files are written to cacheDir/reports/ (app-private, cleaned on uninstall)
- Sharing uses FileProvider (standard Android share sheet -- user chooses destination)

**Export warnings:**
- Before exporting, show a dialog: "This report contains sensitive information including DNS queries, app usage, and permission access times. Share only with trusted parties."
- For STIX export, additional warning: "STIX bundles are designed for threat intelligence sharing. They contain IOC matches and campaign attributions but NOT personal browsing data."

**What is excluded from export:**
- No INFO-level DNS queries in STIX export (only IOC matches)
- No raw logcat output in any export format
- Encryption keys are never included
- Device serial number is never included
- IMEI/IMSI are never included (and AndroDR does not collect them)

### 6.4 Lock Screen Protection

- Timeline screen requires device authentication (biometric or PIN) if the user enables "Require authentication" in Settings
- This prevents physical access attacks where someone picks up an unlocked phone and reads the timeline
- Implementation: BiometricPrompt gate before rendering TimelineScreen

---

## 7. ViewModel Architecture

### 7.1 TimelineViewModel

```kotlin
@HiltViewModel
class TimelineViewModel @Inject constructor(
    private val timelineEventDao: TimelineEventDao,
    private val timelineExporter: TimelineExporter,
    private val correlationEngine: CorrelationEngine,
    @ApplicationContext private val appContext: Context
) : ViewModel() {

    // -- Filter state --
    private val _filter = MutableStateFlow(TimelineFilter())
    val filter: StateFlow<TimelineFilter> = _filter.asStateFlow()

    // -- Timeline events (reactive to filter changes) --
    val events: StateFlow<List<TimelineDisplayItem>> = _filter
        .flatMapLatest { f -> queryEvents(f) }
        .map { events -> groupAndCorrelate(events) }
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), emptyList())

    // -- Event count by severity (for filter chip badges) --
    val severityCounts: StateFlow<Map<String, Int>> = events
        .map { items ->
            items.filterIsInstance<TimelineDisplayItem.Event>()
                .groupingBy { it.event.severity }
                .eachCount()
        }
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), emptyMap())

    // -- Export state --
    private val _exporting = MutableStateFlow(false)
    val exporting: StateFlow<Boolean> = _exporting.asStateFlow()

    private val _shareUri = MutableStateFlow<Uri?>(null)
    val shareUri: StateFlow<Uri?> = _shareUri.asStateFlow()

    // -- Detail sheet --
    private val _selectedEvent = MutableStateFlow<TimelineEvent?>(null)
    val selectedEvent: StateFlow<TimelineEvent?> = _selectedEvent.asStateFlow()

    private val _relatedEvents = MutableStateFlow<List<TimelineEvent>>(emptyList())
    val relatedEvents: StateFlow<List<TimelineEvent>> = _relatedEvents.asStateFlow()

    // -- Available filter options --
    val availableSources: StateFlow<List<String>> = flow {
        emit(timelineEventDao.getDistinctSources())
    }.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), emptyList())

    val availablePackages: StateFlow<List<String>> = flow {
        emit(timelineEventDao.getDistinctPackages())
    }.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), emptyList())

    // -- Actions --

    fun updateFilter(newFilter: TimelineFilter) {
        _filter.value = newFilter
    }

    fun toggleSeverity(severity: String) {
        _filter.update { current ->
            val newSet = current.severities.toMutableSet()
            if (severity in newSet && newSet.size > 1) newSet.remove(severity)
            else newSet.add(severity)
            current.copy(severities = newSet)
        }
    }

    fun selectEvent(event: TimelineEvent) {
        _selectedEvent.value = event
        if (event.correlationId.isNotEmpty()) {
            viewModelScope.launch {
                timelineEventDao.getCorrelatedEvents(event.correlationId)
                    .first()
                    .let { _relatedEvents.value = it }
            }
        } else {
            _relatedEvents.value = emptyList()
        }
    }

    fun dismissDetail() {
        _selectedEvent.value = null
        _relatedEvents.value = emptyList()
    }

    fun export(format: TimelineExporter.ExportFormat) {
        if (_exporting.value) return
        viewModelScope.launch {
            _exporting.value = true
            try {
                _shareUri.value = timelineExporter.export(format, _filter.value)
            } finally {
                _exporting.value = false
            }
        }
    }

    fun onShareConsumed() {
        _shareUri.value = null
    }

    // -- Internal --

    private fun queryEvents(filter: TimelineFilter): Flow<List<TimelineEvent>> {
        // Build query based on active filters
        // Uses the DAO methods defined above
        return when {
            filter.packageName != null ->
                timelineEventDao.getEventsByPackage(filter.packageName!!)
            filter.campaign != null ->
                timelineEventDao.getEventsByCampaign(filter.campaign!!)
            filter.dateRange != null ->
                timelineEventDao.getEventsInRange(
                    filter.dateRange!!.first,
                    filter.dateRange!!.second
                )
            else ->
                timelineEventDao.getEventsBySeverity(
                    filter.severities.toList()
                )
        }
    }

    private fun groupAndCorrelate(
        events: List<TimelineEvent>
    ): List<TimelineDisplayItem> {
        val items = mutableListOf<TimelineDisplayItem>()
        val grouped = events.groupBy { epochToDateString(it.timestamp) }

        for ((date, dayEvents) in grouped) {
            items.add(TimelineDisplayItem.DateHeader(
                date = date,
                eventCount = dayEvents.size,
                densityBuckets = computeDensityBuckets(dayEvents)
            ))

            val (clustered, standalone) = correlationEngine.partition(dayEvents)

            // Interleave clusters and standalone events in chronological order
            val allItems = mutableListOf<Pair<Long, TimelineDisplayItem>>()

            clustered.forEach { cluster ->
                val clusterTime = cluster.first().timestamp
                allItems.add(clusterTime to TimelineDisplayItem.Cluster(cluster))
            }
            standalone.forEach { event ->
                allItems.add(event.timestamp to TimelineDisplayItem.Event(event))
            }

            allItems.sortBy { it.first }
            items.addAll(allItems.map { it.second })
        }

        return items
    }
}

sealed interface TimelineDisplayItem {
    data class DateHeader(
        val date: String,
        val eventCount: Int,
        val densityBuckets: List<Float>  // 6 buckets (4h each), value 0.0-1.0
    ) : TimelineDisplayItem

    data class Event(
        val event: TimelineEvent
    ) : TimelineDisplayItem

    data class Cluster(
        val events: List<TimelineEvent>
    ) : TimelineDisplayItem
}
```

### 7.2 CorrelationEngine

```kotlin
@Singleton
class CorrelationEngine @Inject constructor() {

    /**
     * Partitions a list of events into correlation clusters and standalone events.
     * Returns: Pair(clusters, standalone)
     *
     * Correlation rules:
     * 1. Same package + different categories + within 30 minutes = cluster
     * 2. Same correlationId = cluster (pre-linked by analysis modules)
     * 3. Install + permission use + IOC match for same package = always cluster
     */
    fun partition(
        events: List<TimelineEvent>
    ): Pair<List<List<TimelineEvent>>, List<TimelineEvent>> {
        val clusters = mutableListOf<List<TimelineEvent>>()
        val used = mutableSetOf<Long>()  // event IDs already in clusters

        // Rule 1: Pre-linked correlations
        events.filter { it.correlationId.isNotEmpty() }
            .groupBy { it.correlationId }
            .values
            .filter { it.size >= 2 }
            .forEach { group ->
                clusters.add(group.sortedBy { it.timestamp })
                used.addAll(group.map { it.id })
            }

        // Rule 2: Package-based temporal clustering
        val remaining = events.filter { it.id !in used && it.packageName.isNotEmpty() }
        val byPackage = remaining.groupBy { it.packageName }

        for ((_, pkgEvents) in byPackage) {
            if (pkgEvents.size < 2) continue
            val sorted = pkgEvents.sortedBy { it.timestamp }

            var clusterStart = 0
            for (i in 1 until sorted.size) {
                val gap = sorted[i].timestamp - sorted[i - 1].timestamp
                if (gap > CLUSTER_WINDOW_MS) {
                    val segment = sorted.subList(clusterStart, i)
                    if (segment.size >= 2 && hasMultipleCategories(segment)) {
                        clusters.add(segment)
                        used.addAll(segment.map { it.id })
                    }
                    clusterStart = i
                }
            }
            // Handle last segment
            val lastSegment = sorted.subList(clusterStart, sorted.size)
            if (lastSegment.size >= 2 && hasMultipleCategories(lastSegment)) {
                clusters.add(lastSegment)
                used.addAll(lastSegment.map { it.id })
            }
        }

        val standalone = events.filter { it.id !in used }
        return clusters to standalone
    }

    private fun hasMultipleCategories(events: List<TimelineEvent>): Boolean {
        return events.map { it.category }.distinct().size >= 2
    }

    companion object {
        private const val CLUSTER_WINDOW_MS = 30 * 60 * 1000L  // 30 minutes
    }
}
```

---

## 8. Navigation Integration

The Timeline screen becomes a new top-level navigation destination, added to the existing bottom navigation bar:

```
[Dashboard] [Apps] [Device] [DNS] [Timeline]
```

The icon is Icons.Filled.Timeline (Material Icons). The label is "Timeline".

Additionally, other screens should deep-link into the timeline:
- DNS Monitor: tapping a matched DNS event opens Timeline filtered to that domain's package
- Bug Report Screen: "View Timeline" button opens Timeline filtered to bugreport events
- History Screen: tapping a scan opens Timeline filtered to that scan's timestamp range
- Apps Screen: tapping an app risk finding opens Timeline filtered to that package name

---

## 9. Example Timeline Entries

### 9.1 Stalkerware Investigation

This is what an analyst would see when investigating a domestic stalkerware case. The timeline tells the story: someone installed mSpy during a period when the victim's phone was physically accessible.

```
Date: March 25, 2026          12 events  [  ||||  ]
------------------------------------------------------

+-- Correlation Cluster (CRITICAL) ---+ 02:15-02:22
|                                      |
| 02:15:33  App installed: com.mspy.app
|           Sideloaded (installer: null) [SIDELOADED]
|           [package_monitor]                  [HIGH]
|
| 02:16:45  com.mspy.app registered AccessibilityService
|           [app_scanner] [T1626.001]       [CRITICAL]
|
| 02:17:12  com.mspy.app registered DeviceAdmin
|           [app_scanner] [T1629.003]       [CRITICAL]
|
| 02:18:01  com.mspy.app: IOC match (stalkerware-indicators)
|           Known stalkerware: mSpy
|           [app_scanner] [mspy]            [CRITICAL]
|
| 02:22:44  DNS: panel.mspy.com
|           [dns_monitor] [MATCHED: stalkerware C2]
|                                           [CRITICAL]
+----------------------------------------------+

  03:14:22  com.mspy.app used CAMERA
            [appops]                           [MEDIUM]

  03:14:25  com.mspy.app used RECORD_AUDIO
            [appops]                           [MEDIUM]

  03:15:01  com.mspy.app used READ_SMS
            [appops]                           [MEDIUM]

  03:15:03  com.mspy.app used READ_CONTACTS
            [appops]                           [MEDIUM]

  03:15:05  com.mspy.app used ACCESS_FINE_LOCATION
            [appops]                           [MEDIUM]

Date: March 24, 2026          2 events   [      ]
------------------------------------------------------

  22:30:00  Device posture: ADB debugging enabled
            [device_auditor]                    [HIGH]

  22:30:01  Device posture: Unknown sources enabled
            [device_auditor]                    [HIGH]
```

**What this tells the analyst:** ADB and unknown sources were enabled the evening before. The stalkerware was installed at 2:15 AM (while the victim was likely sleeping). Within 7 minutes, it had registered accessibility, device admin, and started surveillance. By 3:15 AM it had accessed camera, microphone, SMS, contacts, and location.

### 9.2 Nation-State Spyware Investigation

This is what an analyst investigating a journalist's device would see after analyzing a bugreport and cross-referencing with Amnesty Tech's Pegasus IOC list.

```
Date: March 20, 2026          8 events   [||    ]
------------------------------------------------------

+-- Correlation Cluster (CRITICAL) ---+ 09:30-09:35
|                                      |
| 09:30:15  com.process.helper installed
|           Sideloaded (installer: null)
|           [bugreport_legacy]                 [HIGH]
|
| 09:31:22  com.process.helper: cert hash IOC match
|           SHA256: a1b2c3...
|           Source: amnesty / Pegasus
|           [app_scanner] [Pegasus]         [CRITICAL]
|
| 09:33:44  DNS: imgcache-cdn.net
|           [bugreport_legacy] [MATCHED: Pegasus C2]
|           [Pegasus] [amnesty]             [CRITICAL]
|
| 09:34:01  Base64 data blob (4096 chars)
|           In logcat for com.process.helper
|           [bugreport_legacy]                 [HIGH]
|
| 09:35:12  C2 beacon pattern: HTTP POST every 300
|           [bugreport_legacy]              [CRITICAL]
+----------------------------------------------+

  09:41:00  com.process.helper used RECORD_AUDIO
            [appops]                           [MEDIUM]

  09:41:05  com.process.helper used ACCESS_FINE_LOCATION
            [appops]                           [MEDIUM]

Date: March 15, 2026          3 events   [      ]
------------------------------------------------------

  Device patch level 2025-12-01 (96 days old)
  3 CVEs linked to Pegasus campaigns:
    CVE-2025-27363 (FreeType RCE)
    CVE-2025-27364 (WebRTC bypass)
    CVE-2025-27365 (kernel UAF)
  [device_auditor]                              [HIGH]
```

**What this tells the analyst:** The device has a 96-day-old patch level with 3 CVEs linked to Pegasus campaigns. On March 20, a suspicious process was installed, its certificate hash matches Amnesty's Pegasus IOC list, it resolved a known C2 domain, transmitted base64 data (likely exfiltrated recordings), and established a periodic beacon. Classic Pegasus infection pattern.

---

## 10. Implementation Plan

### Phase 1: Data Layer (Week 1)

1. Create enhanced TimelineEvent Room entity (Section 2.1)
2. Create TimelineEventDao (Section 2.2)
3. Add migration to AppDatabase
4. Create event source adapters: DnsEvent.toTimelineEvent(), Finding.toTimelineEvent() (Section 2.4)
5. Modify BugReportAnalyzer to persist timeline events to Room
6. Modify ScanOrchestrator to persist scan findings as timeline events
7. Modify LocalVpnService to persist IOC-matched DNS events as timeline events

### Phase 2: Correlation Engine (Week 1-2)

1. Implement CorrelationEngine (Section 7.2)
2. Unit tests for correlation patterns (install-then-permission, multi-permission burst)
3. Ensure correlation assignment happens on insert (not on every query)

### Phase 3: Timeline UI (Week 2-3)

1. Create TimelineScreen composable (Section 4.2)
2. Create TimelineEventCard composable (Section 4.3)
3. Create TimelineEventDetailSheet composable (Section 4.4)
4. Create CorrelationCluster composable (Section 4.5)
5. Create filter bar with chips (Section 4.6)
6. Create date headers with density indicators (Section 4.7)
7. Create TimelineViewModel (Section 7.1)
8. Add Timeline to bottom navigation (Section 8)

### Phase 4: Export (Week 3)

1. Implement TimelineExporter (Section 5.6)
2. Implement CSV formatter (MVT-compatible) (Section 5.2)
3. Implement JSON formatter (Section 5.3)
4. Implement STIX 2.1 formatter (Section 5.4)
5. Extend plaintext formatter (Section 5.5)
6. Add export format picker dialog in UI

### Phase 5: Package Lifecycle Monitor (Week 3-4)

1. Implement PackageLifecycleReceiver (Section 3.3)
2. Register in AndroidManifest.xml
3. Test with adb install and Play Store installs

### Phase 6: Privacy Controls (Week 4)

1. Add SQLCipher encryption to Room database (Section 6.2)
2. Add timeline retention settings UI (Section 6.2)
3. Add export warning dialogs (Section 6.3)
4. Add "Delete All Timeline Data" to Settings
5. Add optional biometric gate for Timeline screen (Section 6.4)

### Phase 7: Deep-Link Integration (Week 4)

1. DNS Monitor -> Timeline filtered by package
2. Bug Report -> Timeline filtered to bugreport events
3. History -> Timeline filtered by scan timestamp range
4. Apps -> Timeline filtered by package name

---

## 11. Testing Strategy

### Unit Tests

| Test | What It Validates |
|---|---|
| TimelineEventDaoTest | Room queries return correct events for each filter combination |
| CorrelationEngineTest | Clustering logic groups events correctly by package + time window |
| DnsEventToTimelineTest | DnsEvent -> TimelineEvent conversion preserves all fields |
| FindingToTimelineTest | Finding -> TimelineEvent conversion maps severity/category correctly |
| CsvExporterTest | CSV output matches MVT column format |
| JsonExporterTest | JSON output is valid and contains all required fields |
| StixExporterTest | STIX 2.1 bundle validates against schema |
| TimelineFilterTest | Filter combinations produce correct DAO queries |

### Integration Tests

| Test | What It Validates |
|---|---|
| BugreportToTimelineTest | Full bugreport analysis populates timeline with correct events |
| ScanToTimelineTest | Runtime scan findings appear as timeline events |
| DnsToTimelineTest | DNS IOC matches create CRITICAL timeline events |
| ExportRoundtripTest | Export -> re-import produces equivalent event set |

### UI Tests (Compose)

| Test | What It Validates |
|---|---|
| TimelineScreenEmptyTest | Empty state renders with action buttons |
| TimelineScreenFilterTest | Filter chips toggle visibility of events |
| TimelineEventCardTest | Card renders all severity levels with correct colors |
| CorrelationClusterTest | Cluster renders connected events with border |
| DateHeaderTest | Date headers show correct counts and density |

---

## 12. Open Questions

1. **Should INFO-level events be shown by default?** Benign DNS queries and passing device posture checks add noise. Recommendation: default filter excludes INFO, user can toggle it on.

2. **Maximum event retention before performance degrades?** Room with SQLCipher on a mid-range phone can handle ~50K rows with indexed queries. At 100 events/day, that is 500 days. The 90-day default retention keeps it well within limits.

3. **Should the timeline replace the Bug Report screen's event list?** Currently BugReportScreen shows its own TimelineEventCard list. After this work, bugreport events also appear in the unified Timeline. Recommendation: keep the inline list on BugReportScreen for immediate context, but add a "View in Timeline" button that deep-links.

4. **STIX export: full bundle or individual objects?** Recommendation: full bundle. Individual STIX objects are meaningless without relationships. A bundle is self-contained and can be imported directly into MISP or OpenCTI.

5. **Should the app request PACKAGE_USAGE_STATS permission?** This is a special permission requiring user navigation to Settings. It enables richer timeline data (foreground/background transitions) but adds friction to setup. Recommendation: optional, prompted only when the user enters Timeline screen for the first time, with a clear explanation of why it matters.
