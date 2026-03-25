# Design: MVT Domain IOC Feed + VPN Self-Exclusion Fix

**Date:** 2026-03-25
**Branch:** main (next feature branch)
**Status:** Approved

---

## Overview

Two related improvements to AndroDR's network security layer:

1. **VPN self-exclusion fix** — AndroDR's own HTTPS traffic (IOC updates, feed fetches) is currently routed through the local VPN tunnel, causing update timeouts when the VPN is active. One-line fix: exclude the app's own package from the tunnel.
2. **MVT domain IOC feed** — Fetch mercenary spyware domain indicators from the Amnesty/Citizen Lab MVT project (Pegasus, Predator, RCS Lab, etc.), store them in Room, and check them at DNS query time with a configurable block-vs-detect policy.

---

## Part 1: VPN Self-Exclusion Fix

### Change

One line added to `DnsVpnService.startVpn()` inside the `Builder()` call:

```kotlin
.addDisallowedApplication(packageName)
```

`packageName` is inherited from `Context` and resolves correctly for both the debug (`com.androdr.debug`) and release (`com.androdr`) variants. This causes Android to bypass the VPN tunnel for all traffic originating from AndroDR itself, including `HttpURLConnection` calls made by `RemoteIocUpdater` and the new `DomainIocUpdater`.

### Files changed

- `app/src/main/java/com/androdr/network/DnsVpnService.kt` — add `.addDisallowedApplication(packageName)` in `startVpn()`

---

## Part 2: Data Layer

### New Room entity: `DomainIocEntry`

**Package:** `com.androdr.data.model`

```kotlin
@Entity(tableName = "domain_ioc_entries")
data class DomainIocEntry(
    @PrimaryKey val domain: String,   // e.g. "weather4free.com", lowercase, no trailing dot
    val campaignName: String,          // e.g. "NSO Group Pegasus"
    val severity: String,              // "CRITICAL" for all mercenary spyware entries
    val source: String,                // e.g. "mvt_pegasus", "mvt_predator"
    val fetchedAt: Long
)
```

`domain` is the primary key, stored lowercase without a trailing dot, at whatever granularity the feed provides (apex or full subdomain). Subdomain resolution is handled at lookup time via label-stripping (see `DomainIocResolver`).

### New DAO: `DomainIocEntryDao`

**Package:** `com.androdr.data.db`

Methods:
- `upsertAll(entries: List<DomainIocEntry>)`
- `getAll(): List<DomainIocEntry>`
- `count(): Int`
- `deleteStaleEntries(source: String, before: Long)`
- `mostRecentFetchTime(): Long?` — returns global max `fetchedAt` across all sources (same behaviour as `IocEntryDao.mostRecentFetchTime()`; known limitation: a partial update failure still shows an optimistic timestamp)

### Room migration

`AppDatabase` currently has `exportSchema = false`, which means **auto-migration is not available** (Room auto-migration requires schema JSON exports). The only viable path is a manual `Migration` object, following the exact pattern of the existing `MIGRATION_1_2` in `Migrations.kt`:

```kotlin
val MIGRATION_2_3 = object : Migration(2, 3) {
    override fun migrate(db: SupportSQLiteDatabase) {
        db.execSQL("""
            CREATE TABLE IF NOT EXISTS `domain_ioc_entries` (
                `domain` TEXT NOT NULL,
                `campaignName` TEXT NOT NULL,
                `severity` TEXT NOT NULL,
                `source` TEXT NOT NULL,
                `fetchedAt` INTEGER NOT NULL,
                PRIMARY KEY(`domain`)
            )
        """)
    }
}
```

`AppDatabase` version advances from **2 to 3** and `MIGRATION_2_3` is added to the `databaseBuilder` call in `AppModule`.

### New in-memory resolver: `DomainIocResolver`

**Package:** `com.androdr.ioc`

- `@Singleton`, Hilt-injected
- Holds `AtomicReference<Map<String, DomainIocEntry>?>` keyed by exact domain (lowercase, no trailing dot)
- `suspend fun refreshCache()` — loads all rows from Room into the map
- `fun isKnownBadDomain(domain: String): DomainIocEntry?` — performs the same label-stripping walk as `BlocklistManager.isBlocked()` (O(k) where k = number of labels), so that a query for `c2.pegasus-domain.example` matches an IOC entry keyed on `pegasus-domain.example`. Returns `null` if not found or cache not yet loaded.

The label-stripping walk:
```
candidate = domain.trimEnd('.').lowercase()
while candidate is not empty:
    if candidate in cache → return cache[candidate]
    dotIndex = candidate.indexOf('.')
    if dotIndex < 0 → break   // reached TLD
    candidate = candidate.substring(dotIndex + 1)
return null
```

---

## Part 3: MVT Feed Implementation

### Feed index

The MVT project publishes `indicators.yaml` at:

```
https://raw.githubusercontent.com/mvt-project/mvt-indicators/main/indicators.yaml
```

Each entry has `type: github` and a `github:` block with `owner`, `repo`, `branch`, and `path` pointing to a STIX2 file.

### New interface: `DomainIocFeed`

**Package:** `com.androdr.ioc`

```kotlin
interface DomainIocFeed {
    val sourceId: String
    suspend fun fetch(): List<DomainIocEntry>
}
```

Mirrors the existing `IocFeed` interface; return an empty list on any failure (never throw).

### New feed: `MvtIndicatorsFeed`

**Package:** `com.androdr.ioc.feeds`

Implementation steps:

1. Fetch `indicators.yaml` via `HttpURLConnection` (15 s timeout, `User-Agent: AndroDR/1.0`)
2. Parse YAML with a line-based state machine to extract GitHub-hosted STIX2 URLs. Relevant lines:
   - `type: github` — marks a GitHub-hosted entry
   - `name: <campaign>` — campaign display name
   - `github:` block with `owner`, `repo`, `branch`, `path` sub-keys
3. Construct raw GitHub URL: `https://raw.githubusercontent.com/<owner>/<repo>/<branch>/<path>`
4. Fetch all STIX2 files in parallel (one coroutine per campaign) using `coroutineScope { async { ... } }`
5. For each STIX2 JSON response, parse `indicator` objects whose `pattern_type == "stix"`. Extract all domain names from the `pattern` field using `Regex("""domain-name:value\s*=\s*'([^']+)'""").findAll(pattern)` — note `findAll` (not `find`) to handle compound OR patterns such as `[domain-name:value = 'foo.com' OR domain-name:value = 'bar.com']`
6. Return `DomainIocEntry` for each extracted domain, tagged with `source = "mvt_<slug>"` where `<slug>` is the campaign name lowercased with non-alphanumeric characters replaced by underscores

**Visibility:** `parseIndicatorsYaml()` and `parseStix2()` are `internal` functions (not `private`) so they are directly reachable from unit tests in the `test` source set without reflection.

**Source ID:** `"mvt_indicators"` (parent); individual campaign slugs used for stale-entry pruning per source.

### New orchestrator: `DomainIocUpdater`

**Package:** `com.androdr.ioc`

```kotlin
@Singleton
class DomainIocUpdater @Inject constructor(
    private val domainIocEntryDao: DomainIocEntryDao,
    private val domainIocResolver: DomainIocResolver
) {
    private val feeds: List<DomainIocFeed> = listOf(MvtIndicatorsFeed())

    suspend fun update(): Int { /* parallel fetch, upsert, prune, refreshCache */ }
}
```

Mirrors `RemoteIocUpdater` exactly. Returns total domain entries stored (0 if all feeds failed).

**Dependency constraint:** `MvtIndicatorsFeed` is constructed directly (not Hilt-injected) inside `DomainIocUpdater`, following the same pattern as `RemoteJsonFeed` and `StalkerwareIndicatorsFeed` in `RemoteIocUpdater`. `MvtIndicatorsFeed` must therefore remain a pure class with no injected dependencies — it uses `HttpURLConnection` directly. If future feeds require injection, the feeds list should be moved to a Hilt `Set<DomainIocFeed>` multibinding.

### `IocUpdateWorker` update

`IocUpdateWorker` currently calls only `remoteIocUpdater.update()`. It must also call `domainIocUpdater.update()` so that scheduled background refreshes keep domain IOCs up to date. Without this change, domain IOCs are only refreshed via manual Dashboard taps and the "Updated Xh ago" staleness display will show permanently stale after a while.

`IocUpdateWorker` is updated to inject `DomainIocUpdater` and call both updaters in parallel:
```kotlin
coroutineScope {
    async { remoteIocUpdater.update() }
    async { domainIocUpdater.update() }
}
```
**Known limitation (pre-existing):** Both `update()` implementations swallow network failures internally and return `0` rather than throwing. As a result, `Result.retry()` is never triggered by network failures — the worker always returns `Result.success()`. This matches the current single-updater behaviour in the existing `IocUpdateWorker`.

---

## Part 4: DNS Policy & VPN Integration

### Settings persistence

Jetpack DataStore (Preferences). Two boolean keys:

| Key | Default | Meaning |
|-----|---------|---------|
| `blocklist_block_mode` | `true` | Static blocklist: `true` = NXDOMAIN, `false` = detect-only (log + allow) |
| `domain_ioc_block_mode` | `false` | IOC domain hits: `true` = NXDOMAIN, `false` = detect-only (EDR default) |

Default for `domain_ioc_block_mode` is `false` (detect-only) because blocking C2 silently may tip off an attacker and the primary EDR goal is visibility.

### New: `SettingsRepository`

**Package:** `com.androdr.data.repo`

- `@Singleton`, Hilt-injected; DataStore provided via Hilt in `AppModule`
- Exposes `blocklistBlockMode: Flow<Boolean>` and `domainIocBlockMode: Flow<Boolean>`
- `suspend fun setBlocklistBlockMode(value: Boolean)` and `suspend fun setDomainIocBlockMode(value: Boolean)`

### `DnsVpnService` DataStore collection

`DnsVpnService` receives `DomainIocResolver` and `SettingsRepository` via Hilt injection. Policy values are maintained as `MutableStateFlow` fields in the service, updated by coroutines launched in `serviceScope` that collect from `SettingsRepository`:

```kotlin
private var blocklistBlockMode = MutableStateFlow(true)
private var domainIocBlockMode = MutableStateFlow(false)

// called in startVpn():
serviceScope.launch { settingsRepository.blocklistBlockMode.collect { blocklistBlockMode.value = it } }
serviceScope.launch { settingsRepository.domainIocBlockMode.collect { domainIocBlockMode.value = it } }
```

This mirrors the existing `isRunning` pattern. `collectAsStateWithLifecycle` is a Compose API and must not be used in a `Service`.

`DnsVpnService` also triggers `domainIocResolver.refreshCache()` when the tunnel starts. Because `refreshCache()` is a `suspend fun` and `startVpn()` is a regular (non-suspending) function, the call must be wrapped in a launch:
```kotlin
// in startVpn(), after the settings collection launches:
serviceScope.launch { domainIocResolver.refreshCache() }
```

### `DnsVpnService` query path (updated)

```
For each DNS hostname:
  1. BlocklistManager.isBlocked(hostname)?
       yes + blocklistBlockMode=true  → NXDOMAIN; log isBlocked=true, reason="blocklist"
       yes + blocklistBlockMode=false → forward; log isBlocked=false, reason="blocklist_detect"
  2. DomainIocResolver.isKnownBadDomain(hostname)?
       yes + domainIocBlockMode=true  → NXDOMAIN; log isBlocked=true, reason="IOC: <campaignName>"
       yes + domainIocBlockMode=false → forward; log isBlocked=false, reason="IOC_detect: <campaignName>"
  3. Neither → forward; log (existing behaviour)
```

---

## Part 5: UI

### New `SettingsViewModel`

**Package:** `com.androdr.ui.settings`

`@HiltViewModel`. Each screen that uses it (`SettingsScreen`, `NetworkScreen`) receives its own Hilt-scoped instance via `hiltViewModel()` — this is correct because both instances read from the same `SettingsRepository` DataStore, so they are always in sync. There is no need for a shared nav-graph-scoped ViewModel.

Exposes:
- `blocklistBlockMode: StateFlow<Boolean>`
- `domainIocBlockMode: StateFlow<Boolean>`
- `fun setBlocklistBlockMode(value: Boolean)`
- `fun setDomainIocBlockMode(value: Boolean)`

### New `SettingsScreen`

**Package:** `com.androdr.ui.settings`

Added to the nav graph. Reachable via a gear icon in the Dashboard header row.

```
Settings

DNS Blocklist
  [Switch] Block matched domains (off = Detect & log only)

Threat Intelligence Domains (MVT/Pegasus/Predator)
  [Switch] Block matched domains (off = Detect & log only)
```

### `NetworkScreen` quick toggles

Two `Switch` rows added above the DNS event list, bound to a local `SettingsViewModel` instance (same DataStore, same values):

```
Blocklist:    [Switch] Block / Detect
IOC Domains:  [Switch] Block / Detect
```

### `DashboardViewModel` additions

- `domainIocEntryCount: StateFlow<Int>` — from `DomainIocEntryDao.count()`
- `domainIocLastUpdated: StateFlow<Long?>` — from `DomainIocEntryDao.mostRecentFetchTime()`
- `isUpdatingDomainIoc: StateFlow<Boolean>`
- `fun updateDomainIoc()` — launches `DomainIocUpdater.update()` in `viewModelScope`

### `ThreatDatabaseCard` update

Two rows, each with independent update button:

```
[icon] 1,634 package IOCs · Updated 2h ago    [Update]
[icon] 1,549 domain IOCs  · Updated 2h ago    [Update]
```

Staleness logic (>24 h = stale, orange) applies independently to each row.

---

## File Change Summary

| File | Package | Change |
|------|---------|--------|
| `DnsVpnService.kt` | `com.androdr.network` | Add `.addDisallowedApplication(packageName)`; inject `DomainIocResolver`, `SettingsRepository`; collect settings into local `MutableStateFlow`; update query path |
| `DomainIocEntry.kt` (new) | `com.androdr.data.model` | Room entity |
| `DomainIocEntryDao.kt` (new) | `com.androdr.data.db` | Room DAO |
| `DomainIocResolver.kt` (new) | `com.androdr.ioc` | In-memory cache + hierarchical lookup |
| `DomainIocFeed.kt` (new) | `com.androdr.ioc` | Interface |
| `MvtIndicatorsFeed.kt` (new) | `com.androdr.ioc.feeds` | Feed implementation with `internal` parse functions |
| `DomainIocUpdater.kt` (new) | `com.androdr.ioc` | Orchestrator |
| `SettingsRepository.kt` (new) | `com.androdr.data.repo` | DataStore wrapper |
| `SettingsViewModel.kt` (new) | `com.androdr.ui.settings` | HiltViewModel for settings |
| `SettingsScreen.kt` (new) | `com.androdr.ui.settings` | Settings UI |
| `NetworkScreen.kt` | `com.androdr.ui.network` | Add quick policy toggles; imports `SettingsViewModel` from `com.androdr.ui.settings` (do not create a second ViewModel class in the network package) |
| `DashboardViewModel.kt` | `com.androdr.ui.dashboard` | Add domain IOC state + `updateDomainIoc()` |
| `DashboardScreen.kt` | `com.androdr.ui.dashboard` | Update `ThreatDatabaseCard` to show two rows |
| `Migrations.kt` | `com.androdr.data.db` | Add `MIGRATION_2_3` |
| `AppDatabase.kt` | `com.androdr.data.db` | Version 2 → 3; register `MIGRATION_2_3`; add `DomainIocEntryDao` |
| `AppModule.kt` | `com.androdr.di` | Provide DataStore instance + `SettingsRepository` (both need explicit `@Provides`; `DomainIocUpdater` is `@Singleton @Inject constructor` so Hilt auto-binds it — no explicit `@Provides` needed) |
| `IocUpdateWorker.kt` | `com.androdr.ioc` | Inject `DomainIocUpdater`; run both updaters in parallel |
| `MainActivity.kt` / nav graph | `com.androdr` | Add Settings destination + gear icon in Dashboard header |

---

## Testing

- Unit test `MvtIndicatorsFeed.parseStix2()` (`internal`) — fixture STIX2 JSON with single-domain and compound OR patterns; verify all domains extracted
- Unit test `MvtIndicatorsFeed.parseIndicatorsYaml()` (`internal`) — fixture YAML; verify correct raw GitHub URLs constructed per campaign
- Unit test `DomainIocResolver.isKnownBadDomain()` — verify apex match, subdomain match via label-stripping, no false positive on unrelated domain, cache-miss returns null
- Unit test `SettingsRepository` — verify DataStore read/write round-trip using `TestDataStore` / in-memory DataStore
- Unit test `IocUpdateWorker` — verify both `remoteIocUpdater.update()` and `domainIocUpdater.update()` are called
- Existing `AppScanner` and `BugReportAnalyzer` tests unaffected
