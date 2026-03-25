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

```kotlin
@Entity(tableName = "domain_ioc_entries")
data class DomainIocEntry(
    @PrimaryKey val domain: String,
    val campaignName: String,   // e.g. "NSO Group Pegasus"
    val severity: String,       // "CRITICAL" for all mercenary spyware entries
    val source: String,         // e.g. "mvt_pegasus", "mvt_predator"
    val fetchedAt: Long
)
```

Kept deliberately minimal. `domain` is the primary key (lowercase, no trailing dot). `source` is a slug derived from the campaign name in `indicators.yaml`, used for stale-entry pruning.

### New DAO: `DomainIocEntryDao`

Methods:
- `upsertAll(entries: List<DomainIocEntry>)`
- `getAll(): List<DomainIocEntry>`
- `count(): Int`
- `deleteStaleEntries(source: String, before: Long)`
- `mostRecentFetchTime(): Long?`

### Room migration

`AppDatabase` version incremented by 1. Migration adds `domain_ioc_entries` table. Auto-migration annotation used if schema export is enabled; otherwise a manual `Migration` object.

### New in-memory resolver: `DomainIocResolver`

- `@Singleton`, Hilt-injected
- Holds `AtomicReference<Map<String, DomainIocEntry>?>` populated from Room
- `suspend fun refreshCache()` — loads all rows into the map
- `fun isKnownBadDomain(domain: String): DomainIocEntry?` — O(1) lookup; returns `null` if not found or cache not yet loaded

---

## Part 3: MVT Feed Implementation

### Feed index

The MVT project publishes `indicators.yaml` at:

```
https://raw.githubusercontent.com/mvt-project/mvt-indicators/main/indicators.yaml
```

Each entry has `type: github` and a `github:` block with `owner`, `repo`, `branch`, and `path` pointing to a STIX2 file.

### New interface: `DomainIocFeed`

```kotlin
interface DomainIocFeed {
    val sourceId: String
    suspend fun fetch(): List<DomainIocEntry>
}
```

Mirrors the existing `IocFeed` interface; return an empty list on any failure (never throw).

### New feed: `MvtIndicatorsFeed`

Implementation steps:

1. Fetch `indicators.yaml` via `HttpURLConnection` (15 s timeout, `User-Agent: AndroDR/1.0`)
2. Parse YAML with a line-based state machine to extract GitHub-hosted STIX2 URLs. Relevant lines:
   - `type: github` — marks a GitHub-hosted entry
   - `name: <campaign>` — campaign display name
   - `github:` block with `owner`, `repo`, `branch`, `path` sub-keys
3. Construct raw GitHub URL: `https://raw.githubusercontent.com/<owner>/<repo>/<branch>/<path>`
4. Fetch all STIX2 files in parallel (one coroutine per campaign) using `coroutineScope { async { ... } }`
5. For each STIX2 JSON response, parse `indicator` objects whose `pattern_type == "stix"` and `pattern` matches the regex `\[domain-name:value='([^']+)'\]`
6. Return `DomainIocEntry` for each extracted domain, tagged with `source = "mvt_<slug>"` where `<slug>` is the campaign name lowercased with spaces replaced by underscores

No external YAML or STIX library. Both formats are regular enough for simple parsing.

**Source ID:** `"mvt_indicators"` (parent); individual campaign slugs used for stale-entry pruning.

### New orchestrator: `DomainIocUpdater`

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

- `@Singleton`, Hilt-injected
- Wraps DataStore; exposes `blocklistBlockMode: Flow<Boolean>` and `domainIocBlockMode: Flow<Boolean>`
- `suspend fun setBlocklistBlockMode(value: Boolean)` and `suspend fun setDomainIocBlockMode(value: Boolean)`

### `DnsVpnService` query path (updated)

`DnsVpnService` receives `DomainIocResolver` and `SettingsRepository` via Hilt injection. Policy values are read once at query time from the latest emitted DataStore value (cached as `StateFlow` collected in the service scope).

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

`DnsVpnService` also calls `DomainIocResolver.refreshCache()` on service start so domain hits are available immediately.

---

## Part 5: UI

### New `SettingsViewModel`

Shared between `SettingsScreen` and `NetworkScreen`. Collects both `Flow<Boolean>` values from `SettingsRepository` as `StateFlow`; exposes toggle functions.

### New `SettingsScreen`

Added to the nav graph. Reachable via a gear icon in the Dashboard header row.

```
Settings

DNS Blocklist
  [Switch] Block matched domains (off = Detect & log only)

Threat Intelligence Domains (MVT/Pegasus/Predator)
  [Switch] Block matched domains (off = Detect & log only)
```

### `NetworkScreen` quick toggles

Two `Switch` rows added above the DNS event list, bound to the same `SettingsViewModel`:

```
Blocklist:    [Block | Detect]
IOC Domains:  [Block | Detect]
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

| File | Change |
|------|--------|
| `DnsVpnService.kt` | Add `.addDisallowedApplication(packageName)`; inject `DomainIocResolver`, `SettingsRepository`; update query path |
| `DomainIocEntry.kt` (new) | Room entity |
| `DomainIocEntryDao.kt` (new) | Room DAO |
| `DomainIocResolver.kt` (new) | In-memory cache + lookup |
| `DomainIocFeed.kt` (new) | Interface |
| `MvtIndicatorsFeed.kt` (new) | Feed implementation |
| `DomainIocUpdater.kt` (new) | Orchestrator |
| `SettingsRepository.kt` (new) | DataStore wrapper |
| `SettingsViewModel.kt` (new) | Shared ViewModel for settings |
| `SettingsScreen.kt` (new) | Settings UI |
| `NetworkScreen.kt` | Add quick policy toggles |
| `DashboardViewModel.kt` | Add domain IOC state + `updateDomainIoc()` |
| `DashboardScreen.kt` | Update `ThreatDatabaseCard` to show two rows |
| `AppDatabase.kt` | Version bump + migration for `domain_ioc_entries` |
| `AppModule.kt` / DI | Provide `DomainIocUpdater`, `SettingsRepository`, DataStore |
| `MainActivity.kt` / nav graph | Add Settings destination + gear icon |

---

## Testing

- Unit test `MvtIndicatorsFeed.parseStix2()` with a fixture STIX2 snippet — verify domain extraction
- Unit test `MvtIndicatorsFeed.parseIndicatorsYaml()` with a fixture YAML snippet — verify URL construction
- Unit test `DomainIocResolver` — verify cache miss returns null, cache hit returns entry
- Unit test `SettingsRepository` — verify DataStore read/write round-trip (using TestDataStore)
- Existing `AppScanner` and `BugReportAnalyzer` tests unaffected
