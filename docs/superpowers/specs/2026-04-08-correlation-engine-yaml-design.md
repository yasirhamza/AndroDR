# Sprint #75 — Rule-Driven Correlation Engine + Real Install-Time Signal

**Date:** 2026-04-08
**Tracking issue:** [#75](https://github.com/yasirhamza/AndroDR/issues/75)

## Background

Two findings from the April 2026 perf/correctness session must ship together:

1. **`CorrelationEngine` hardcodes detection patterns in Kotlin** — five private methods (`detectInstallThenAdmin`, `detectInstallThenPermission`, `detectPermissionThenC2`, `detectMultiPermissionBurst`, `detectGenericTemporal`) embed every category filter, time window, and minimum count as Kotlin constants. This violates AndroDR's design principle that detection logic must be rule-driven YAML.
2. **`PACKAGE_INSTALL` category has zero producers** — `TimelineCategory.PACKAGE_INSTALL` is referenced by two correlation methods but nothing in the codebase emits events with this category. The "install then admin" pattern falls back to matching SIGMA sideload findings whose timestamps are scan-time, not real install times. Forensically meaningless.

Shipping #1 alone gives a clean rule engine firing on nothing real. Shipping #2 alone gives real signal flowing into hardcoded patterns. Bundled, they yield the first genuinely rule-driven temporal correlation layer with real install semantics.

## Goals

- Migrate the four meaningful hardcoded patterns to upstream-SIGMA-compliant YAML correlation rules.
- Add real install-time signal (`PackageInfo.firstInstallTime` runtime + `dumpsys package` bug-report) so install-then-X correlations fire on real events.
- Persist correlation results as durable timeline rows so they survive across screen opens, exports, and scan history.
- Honor SIEM industry conventions for correlation event modeling (start/end times, distinct event kind, explicit member references).

## Non-goals

- New correlation patterns beyond the four migrations (becomes a rule-authoring task after this lands).
- UI redesign of the cluster card (the existing `CorrelationClusterCard` is reused).
- Cross-scan package monitor (tracked separately in post-RC priorities).
- Full upstream SIGMA correlation spec — `value_count` and nested correlations are out of scope for this sprint.

---

## Architecture

### Locked design decisions

1. **Scan-time evaluation** — `ScanOrchestrator` invokes the correlation engine after SIGMA detection, results persisted as `ForensicTimelineEvent` rows. View-time was rejected because rule-evaluation cost grows silently with rule count, has no durability, and pushes work onto the Timeline screen's open path.
2. **Upstream SIGMA correlation grammar** — full compliance, subset implementation. Rule files using supported types are valid upstream SIGMA and could in principle be authored by the community.
3. **Three correlation types supported:** `temporal_ordered`, `event_count`, `temporal`. Unsupported types (`value_count`, nested correlations) fail at parse time with a clear "unsupported correlation type" error.
4. **Atom rules** — thin pass-through SIGMA rules that match raw event categories (`package_install`, `permission_use`, `device_admin_grant`, `ioc_match`) with no extra filtering. Tagged `level: informational` so they don't render as standalone findings. Correlations reference atoms by ID, not filtered detection rules like `androdr-013`.
5. **Per-rule windowed DB queries** — for each correlation rule, query exactly its `timespan` window from `forensic_timeline`. Individual `timespan` capped at 90 days at parse time.
6. **SIEM-aligned event model** — `ForensicTimelineEvent` gains `startTimestamp` (rename of `timestamp`), `endTimestamp: Long?`, and `kind: String` discriminator (`event` for raw, `signal` for correlation results).
7. **Install events emitted once per package** — first scan emits all installed packages; subsequent scans only emit *newly installed* packages. True install monitoring, not re-emission noise.

### Component diagram

```
ScanOrchestrator
  ├─ AppScanner.collectTelemetry()
  │    └─ buildTelemetryForPackage()  → AppTelemetry { firstInstallTime, lastUpdateTime, ... }
  ├─ SigmaRuleEngine.evaluate*()       → detection findings (existing)
  ├─ InstallEventEmitter.emitNew()     → new package_install timeline rows (delta vs prior scans)
  ├─ SigmaCorrelationEngine.evaluate() → correlation signal rows
  └─ ScanRepository.saveScanResults()  → single-transaction persistence (existing)

BugReportAnalyzer
  ├─ existing modules
  ├─ InstallTimeModule                 → package_install timeline rows from dumpsys package
  └─ SigmaCorrelationEngine.evaluate() → correlation signal rows

SigmaRuleEngine
  ├─ SigmaRuleParser                   → existing detection-rule parser, gains correlation: branch
  ├─ SigmaRuleEvaluator                → existing detection evaluator (unchanged)
  └─ SigmaCorrelationEngine            → NEW: evaluates correlation rules over timeline events
```

### Data flow

1. Runtime scan or bug-report analysis emits raw timeline events (`kind = "event"`) — including new `package_install` events from this sprint.
2. After detection rules evaluate, `SigmaCorrelationEngine.evaluate()` runs each loaded correlation rule:
   - Queries the timeline DB for events within the rule's `timespan` window (per-rule windowed query).
   - Filters to events that match the atom rules referenced by the correlation.
   - Applies the type-specific evaluator (`temporal_ordered`, `event_count`, or `temporal`).
   - For each match, produces a correlation signal row.
3. Signal rows persist alongside detection findings in the same `withTransaction` block in `ScanRepository.saveScanResults()`.
4. Timeline UI reads rows by `startTimestamp`. Rows with `kind = "signal"` render as `CorrelationClusterCard`; member events are joined on `matchContext.member_event_ids` for the expanded view.

---

## Data model changes

### `ForensicTimelineEvent` (modified)

```kotlin
@Entity(tableName = "forensic_timeline")
data class ForensicTimelineEvent(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    val scanId: Long,
    val startTimestamp: Long,           // RENAMED from `timestamp`
    val endTimestamp: Long? = null,     // NEW: null for point events, set for ranges
    val kind: String = "event",         // NEW: "event" (raw) or "signal" (correlation)
    val timestampPrecision: String = "exact",
    val category: String,
    val source: String,
    val description: String,
    val severity: String,
    val matchContext: Map<String, String> = emptyMap()
    // ... other existing fields unchanged
)
```

**For correlation signals:**
- `kind = "signal"`
- `category = "correlation"`
- `startTimestamp` = first member event timestamp
- `endTimestamp` = last member event timestamp
- `matchContext.correlation_type` = `temporal_ordered` | `event_count` | `temporal`
- `matchContext.rule_id` = SIGMA correlation rule ID that fired
- `matchContext.member_event_ids` = comma-separated list of `ForensicTimelineEvent.id` values

### `AppTelemetry` (modified)

```kotlin
data class AppTelemetry(
    // ... existing fields
    val firstInstallTime: Long,    // NEW: from PackageInfo.firstInstallTime
    val lastUpdateTime: Long       // NEW: from PackageInfo.lastUpdateTime
)
```

Both fields populated in `AppScanner.buildTelemetryForPackage()` directly from `PackageInfo`. Both are also exported in the `toFieldMap()` representation that SIGMA rules see, so atom rules can match on them.

### Room migration

Single migration (Migration 16→17, exact number depends on current schema state):

```sql
-- Add new columns
ALTER TABLE forensic_timeline ADD COLUMN endTimestamp INTEGER DEFAULT NULL;
ALTER TABLE forensic_timeline ADD COLUMN kind TEXT NOT NULL DEFAULT 'event';

-- Rename timestamp → startTimestamp (Room 2.4+ supports RENAME COLUMN)
ALTER TABLE forensic_timeline RENAME COLUMN timestamp TO startTimestamp;
```

Existing rows: `endTimestamp = NULL`, `kind = 'event'` (defaults handle the backfill).

No new tables.

---

## Correlation rule format

Rules use upstream SIGMA correlation grammar exactly as specified by SigmaHQ. Three supported types:

### `temporal_ordered`

```yaml
title: Sideloaded install followed by device admin grant
id: androdr-corr-001
status: production
correlation:
    type: temporal_ordered
    rules:
        - androdr-atom-package-install
        - androdr-atom-device-admin-grant
    timespan: 1h
    group-by:
        - package_name
display:
    category: correlation
    severity: high
    label: "Install then admin grant"
```

### `event_count`

```yaml
title: Surveillance permission burst
id: androdr-corr-004
status: production
correlation:
    type: event_count
    rules:
        - androdr-atom-permission-use
    timespan: 5m
    group-by:
        - package_name
    condition:
        gte: 3
    field_filter:
        permission_category: surveillance
display:
    category: correlation
    severity: high
    label: "Multiple surveillance permissions accessed rapidly"
```

### `temporal` (unordered all-fire)

Available for future rule authors; no migrations require it.

```yaml
correlation:
    type: temporal
    rules:
        - androdr-atom-A
        - androdr-atom-B
        - androdr-atom-C
    timespan: 30m
```

### Parser behavior

- Recognizes `correlation:` as a sibling of `detection:` at the rule top level.
- A rule has either `detection:` OR `correlation:`, never both.
- Validates `type` is one of the three supported values; otherwise raises `UnsupportedCorrelationTypeException` with the rule ID and the unsupported type.
- Validates `timespan` parses as a duration (`s`, `m`, `h`, `d` suffixes) and is ≤ 90 days; otherwise raises `CorrelationTimespanExceededException`.
- Validates every ID in `rules:` resolves to a loaded atom rule; otherwise raises `UnresolvedCorrelationRuleException`.

---

## Atom rules

Authored as thin SIGMA detection rules in `app/src/main/res/raw/`:

- `sigma_androdr_atom_package_install.yml` — matches `category: package_install`
- `sigma_androdr_atom_device_admin_grant.yml` — matches `category: device_admin_grant` (no current emitter; see Deferred items)
- `sigma_androdr_atom_permission_use.yml` — matches `category: permission_use` (AppOps usage events)
- `sigma_androdr_atom_dns_lookup.yml` — matches `category: ioc_match` (DNS IOC hits recorded by TimelineAdapter)

Example:

```yaml
title: Atom — package install event
id: androdr-atom-package-install
status: production
description: Internal atom rule. Matches raw package install events for use by correlation rules. Not rendered as a standalone finding.
author: AndroDR
date: 2026-04-08
logsource:
    product: androdr
    service: timeline
detection:
    selection:
        event_type: package_install
    condition: selection
level: informational
display:
    suppress_finding: true
```

`level: informational` plus `display.suppress_finding: true` keep these out of the findings UI. Correlations reference them by ID.

---

## Migration of hardcoded patterns

| Hardcoded method | Replaces with | Type | Window | Min count |
|---|---|---|---|---|
| `detectInstallThenAdmin` | `androdr-corr-001` | `temporal_ordered` | 1h | n/a |
| `detectInstallThenPermission` | `androdr-corr-002` | `temporal_ordered` | 1h | n/a |
| `detectPermissionThenC2` | `androdr-corr-003` | `temporal_ordered` | 30m | n/a |
| `detectMultiPermissionBurst` | `androdr-corr-004` | `event_count` | 5m | gte: 3 |
| `detectGenericTemporal` | **DROPPED** | — | — | — |

`detectGenericTemporal` had no real semantic — it was a "any N events of same category within gap" fallback with no threat-model basis. Dropped, not migrated.

`CorrelationEngine.kt` is deleted entirely after migration. The Timeline UI reads correlation signals directly from the timeline DB.

---

## Install-time signal

### Runtime path

`AppScanner.buildTelemetryForPackage()` reads `pkg.firstInstallTime` and `pkg.lastUpdateTime` from `PackageInfo` (already fetched). Both go into `AppTelemetry`.

`InstallEventEmitter` (new component, called from `ScanOrchestrator`):
- On the first scan ever (or when no prior `package_install` rows exist for a package), emits one `ForensicTimelineEvent` per scanned package with:
  - `kind = "event"`
  - `category = "package_install"`
  - `startTimestamp = firstInstallTime`
  - `matchContext.package_name`, `matchContext.event_type = "package_install"`
- On subsequent scans, queries `forensic_timeline WHERE category = 'package_install'` to find packages already emitted, and only emits for *new* packages (delta).

### Bug-report path

`InstallTimeModule : BugreportModule` parses the `package` section of `dumpsys package` output:

```
Package [com.example.app] (...):
  ...
  firstInstallTime=2024-03-15 14:23:01
  lastUpdateTime=2024-03-20 09:11:45
```

Emits `package_install` timeline rows analogous to the runtime path. Bug-report path always emits all parsed install events (no delta detection — bug reports are point-in-time snapshots).

---

## Deferred items (intentionally)

These are documented here so future-you doesn't re-derive the gap:

- **`value_count` correlation type** — no consumer in the four migrations. Add when first real use case appears. Parser will reject with a clear error until then.
- **Nested correlations** (correlation referencing another correlation) — same reasoning.
- **Multi-field `group-by`** — current migrations only need single-field grouping. Parser supports `group-by:` as a list but only uses the first element.
- **`condition.lt` and `condition.eq`** — `event_count` migration only needs `gte`. Other operators rejected at parse time.
- **Cross-scan correlation lookback beyond 90 days** — capped intentionally; correlations beyond a month are likely the wrong feature shape.

### Open issues

- **`device_admin_grant` atom has no current emitter** — The atom rule parses and loads, but no code writes `forensic_timeline` rows with `category = "device_admin_grant"`. As a result, `androdr-corr-001` (install-then-admin) will not fire on real events until an emitter is added. Tracked in [issue #79](https://github.com/yasirhamza/AndroDR/issues/79).

---

## Testing

### Unit tests

- **`SigmaCorrelationEngineTest`** — one test per correlation type asserting positive and negative match cases on synthetic event lists.
- **Per-rule behavioral equivalence tests** — for each migrated rule (corr-001 through corr-004), assert it produces identical clusters to the deleted Kotlin original on the same event fixtures. This is the regression net for the migration.
- **`SigmaRuleParserCorrelationTest`** — parse success for valid rules, parse rejection for `value_count`, nested, `timespan > 30d`, unresolved atom IDs.
- **`InstallTimeModuleTest`** — parsing edge cases: missing `lastUpdateTime`, malformed timestamps, packages with only `firstInstallTime`.
- **`InstallEventEmitterTest`** — first scan emits all packages, second scan with no new installs emits zero, second scan with one new install emits one.

### On-device verification

- Runtime scan on a real device produces `package_install` timeline rows for all installed packages, with real install dates going back years.
- A subsequent runtime scan emits **zero** new install rows (delta detection working).
- Sideloading a test APK and re-running the scan emits exactly one new install row.
- Granting device admin to a freshly sideloaded test app within an hour fires `androdr-corr-001` and a `kind = "signal"` row appears in the timeline with both member event IDs in `matchContext`.
- Bug-report analysis produces install rows from a captured bug report.
- The deleted `CorrelationEngine.kt` and its tests are removed without breaking any other module.

### Detekt + lint

- New components stay under existing complexity caps.
- No new hardcoded threat patterns in Kotlin (would defeat the sprint).

---

## Risks and mitigations

| Risk | Mitigation |
|---|---|
| Migration of `forensic_timeline` schema breaks existing user data | Additive columns + Room `RENAME COLUMN` is well-tested. Migration test required. |
| Behavioral equivalence between Kotlin and YAML versions of correlations might drift | Per-rule equivalence tests on shared fixtures pin behavior at migration time. |
| Per-rule timeline queries multiply DB load on scan completion | Index on `(category, startTimestamp)` already exists; queries are O(log N) per rule. Worst case at 30 rules × 90-day window = 30 indexed range scans. Re-measure on-device once the engine is wired up; if total exceeds ~150 ms, batch into a single union query. |
| Atom rules show up in the findings UI by accident | `level: informational` is already filtered out by `findingsViewModel`. Verified during implementation. |
| Install-event delta detection misses packages installed *during* a scan | Acceptable — they show up on the next scan. The race window is seconds. |
| Cluster signals duplicate on re-scan if the same correlation fires again | Dedup by `(rule_id, member_event_ids)` in `InstallEventEmitter`-equivalent for correlations: skip insert if a signal with the same rule + identical member set already exists. |

---

## Out of scope for this sprint (filed separately)

- Rule 011/014 interaction fix — already addressed in [#78](https://github.com/yasirhamza/AndroDR/issues/78).
- Package monitor (cross-scan install/uninstall monitoring as a continuous WorkManager job) — tracked in post-RC priorities.
- UI redesign of cluster expansion — current `CorrelationClusterCard` is sufficient.

## References

- [SigmaHQ Correlations spec](https://github.com/SigmaHQ/sigma-specification/blob/main/specification/sigma-correlation-rules-specification.md)
- `app/src/main/java/com/androdr/ui/timeline/CorrelationEngine.kt` (to be deleted)
- `app/src/main/java/com/androdr/sigma/SigmaRuleEngine.kt` (gains correlation evaluator)
- `app/src/main/java/com/androdr/scanner/AppScanner.kt` (`buildTelemetryForPackage`)
- `app/src/main/java/com/androdr/data/model/ForensicTimelineEvent.kt` (model change)
- `docs/research/2026-03-31-stix2-ioc-model-research.md` (cert-allowlist dead-end context, referenced in Q5 of brainstorming)
