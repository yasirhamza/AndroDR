# Telemetry Store, Uncapped Timeline, Finding Lifecycle, and the Telemetry Vocabulary — Design

**Date:** 2026-10-22
**Status:** Design approved in-session (all decisions closed 2026-10-22);
revised after plan-gate rounds 1–7 (2026-10-22). Plan gate and implementation are coordinated by a
separate session (Opus), not the session that wrote this document.
**Depends on:** `docs/superpowers/specs/2026-04-09-unified-telemetry-findings-refactor-design.md`
(§4 facts-first naming, provenance as a field); the rule-repo
`validation/logsource-taxonomy.yml` (field-map shape, `raw_fact`/`judgment` grading).
**Related:** #353 (export window vs. persisted-row budget), #137 (machine-readable
telemetry schema), #342 (intrusion-log import; introduced the persistence caps).

## 1. Background and motivation

AndroDR collects a great deal and keeps very little. On the maintainer's test
device (SM-F916B, 438 packages, 11 user apps, no SIM) the on-device database
is 86 MB; 81 MB of that is the IOC indicator table (697,313 rows). The entire
forensic timeline is 92 KB — 466 rows across four scans, 414 of which are the
one-time `package_install` backfill from the first scan. The three later scans
contributed 6, 6 and 31 rows.

Tracing every writer and reader (session of 2026-10-22) found the reasons:

1. **Only a thin slice of a scan is ever persisted.** `ScanOrchestrator.runFullScan`
   writes triggered findings, once-ever install and device-admin rows, 24 h of
   usage transitions (user apps only, *replaced* on every scan), and DNS IOC
   hits. The complete record sets the scanners produce — app inventory, app-ops,
   receivers, processes, accessibility services, file-artifact checks, device
   posture — go to the rule engine and are then discarded, except for a
   process-lifetime cache (`ScanOrchestrator.last*Telemetry`).
2. **The report reads that cache.** `ReportExporter` fills the TELEMETRY
   sections from `last*Telemetry`. A report for any scan but the most recent,
   or after the process restarted, has silently empty telemetry sections. A
   report for a bug-report or intrusion-log import shows the *live device's*
   cached telemetry under the import's heading — wrong provenance. There is a
   **second report path**: `HistoryViewModel` (line ~90) calls
   `ReportFormatter.formatScanReport` directly with `lastAppTelemetry`,
   `dnsEventDao.getRecentSnapshot()` and its own `INTRUSION_ROW_LIMIT = 500`.
   `BugReportViewModel` (line ~167) and `ScanOrchestrator.analyzeBugReport`
   (lines ~544–575) also read `lastAppTelemetry`, for APK-hash and
   display-name enrichment of import rows.
3. **Bug-report imports throw away ten modules' telemetry.** Only four of
   fourteen modules emit timeline rows; the typed records of the other ten
   (tombstones, wakelocks, platform-compat, db-info, accessibility, activity,
   receivers, …) exist only as `List<Map<String, Any?>>` on the way into the
   rule engine (`BugreportModule.kt:16`).
4. **Persistence caps bound what an import keeps**: 1,000 findings, 10,000 DNS,
   5,000 connect, 5,000 security rows (`ScanOrchestrator.kt:1024–1048`). They
   were added in #342 because `ScanResult.findings` is one JSON TEXT column
   read in full for every history row, and Room's `CursorWindow` fails on a
   row over ~2 MB. The maintainer did not intend any cap: *"That seriously
   reduces the fidelity of a scanning and telemetry tool."*
5. **The readers cap again.** The Timeline tab reads `getRecentEvents(limit = 500)`
   over the whole table with no "showing N of M" indicator; the report embeds
   ≤ 500 intrusion-log rows; the timeline export is `LIMIT 10000` oldest-first
   while one import may legitimately write 21,000 rows (#353). The History
   list is `LIMIT 50`. A live scan evaluates DNS against
   `DnsEventDao.getRecentSnapshot()` = the newest 500 DNS events with no scan
   boundary — a cap on what the rules *see*, not only on what is kept.
6. **Events are re-collected and re-stored.** Nothing remembers where the
   previous scan stopped: usage stats re-pull 24 h every scan (and the save
   deletes the previous window), DNS re-evaluates the same newest 500. A
   finding on a DNS event therefore re-fires on every scan while the event
   stays in the window, and never fires if the event has already scrolled out.
7. **"Telemetry" means three things.** In the scanner layer it is a typed
   record; `TelemetrySource` is actually provenance; in the Timeline UI the
   "Hide informational telemetry" switch governs *timeline rows not derived
   from a finding* — which, given (1), is almost nothing.

### 1.1 What keeping everything costs — on a real phone

The test device understates volume badly (no SIM, 11 user apps, zero usage
events in 24 h). The estimate below is for a heavy daily-use phone: ~650
packages (200+ user apps), 2–4k foreground/background transitions a day,
5–20k DNS resolutions a day, Android 16 intrusion logging switched on.
Compression ratio anchor: `dumpsys package` from the test device (6.6 MB)
gzips 7.2×; permission-string-heavy JSON does the same or better.

| Unit | Records | Raw |
|---|---|---|
| Daily live scan — snapshots (apps 650 × ~3.5 KB, app-ops ~1.5k, receivers ~1k, rest) | ~3k | ~2.7 MB |
| Daily live scan — usage events, 24 h | 2–4k | 0.4–0.8 MB |
| Daily live scan — DNS events since previous scan | 5–20k | 0.75–3 MB |
| Weekly intrusion-log import (DNS 50–150k, connect 100–300k, security few k) | 200–450k | 50–110 MB |

Twenty daily scans plus four weekly imports, by storage layout:

| Layout | Snapshots | Live events | Imports | Total |
|---|---|---|---|---|
| SQLite rows, plain JSON | 54 MB | 25–75 MB | 200–440 MB | 280–570 MB |
| + content-hash dedup of snapshot bodies (daily churn ≈ 10 %) | ~8 MB | 25–75 MB | 200–440 MB | 230–520 MB |
| + Deflate-with-dictionary on event bodies (~5×) | ~8 MB | 5–15 MB | 40–90 MB | **55–115 MB** |
| (reference) gzip JSONL files, ~7× | — | — | — | ~45–90 MB |

These figures are bodies only. Per-event row and index overhead (fact row,
observation row, three indexed 16-byte keys) adds roughly 120–150 B per
event — about 30–65 MB per weekly import at the volumes above — so the
realistic total for the compressed layout is **~150–380 MB**, still bounded
by the user's retention and import choices and shown in Settings. The
release battery measures the real factor (§5.2).

Two conclusions drove the design: **event volume, not snapshot volume,
dominates on a real phone**, and the parser's 200,000-records-per-type bound
is one week of a real intrusion log, not a theoretical ceiling. Serialize +
compress of a few MB on a phone is well under a second; disk at the chosen
layout is comparable to the IOC table the app already carries. The
constraints are the 2 MB cursor row limit, the 500-row reads, duplicate
storage of events, and the vocabulary.

## 2. Goals, non-goals, anti-goals

**Goals**

- G1. Every telemetry record a scan or import produces is persisted, complete
  and unmodified, and can be read back for that scan — by the report, by the
  UI, by export, and by queries across scans.
- G2. No persistence cap anywhere in the scan → store → timeline path. Bounds
  are retention policies the user can see, never silent truncation.
- G3. The report for scan *X* describes scan *X* and nothing else.
- G4. The Timeline shows every timeline event, paged; it never hides rows
  without saying so.
- G5. One precise vocabulary — *telemetry record* (snapshot or event),
  *timeline event*, *finding* — used identically in code, UI text, docs, and
  the rule taxonomy; enforced by a gate.
- G6. A finding can be walked back to the exact record it matched.
- G7. **A fact is stored once.** A live event is collected by exactly one
  scan; an unchanged snapshot is one fact however many scans observe it; an
  imported event two exports both contain is one fact, observed by both.
- G8. Findings follow an alert lifecycle: a finding on state clears when the
  state clears; a finding on an event stays open until a person closes it.

**Non-goals**

- No new live emitters; no new *detection*. (The taxonomy does gain entries
  for emitters that already exist, §4.2.)
- No differential rules (snapshot-vs-snapshot detection) in this design; the
  store makes them a pure query later.
- No cloud or off-device storage; no change to the 12 h IOC/rule fetch.
- No new native library, no new SQLite build. Compression and dedup use what
  the platform ships (`java.util.zip`, SQLite JSON1).
- IP filtering remains parked (ARCHITECTURE §11 D3).

**Anti-goals** (would make this a failure even if it technically works)

- Reintroducing a cap "for safety" anywhere in the path.
- Putting large blobs back into `ScanResult` or any row a list query reads.
- A stored record that differs from what the rule engine evaluated.
- Storing the same event twice (once as a record, once as a timeline row).
- A bound that silently drops evidence; storage protection refuses visibly
  instead (§5.2).
- Source-named types or fields (`BugReportX`, `ImportedY`) — spec 2026-04-09 §4.

## 3. Vocabulary (normative)

These definitions are the contract. ARCHITECTURE.md gains a glossary section
containing them verbatim; a build gate (§9, V1) enforces the retired phrases.

| Term | Definition |
|---|---|
| **Telemetry record** | A typed fact an emitter produced, exactly as produced, before any rule saw it. Source-agnostic; provenance belongs to the observation. Every record is one of two time-shapes, decided per record (§4.3). |
| **Snapshot record** | State observed *at scan time*: app inventory, live app-ops grants, receivers, processes, accessibility services, file-artifact checks, device posture, system properties, database-path observations, platform-compat changes, ADB trusted keys, and any record whose service declares no event-time field or whose value for it is absent. |
| **Event record** | Something that happened at a time *T* the record carries: usage transitions, DNS queries, connections, security-log events, tombstones, wakelock acquisitions, package install history, bug-report app-ops accesses, battery-daily package events. An event's time has a precision (`exact` or `day`). |
| **Fact** | One distinct telemetry record, stored once however many scans or imports observed it (§5.1). |
| **Observation** | One scan's or import's sighting of a fact, at a position in that scan's emitted list. Provenance and capture time belong to the observation. |
| **Timeline event** | A timestamped row on the forensic timeline. Comes from (a) every event fact, read in place — never copied; (b) every triggered finding; (c) correlation signals; (d) detected changes (first-seen install, first-seen device-admin grant, live DNS IOC match, alert closure). **Snapshot records never become timeline events.** |
| **Finding** | Rule output in one scan (`Finding`), referencing the observation it matched. A finding on an event record belongs to an **alert**; every other finding — on a snapshot record, or a correlation finding — is a **state finding**. |
| **Alert** | The lasting record of an incident: opened by the first finding with its identity, kept across scans, closed only by a person (§5.4). |
| **Provenance** | Where an observation came from: `TelemetrySource` (`LIVE_SCAN`, `BUGREPORT_IMPORT`, `INTRUSION_LOG_IMPORT`). It is not a kind of telemetry. |
| **Watermark** | Per live event service, the position up to which live events have been collected. The next scan collects from it. |

**Retired phrases.** "Raw telemetry" — every telemetry record is raw by
definition; the `raw_fact`/`judgment` grading lives at the field level in the
taxonomy. "Informational telemetry" — the UI switch meant "timeline events not
referenced by a finding" and will say so. The bug-report `TimelineEvent`
class — a source-shaped, untyped row — is retired (§5.3).

Field-level naming keeps the taxonomy's `snake_case`.

## 4. Architecture

```
emitter ─▶ ChunkedScanWriter session:  begin(scan: IN_PROGRESS)
              append(service, chunk ≤ 5,000):
                 SigmaRuleEngine.evaluateRecords(chunk)  (same maps, same ordinals; before the transaction)
                 then one transaction:
                 ├─▶ record_body ◀ telemetry_record (fact) ◀ scan_record (observation)
                 └─▶ scan_finding rows for newly observed ordinals (alertKey only)
              finish():  one finishing transaction —
                         timeline rows → atoms → correlate → signals →
                         alerts (set-based + correlation) → summary, COMPLETE, watermarks

Timeline = keyset-paged UNION(event facts of COMPLETE scans, forensic_timeline rows)
Report (streamed) · Telemetry browser · JSONL export · cross-scan history / diff
```

Persistence surfaces:

- **Schema 19 (Phase A)**:
  - New tables: `record_body`, `telemetry_record`, `scan_record` (content, facts, observations — §5.1); `event_watermark` (§5.2); `signal_member` (correlation-signal members, §5.4).
  - New `forensic_timeline` columns: `recordId`, `sourceEventKey` (h128 BLOB, the same hash as `telemetry_record.sourceKey`), `level`, `persistent` (default 0). New `ScanResult` columns: `state` (`IN_PROGRESS` | `COMPLETE` | `DELETING`, default `COMPLETE`), `telemetryState` (`NONE` | `STORED` | `PARTIAL_RETENTION` | `FAILED`). The migration backfills `level` on legacy finding rows from `ScanResult.findings` by (`scanResultId`, `ruleId`). It uses the same chunked `substr` reader as 19→20, so an oversized or corrupt row leaves `level` null and never aborts the upgrade.
  - Composite indices: §5.1 and §6.
- **Schema 20 (Phase D)**: `scan_finding`, `alert` (§5.4); `ScanResult` loses `findings`.
- **`forensic_timeline`** keeps only finding rows, correlation signals, detected changes, and audit and closure rows.
  - Rows that outlive their scan *by nature* carry `persistent = 1`: closure, audit and "import interrupted" rows.
  - `scanResultId = -1` keeps its existing meaning ("no owning scan") and is not a retention marker.

### 4.1 One list, evaluated and stored

Each emitter's output is projected to field maps **once** and handed to the
writer session chunk by chunk (`append(service, source, capturedAt, chunk)`).
The session keeps a next-ordinal and an `OccurrenceCounter` per service. Within
each chunk, the same maps are first evaluated, before the chunk's write
transaction, so the write lock is held only for the inserts. They are then
persisted. Only ordinals **newly observed in this scan** keep their findings.
An exact duplicate the store drops, or a live **event** fact an earlier scan
already observed, contributes no finding — the same guarantee the parser's
duplicate set used to give. Unchanged snapshot facts get a new observation every
scan and keep producing their state findings. In evaluate-only mode (§5.2),
where nothing is persisted, a bounded in-memory key set (200,000 64-bit fact-key prefixes in an `androidx.collection.MutableLongSet`, about 3 MB)
gives the same deduplication; beyond it, a duplicate may produce a second
finding — a documented residual, never a lost one. Evaluation goes through
`SigmaRuleEngine.evaluateRecords(service, chunk, firstOrdinal)`; the typed
`evaluate*` methods delegate to it. A finding carries the ordinal of its
record. Engine-side pre-filters (today: `file_scanner` skips inaccessible
paths) keep the original index. Stored equals evaluated by construction, and a
gate requires writers to evaluate only through the session. `ServiceRecords`
(a one-shot `Sequence`, `constrainOnce()`) is a convenience that appends a
whole sequence to a session.

Records are stored as their `toFieldMap()` projection.

**Field-map completeness.** A field map carries every fact its data class holds. Two gaps close as positive-only fields:
- `FileArtifactTelemetry.accessible` → `accessible`
- `ImportedDnsEvent.resolvedIps` → `dns_monitor.resolved_ips`

A gate compares each telemetry class's constructor properties with its field-map keys.

**Envelope keys.**
- `source` and `captured_at` are stripped before hashing only when equal to the observation's values. The observation records which keys it stripped (`strippedKeys`), and decode restores exactly those.
- Content values (`"bugreport_import"`, `"adb_trusted_key"`) stay in the body.
- The decoded map equals the evaluated map.

Services covered: every emitter output — each typed `evaluate*`, the generic bug-report path, `usage_stats`, `system_property`.

### 4.2 Taxonomy (Phase 0, before anything is stored)

Decided by the maintainer on 2026-10-22:
- `dbinfo_audit` / `platform_compat_audit` collapse into `db_info` / `platform_compat`.
- `adb_audit`, `activity_audit`, `usage_stats`, `system_property` are documented emitter services with no rules.

The rules-repo change adds, per service:
- **`status: emitter_only`** for `usage_stats` and `system_property`. `validate-rule.py` already rejects rules on non-active services outside `staging/`.
- **`event_time_field`** on `usage_stats`, `dns_monitor`, `network_monitor`, `security_log`, `appops_audit` (`event_time_ms`), `tombstone_parser` (`crash_timestamp`), `wakelock_parser` (`acquired_at`), `battery_daily` (`timestamp`) and `package_install_history` (`timestamp`). Not on `db_info`.
- **`time_precision_field`**: `battery_daily: timestamp_precision`.
- **`key_fields`** on every snapshot-capable service.
- **`package_field`**: `package_name`; `source_package` for `dns_monitor`; `app_name` for `network_monitor`; and so on.
- **`optional: true`** on fields only some producers set (`appops_audit.event_time_ms`). Optional implies positive-only.
- **`positive_only: true`** on every field old binaries lack: `dns_monitor.timestamp`, `dns_monitor.resolved_ips`, `file_scanner.accessible`, `appops_audit.event_time_ms`, `battery_daily.timestamp`, `battery_daily.timestamp_precision`, `db_info.db_path`, `db_info.recent_query_count`, `requested_permissions`, `has_boot_receiver`. `validate-rule.py`'s negation guard is generalised to all of them.
- **Field entries** for the typed bug-report records' new facts (§5.3).

It follows CLAUDE.md safe ordering and lands before the store.

### 4.3 One contract object; categories are a detection contract

`TaxonomyContract` (Kotlin, `sigma/`) is the single Kotlin mirror of the
taxonomy facts the store needs: event-time field, precision field, key fields,
package field, field order and descriptions. It has one cross-check test, both
directions. The set of live event services is derived from it, together with
the watermark registry; no other list exists.

A record is an **event record iff its service declares an `event_time_field`
and the record's value is present and > 0**.

**Timeline categories** (`TimelineCategories`) preserve today's values exactly:

| Service | Category |
|---|---|
| `usage_stats` | the record's `event_type` |
| `appops_audit` | `permission_use` |
| `package_install_history` | `package_install` |
| `battery_daily` | the record's `event_type` |
| `network_monitor` | `network_connect` |
| `security_log` | `security_event` |
| `dns_monitor` | `ioc_match` when `reason` is set, else `dns_query` |
| `tombstone_parser`, `wakelock_parser` | the service name |

Gate K1: every atom-bound category has a producer. Only facts with `exact` time
precision become correlation atoms.

**Computed columns** (`subjectKey`, `category`, `packageName`, `timePrecision`,
`eventTime`) are pinned by a contract hash. The hash covers the contract table
*and* the outputs of `TimelineCategories.categoryOf` and the precision logic
over a fixed corpus of sample records. It maps to the schema version that last
recomputed those columns, so any change fails the build until a recompute
migration exists.

## 5. Persistence

### 5.1 Content, facts, observations

Hashes are 16-byte BLOBs (SHA-256 truncated to 128 bits). Map lookups on them
wrap the bytes (`ByteBuffer.wrap`), never use raw `ByteArray` keys.

- **`record_body`**:
  - `hash` BLOB PK
  - `encoding` (0 plain JSON, 1 Deflate with preset dictionary)
  - `dictVersion`
  - `body` BLOB
  - `rawBytes`
- **`telemetry_record`** (fact):
  - columns: `id` PK AUTOINCREMENT, `service`, `factKey` BLOB, `sourceKey` BLOB (nullable, = `h128` of the source-supplied key), `subjectKey`, `eventTime`, `timePrecision`, `category`, `packageName`, `bodyHash` BLOB
  - indices: unique `(service, factKey)`; `(service, subjectKey)`; `(packageName, eventTime)`; `eventTime`; `sourceKey`; `bodyHash`
- **`scan_record`** (observation):
  - columns: `scanId`, `service`, `ordinal` (PK `(scanId, service, ordinal)`); `recordId`; `eventTime` (copied from the fact for ordered scan-filtered reads); `source`; `capturedAt`; `strippedKeys`
  - indices: unique `(scanId, recordId)`; `recordId`; `(scanId, eventTime)`

**Fact identity (`factKey`).**
- With a source key, the fact key is `H("src:" + key + "#" + bodyHash)`: identity *and* content. Source keys:
  - live DNS: `dns:<DnsEvent.id>`
  - intrusion-log records with an id: `"$type $event_id $event_time"`
  - intrusion-log records without an id: `"$type ? $event_time"`
- Otherwise the fact key is `H(bodyHash + "#" + n)`, where `n` is the occurrence index of that content within the service's emitted list. It is counted in a primitive long → int map (`androidx.collection.MutableLongIntMap`) on a 64-bit hash prefix; a prefix collision only bumps a counter.

**Observations.**
- Unique `(scanId, recordId)`: an exact duplicate record within one scan is dropped and counted. This replaces the parser's in-memory set.
- A live event fact already observed by an earlier live scan gets no new observation.
- Imports always observe what they contain.

**Write order** per chunk is bodies → facts → observations, each `INSERT OR IGNORE`. Ids of existing facts are looked up by `(service, factKey)`. List-parameter `@Query` calls go through `chunkedIn(≤ 900)`.

**Visibility.**
- Every read of facts or observations (Timeline, browser, report, export, history, diff, storage sums) shows a fact only if one of these holds:
  - it has an observation whose scan is `COMPLETE`; or
  - it has **no observation at all and is pinned** (§5.1 Pins) — evidence behind a finding or alert whose observations retention or deletion removed stays readable. An unpinned orphan is never visible. The pin test is one shared SQL fragment, used by both the readers and `deleteUnobservedUnpinned`.
- Every read of `scan_finding` requires its scan to be `COMPLETE`. A `forensic_timeline` row is visible when it is persistent, has `scanResultId = -1`, or belongs to a `COMPLETE` scan (one shared fragment, `VisibleRow.SQL`).
- A SQL source gate enforces all three rules.
- Paging sources observe `ScanResult`, `forensic_timeline` and `alert`, not the store tables. Store data becomes visible only when a scan completes or is deleted, so chunk commits cause no invalidation storms.

**Delete.**
- Deleting a scan starts with **one transaction** that writes the persistent audit row (built from the scan's triggered `scan_finding` rows, §5.4) **and** sets `state = DELETING`, which hides the scan like `IN_PROGRESS`. The audit therefore exists before anything is removed and survives a force-stop; the sweep never needs to write it.
- Then the scan's own signal rows (with their `signal_member` rows), its `scan_finding` rows and its other non-persistent `forensic_timeline` rows are deleted. Another scan's signal that listed one of these rows as a member shows the members that remain, exactly as today's cluster builder does.
- Then, by keyset on the observation PK, **each batch is one transaction**: delete the batch's observations, then the batch's candidate facts that now have no observation and no pin, then bodies left unreferenced.
- The `ScanResult` row is deleted last.
- Retention batches follow the same rule: no batch can leave an unpinned fact with no observation.
- A crash at any point is completed by the startup sweep, which resumes `DELETING` scans.

**Pins.** No delete path removes a fact, or a `forensic_timeline` row, while it is referenced by any of:
- a triggered `scan_finding.recordId` (facts)
- an `alert.recordId` (facts)
- a `signal_member` fact ref
- a `forensic_timeline.recordId` (facts)

Covered paths: scan deletion, "Clear all", retention and the prune. References are plain indexed columns (no FK).

**Compression.**
- Event bodies use Deflate with a per-service-family preset dictionary of ≤ 4 KiB. Snapshot bodies are plain JSON.
- Dictionaries are shipped in `res/raw/` and are **immutable**: pinned by SHA-256, a new builder output needs a new `dictVersion`, and decode selects by `dictVersion`.
- The writer owns one `Deflater` per chunk (`setDictionary` after each `reset()`, `end()` after). `decode` uses its own `Inflater`.
- Any decode failure, or inflation past `rawBytes`, yields an unreadable placeholder.
- A test checks each event body's zlib header carries the dictionary flag and the dictionary's Adler-32.

**Cross-scan reads.** `history(service, subjectKey)`, `changedBetween(scanA, scanB, service)`.

**Retention** (Phase D, after finding pins exist; my call):
- **Snapshot observations** are kept for the newest N live scans (default 20).
- **Live event observations** are kept for 30 days.
- **Import observations** are kept until the user deletes the import.
- **Pinned facts** are always kept.
- A scan that loses any observations becomes `PARTIAL_RETENTION`.
- Retention runs in `IocUpdateWorker` after the IOC fetch, under `scanMutex.tryLock()` (it is skipped this cycle if a scan or import holds the lock), in keyset batches.

### 5.2 Writers, watermarks, failure handling

**Session.**
1. `begin` inserts the `ScanResult` with `state = IN_PROGRESS`.
2. Each `append` evaluates the chunk first. It then runs one transaction: persist the chunk, then write `scan_finding` rows for the newly observed ordinals.
   - These rows carry `alertKey` only; no alerts are created yet.
   - Nothing is written to `forensic_timeline` during `append`.
3. Before each `append` on an import, `StatFs` free space is checked against a fixed **150 MB reserve that nothing overrides**.
   - When the reserve is breached, the import stops storing telemetry and **finishes evaluate-only**: findings are kept with their `matchContext`, `telemetryState = FAILED`, and the import card says how much space to free.
4. Before `finish`, the 150 MB reserve is checked once more. The finishing transaction's growth — mostly the finding-row copy, about 10–20 MB per 100k findings — fits inside the reserve.
5. `finish` opens **the session's single finishing transaction**, which does the following in order (as today's `saveScanWithCorrelation` does):
   - Writes this scan's `forensic_timeline` rows, so they have ids:
     - detected changes (first-seen install, device-admin grant);
     - finding rows — in Phases A–C, after sweeping prior intrusion-log imports (excluding this scan), from the top-K and the newest-N heaps, which also hold the interim event rows; in Phase D, `INSERT … SELECT` from `scan_finding`.
   - Reads correlation atoms, inside the transaction, so this scan's just-written rows are `Row(id)` atoms with real ids.
   - Runs the correlator. Each (rule, group) has its own step/time budget (default 2 s, checked by a deadline test that returns normally — never a `CancellationException` inside the transaction; the clock is injected so tests force the cut-off). Before the nested loops each group is filtered to atoms matching one of the rule's steps, and the largest groups run last. Signals of rules that completed are kept; an unfinished (rule, group) records `NotEvaluatedReason.CORRELATION_INCOMPLETE` with the rule and package (excluded from `realFailureCount`), shown in the report and on the dashboard — never a silent truncation.
   - Writes signals and `signal_member` rows.
   - Creates alerts **set-based** from this scan's `scan_finding.alertKey` values (§5.4); correlation findings are state findings and create no alert. Post-condition: no `scan_finding` row with an `alertKey` is left unattached.
   - Writes summary columns, sets `state = COMPLETE` and `telemetryState`, and advances the watermarks.

   Every helper it calls is transaction-agnostic. Atoms are bounded to atom-bound categories and each (rule, group) is budgeted, so a dense group cannot stall the transaction indefinitely. Target: `finish` ≤ 2 s on the F916B for a 100k-finding import, asserted in the release battery.

Failure handling:
- A failed writer deletes its scan inside `withContext(NonCancellable)`, through an unaudited cleanup delete.
- On startup, `StartupSweep`:
  - takes `scanMutex` only long enough to snapshot the `IN_PROGRESS` and `DELETING` ids;
  - deletes those scans (deletes are idempotent);
  - writes one persistent "import interrupted" row per swept `IN_PROGRESS` import, so an import that crashed the app is not silent (a resumed `DELETING` scan already has its audit row);
  - runs `gcUnobservedUnpinned` only when it found scans to sweep or the store's dirty flag is set (a DataStore boolean set by any delete or retention batch that fails part-way, cleared after a completed GC pass);
  - deletes stale report and export files.
- Nothing of a failed import is ever visible: no fact, finding, alert or Timeline row. This is the #342 B1 guarantee.
- Live scans and imports are serialised by `scanMutex`. Retention takes the lock per keyset batch with `tryLock`.

**Correlation inputs.**
- Atoms are restricted to the categories atom rules bind (the correlator's memory bound).
- Exact-precision facts only.
- Facts referenced by a `forensic_timeline` row (`recordId`, or `sourceKey` = the row's `sourceEventKey`) are excluded.
- For a live scan, lookback atoms are bounded to `timestamp ≤ scanStart` and exclude every import source.

**Interim, Phases A–C.** Until `scan_finding` exists (Phase D), findings go to the `ScanResult.findings` JSON column through a streaming top-K that keeps today's 1,000-finding cap (severity, then time). Until C3:
- intrusion-log and bug-report event rows still go to `forensic_timeline`, built from bounded newest-N heaps per type filled per chunk (today's caps);
- `deletePriorIntrusionLogRows` stays, deleting forensic rows only.

**Live enrichment.**
- `last*Telemetry` is deleted.
- Bug-report enrichment reads the latest live scan's `app_scanner` observations within `TelemetryReader.APP_ENRICHMENT_MAX_AGE_MS` (5 min), or collects fresh and discards.
- Enrichment data is never stored under an import.

**Replace-on-reimport is removed in C3**, when event rows leave `forensic_timeline`. The import card reports new facts, already-stored facts and dropped duplicates.

**Watermarks** (`event_watermark(service, position, scanId)`):
- **Live DNS**: position = `DnsEvent.id`, starting from the last 24 h.
- **Usage stats**: position = event time, re-read from `position − 5 min`. Usage access is checked explicitly; no access = collection failed.
- **Advancing**: a watermark advances on every committed scan whose collection did not fail, *including* when rules on that service were capability-skipped (the skip is recorded). It never moves past the scan start, and resets if it is ahead of `now`. It does not advance on the disk-full fallback.
- **Late-IOC re-check**: each live scan also re-evaluates the `dns_monitor` rules over stored live DNS facts from the trailing 24 h.
  - The facts are selected through `scan_record`: observations with source `LIVE_SCAN` of `COMPLETE` scans.
    - The current, still `IN_PROGRESS` scan's own facts are therefore excluded; they were already evaluated by `append`.
    - So are imported DNS facts, whatever their event time.
  - The facts are streamed in keyset chunks through `Session.evaluateStored(service, Sequence<(factId, record)>)`, and no new observations are written.
  - A re-check finding is emitted only when no alert with its record key (`recordKey(ruleId, factId, evidence)`) exists yet — alerts are permanent, so a fact that already fired never re-fires or re-surfaces its alert, even after the scan that first found it is deleted. (Phases A–C, before alerts exist: when no triggered finding for the same `(ruleId, recordId)` exists in a `COMPLETE` scan.)
  - Findings set `recordId = factId` directly, with `ordinal = -1`.
  - Today's behaviour is kept: a domain that becomes an IOC after it was queried still fires. Alert identity prevents duplicates.

**Storage protection (nothing is truncated silently).**
- **Import preflight**: every import is estimated from the archive's decompressed entry sizes × a measured stored-size factor (initial 0.6). Unknown or −1 sizes are shown as "unknown".
  - If free space after the estimate would be below `2 × estimate + 200 MB`, the user may cancel or **import anyway**.
  - The per-chunk 150 MB reserve still applies.
- **Input bounds**: the intrusion-log parser is bounded at 2,000,000 per type; bug-report modules at 200,000 records each (they still materialise per-module lists). Each bound is named on the import card when tripped.
- **Errors**: writers catch `Throwable`.
- **Live scan on `SQLiteFullException`**: the rest of the same pass continues evaluate-only.
  - Findings are buffered in memory; live findings are bounded by rules × live records.
  - `finish` writes them with `recordId = null` and `telemetryState = FAILED`. Watermarks are unchanged.
  - If that write fails too, the in-memory result is still shown, and a storage-health flag is recorded in DataStore, outside the database.
- **DNS logging failures**: `DnsLogBuffer` re-queues a failed batch, with exponential backoff and dropping the oldest beyond its bound, and records a health warning.

### 5.3 Typed bug-report records; `TimelineEvent` retired

Before any module's timeline rows are removed (C3), four modules emit typed
records that fill the `TelemetryBundle`, each emitting every fact it parses:

- **`InstallTimeModule`** → `PackageInstallHistoryEntry` (event, `package_install`).
- **`DbInfoModule`** → `DatabasePathObservation` with `db_path` and `recent_query_count` (snapshot). Its generic emission is deleted.
- **`PlatformCompatModule`** → `PlatformCompatChange` (snapshot). Its generic emission is deleted.
- **`BatteryDailyModule`** → `BatteryDailyEvent` for every parsed entry (install, update, uninstall, downgrade) with today's `event_type`. When the section yields a date, it also carries `timestamp` at day precision and `timestamp_precision = "day"`. Its IOC-only generic emission is deleted. A parity test compares old rows with new records.

Other module changes:
- **`WakelockParser`**: its time base becomes the bug report's own capture time, taken from its header.
- **`AdbKeysModule`**: its records are snapshots.

In C3, the hand-built `TimelineEvent` rows, `ModuleResult.timeline`, `BugReportAnalysisResult.timeline`, `TimelineFormatter` and `TimelineEvent.kt` are removed. At the same time, a one-time cleanup deletes legacy event rows.
- Rows are selected by **producer** — the `source` of the bug-report, intrusion-log and usage-stats event adapters — not by category. Live first-seen `package_install` and `device_admin_grant` detected-change rows therefore survive.
- The cleanup covers scans whose `telemetryState` is `STORED` or `PARTIAL_RETENTION`. Pre-feature (`NONE`) scans keep their rows, because those rows are their only record.

Interim event rows written in Phases A–C carry `recordId`, so correlation never counts the same event twice.

### 5.4 Findings, alerts, lifecycle

Schema 20 (Phase D).

**`scan_finding`** has one row per finding per scan, always inserted.
- **Columns**: `id`, `scanId`, `ruleId`, `triggered`, `level`, `category`, `kind` (`STATE` | `ALERT`), `recordId`, `service`, `ordinal`, `alertKey`, `alertId`, `findingJson`.
- **`findingJson`** omits `matchContext` only when `recordId` is set; correlation and pre-schema-19 findings keep it.
- **Untriggered findings** (safe-state rows) are stored only for snapshot services.
- **Indices**: `recordId`, `(scanId, alertKey)`.

**`alert`** has one row per incident.
- **Columns**: `id` PK AUTOINCREMENT, `alertKey` BLOB unique, `ruleId`, `status`, `openedAt`, `openedScanId`, `lastActivityAt`, `closedAt`, `closedReason`, `closedWithCredential`, `level`, `recordId`, `evidenceJson`.
  - `evidenceJson` is the **authoritative evidence record** of the alert: the opening finding, with its `matchContext`. The alert row, the report and "Matched record" read it, whatever happens to scans.
- **Indices**: `recordId`, `(ruleId, status)`.
- Attaching a finding to an alert updates `lastActivityAt` and re-surfaces the alert in the list.
- Alerts are never deleted. Their evidence is a permanent incident record and is counted in the Settings storage figure.

**`signal_member`** (`signalRowId`, `kind`, `refId`; indices `(kind, refId)`, `signalRowId`) records every correlation signal's members, from Phase C, and is deleted together with its signal row. It is the **only** store of member lists: signal `details`, `correlationId` and `matchContext` carry no id lists (`correlationId = ruleId:` + `h128` over the members sorted by `(kind, refId)`, each encoded `kind:id`; `matchContext` carries `member_count`), so no row grows with chain size. Existing signals' `member_event_ids` are moved into `signal_member` by a one-time backfill in Phase C. Readers load a signal's members on demand (`ClusterMembers.load(signalRowId)`: rows through the DAO, facts decoded through `TelemetryReader`).

**Kind**:
- `ALERT` iff the matched record is an event fact. Correlation findings are `STATE`.
- A finding with no `recordId` (evaluate-only fallback) is `ALERT` iff its `matchContext` holds the service's event-time field > 0, or the service is always-event (`dns_monitor`, `network_monitor`, `security_log`) — the same rule as the migration.
- Otherwise `STATE`.

**Alert identity**, set-based at `finish`:
- **Record finding**: `alertKey = H(ruleId | factId | evidenceDiscriminator)`, for triggered findings only. The discriminator is the evidence *type and matched value*, never IOC row ids or feed metadata, so it is stable across IOC re-sync.
- **Record finding without a fact** (evaluate-only fallback): `alertKey = H(ruleId | "nofact" | evidence type | matched value | event time from matchContext)`; when there is no event time, `scanId | ordinal` takes its place, so unrelated hits never collapse into one alert. A dashboard banner marks `FAILED` scans.
- **Correlation findings** are state findings of the scan that produced them, as today. Lasting correlation alerts are a recorded follow-up (`docs/superpowers/specs/2026-10-22-lasting-correlation-alerts-followup.md`; maintainer decision 2026-10-22).

**Lifecycle (maintainer decision, SOC pattern).**
- **State findings** are current while the latest live scan triggers them. Imports never displace live state.
- **Alerts** are current from opening until a person closes them.
- **Re-fires** attach findings to the existing alert. New facts open new alerts. A closed alert stays closed.
- **Current findings** = the latest live scan's triggered state findings ∪ OPEN alerts. The dashboard shows a count and a paged list, grouped by rule and matched value so a flood of one indicator cannot bury another.

**Closing an alert.**
- **Confirmation**: closing one alert, or a selection (**bulk close** under one confirmation), requires the device credential: platform `BiometricPrompt` with `DEVICE_CREDENTIAL` only on API 30+ (manifest `USE_BIOMETRIC`), and `KeyguardManager.createConfirmDeviceCredentialIntent` on API 26–29.
- **No secure lock screen**: `NoSecureLock` is returned only when `KeyguardManager.isDeviceSecure()` is false; any other error is `Cancelled`. The repository re-checks `isDeviceSecure()` before honouring `NoSecureLock` and records `closedWithCredential = false`.
- **Obscured touches**: the views set `filterTouchesWhenObscured = true` (`FLAG_WINDOW_IS_PARTIALLY_OBSCURED` exists only from API 29). Accessibility clicks bypass touch filtering; the credential is the real control.
- **Not protected**: a person who knows the PIN, or spyware that has logged it, can close alerts. This is documented as a residual risk.

**Deleting scans.**
- Deleting a scan or "Clear all" never deletes an alert, its evidence JSON or its pinned fact, so it needs no credential.
- Each deletion writes one persistent audit row, in the same transaction that marks the scan `DELETING` (§5.1). It summarises the deleted scan's triggered findings as distinct (rule, level, package) entries with counts, capped at 100 entries plus "and K more", so the row stays small.
- Persistent rows are exempt from the prune and from "Clear all".
- "Clear all" starts with **one transaction** that writes a single capped audit row (built from every `COMPLETE` scan's triggered `scan_finding` rows) and sets every scan `DELETING`; it then deletes scans, observations, `scan_finding` rows, and every non-persistent timeline row not referenced by a `signal_member` — including live `dns_query`/`ioc_match` rows with `scanResultId = -1`, as it does today.

**The report** lists state findings, open alerts (with the opening scan), and closed alerts (time, note, credential flag).

**Migration 19 → 20.**
- **Reading**: `findings` is read in 256 KB `substr` chunks. A corrupt row keeps its scan with zero findings. `ScanResult` is rebuilt as a new table, then copied and renamed, because API 26 has no `DROP COLUMN`.
- **Backfill**: `triggeredCount`, `maxLevel` and `forensic_timeline.level`.
- **Kind**:
  - findings carrying `recordId` (late-IOC re-checks) are resolved by it;
  - other schema-19 findings (with `service`/`ordinal`) are resolved per record through `scan_record`;
  - older findings are ALERT iff `matchContext` holds the event-time field > 0, or the service is always-event (`dns_monitor`, `network_monitor`, `security_log`);
  - unknown rule ids are STATE;
  - rule id → service comes from a frozen table.
- **Alerts**: created from the migrated findings. They are OPEN if their scan is within 30 days, otherwise CLOSED "migrated (older than 30 days)". They keep `matchContext`.

### 5.5 Caps removed

Removed in C3:
- `DNS_PERSIST_CAP`, `CONNECT_PERSIST_CAP`, `SECURITY_PERSIST_CAP` (including their `BugReportScreen` uses)
- the report's `take(500)`
- `HistoryViewModel.INTRUSION_ROW_LIMIT`
- the timeline DAO's `limit = 500` defaults
- `getAllForExport`'s `LIMIT 10000`
- `getRecentSnapshot()` as the scan DNS window

Removed in D2:
- `FINDINGS_PERSIST_CAP`
- `capTriggeredFindings`
- the caps log
- `getAllScans`'s `LIMIT 50`

Allow-listed permanently:
- `ScanResultDao.getLatestTwo`
- `IndicatorDao.lookup` (`LIMIT 1`)
- `DnsEventDao.getRecentEvents` / `getRecentSnapshot` (the DNS monitor screen)

### 5.6 Timeline rows

`forensic_timeline` keeps finding rows, signals, detected changes, and the
persistent audit, closure and "import interrupted" rows.

The 30-day prune applies to non-persistent `LIVE_SCAN` rows that no
`signal_member` row ref points at. This includes live
`ioc_match` rows, whatever their `scanResultId`. A pruned signal row takes its
`signal_member` rows with it, in the same transaction.

Phases A–D form one release train: no Play release ships between the A and D
merges, because retention arrives in D4.

## 6. Timeline

- **One keyset-paged query** in `TimelineDao`:
  - `UNION ALL` of event facts (visible per §5.1: a `COMPLETE` observation, or no observation and pinned; the scan filter uses `scan_record(scanId, eventTime)`) and `forensic_timeline` rows.
  - Ordered and keyed on `(time DESC, rowKind, id DESC)`.
  - A custom `PagingSource` with an inclusive refresh key at the anchor, prepend via a reverse-ordered query, and observation of `ScanResult`, `forensic_timeline` and `alert`.
  - One SQL builder per filter shape, with `COALESCE` for non-null columns in the fact branch.
  - A fact referenced by a `forensic_timeline` row is nested under that row.
- **Counts** appear on every group header and on the filter bar. Date groups use the device's zone.
- **Presentation (my calls):**
  - The severity filter is SQL on `level` (schema 19).
  - There is no cross-page roll-up.
  - Finding rows appear for every scan.
  - The pinned section shows current findings.
- **Switch renamed**: "Show findings and their evidence only". `TimelineRow.TelemetryRow` → `EventRow`.
- **Correlation** keys atoms by `AtomRef` (`Row(id)` | `Fact(id)`). Members are stored only in `signal_member`; `member_event_ids` is removed from signal details, and every former reader of it reads `signal_member` instead (gate: no `member_event_ids` left in `main`).
- **Navigation**:
  - "View telemetry" from History, scan headers and finding detail.
  - "Matched record" navigates by `recordId`.

## 7. Report and export

- **One report path.** All reports go through `ReportExporter`, streaming to a file `Writer`. The History sheet shows a summary.
- **Telemetry sections** read only the scan's own observations. When telemetry is missing, the report says why: `NONE`, `PARTIAL_RETENTION` or `FAILED`.
- **Escaping.**
  - Device-controlled strings, field keys, and values nested in lists and maps are escaped: `\` and every character in Unicode categories Cc, Cf, Zl, Zp, Co, Cn and Cs (lone surrogates) is rendered as `\uXXXX`.
  - So no value can emit a raw line break, a bidi override, or an ambiguous escape.
- **Full telemetry** stays in `BOTH` and `TELEMETRY_ONLY` (owner intent). The export dialog states the record count, the size, and the sensitive categories included.
- **FINDINGS section**: state findings, open alerts, closed alerts.
- **Exports and cleanup.**
  - The JSONL export streams through `GZIPOutputStream`.
  - Report and export files in `cache/reports/` older than one hour are deleted before each export and at startup.
  - `TimelineExporter` streams and keeps its CSV formula guard.

## 8. UI

### 8.1 Telemetry browser

The browser opens from History, scan headers and finding detail. It has three levels:
1. **Services**, with record counts.
2. **Records** of one service: keyset-paged, with a debounced search over the indexed columns.
3. **One record's fields**, in taxonomy order with their descriptions. For a snapshot record, it also shows the subject's history across scans, with the fields that changed highlighted.

Unreadable bodies are shown as unreadable.

### 8.2 Settings

- **Storage size**: distinct bodies, split into snapshots, live events and imports.
- **"Keep snapshot telemetry for the last N scans"**: default 20.
- **"Delete old snapshot telemetry now"**.

## 9. Testing and gates (regression policy)

All gates are JVM unit tests (Robolectric 4.14.1, SDK 35, offline via the `robolectric.offline` system property; routing by API level through an injected `sdkInt`).

| Gate | What it checks |
|---|---|
| **S1** | The full decoded map equals the evaluated map for every service. |
| **S2** | Facts are stored once: shared across imports with different `capturedAt`; identical-content events in one batch stay distinct; the same source key with different content gives two facts; id-less duplicate intrusion lines give one fact; unchanged snapshots share facts; exact duplicates in one import give one observation and one finding. |
| **S3** | A failed or killed writer leaves no visible fact, finding, alert or Timeline row, and the startup sweep removes it. Re-run in Phase D with `scan_finding` pins; a crash between delete batches of a `COMPLETE` scan (now `DELETING`) or of retention leaves no visible orphan, and the sweep completes the delete. |
| **S4** | Deleting import A keeps facts that B observed and facts that are pinned (including `signal_member` and `alert.recordId`). |
| **S5** | Dictionary immutability and the zlib header check. |
| **S6** | Unreadable placeholder. |
| **S7** | A one-shot sequence cannot be read twice. |
| **ST1** | Streaming: chunk *k* commits before record *(k+1)·5000+1* is pulled. Runs in `test`. A low-heap smoke run is added to the CI command. |
| **E1** | Writers evaluate exactly what they persist; `file_scanner` ordinal. |
| **E2** | Field-map completeness. |
| **W1** | Watermarks: each event observed once; no advance on `Failed`, `NoAccess` or disk-full fallback; advance despite capability skips, with observations linear; late-flushed DNS; clock-ahead reset; late IOC re-check fires once on a fact from the previous scan, never re-evaluates the current scan's own facts, and ignores imported DNS facts. |
| **R1** | Report provenance. |
| **R2** | Single report path. |
| **R3** | Escaping (including `\`, lone surrogates and nested values). |
| **B1** | Typed bug-report records, battery parity, wakelock time, no generic battery emission. |
| **C1** | No persistence caps (allow-lists per phase, §5.5). |
| **T1** | 100,000-event import pages fully; counts match; no duplicates; no OFFSET; no TEMP B-TREE for any shape; scroll position survives an invalidation; an uncommitted import is invisible, including its finding rows; the severity filter matches writer-produced rows. |
| **K1** | Every atom-bound category has a producer; day-precision facts never become atoms; a live DNS fact and its `ioc_match` row bind once. |
| **F1** | Migration 19→20, including keeping `matchContext`, backfilling the summary columns, and resolving a late-IOC re-check finding by its `recordId`; `Migration18To19Test` covers a 3 MB row and a corrupt row (backfill leaves `level` null, upgrade completes). |
| **F2** | `recordId` resolves for every service; finding rows carry `recordId` from Phase A. |
| **L1** | Lifecycle: state findings follow the latest live scan, not imports; an alert persists until closed; an overlapping import's finding attaches to the same alert and keeps its own `scan_finding` row; a closed alert stays closed; a new fact opens a new alert; correlation findings are state findings of their scan and open no alert; this scan's timeline rows are `Row` atoms with real ids and bind once; a signal's fact and row members load through `ClusterMembers` and the Timeline; legacy signals' members appear after the Phase C backfill; the evidence discriminator is stable across an IOC re-sync. |
| **L2** | Close and bulk close need confirmation; `NoSecureLock` fails closed; obscured touches are filtered; closure and audit rows survive "Clear all"; after deleting an alert's opening scan and after "Clear all", the alert's matched fact reads back **through the report and "Matched record"** and the evidence JSON is present; a `deleteScan` or "Clear all" killed after its first transaction still has exactly one audit row with a non-empty summary and no "import interrupted" row; the audit row for a 50,000-finding scan stays under 16 KB and the Timeline and report still load. |
| **M1** | Preflight and the per-chunk reserve (headers that under-report sizes); disk-full live fallback keeps findings from every later chunk; a fallback DNS IOC finding (no `recordId`) opens an OPEN alert; evaluate-only deduplicates duplicate lines; DNS retry backoff. |
| **Q1** | No post-API-26 SQL syntax in DAO, migration or Timeline SQL; list-binding `@Query` calls go through `chunkedIn`; every fact/observation read filters `COMPLETE` scans. |
| **X1** | Computed-column contract hash, including `categoryOf` outputs. |
| **V1** | Vocabulary. |
| **P1** | Prune exemptions (imports, persistent rows, rows referenced by `signal_member`). |
| **C2** | Correlation over an adversarial-density import (100k `permission_use` atoms for one package in 30 min) stops at its per-(rule, group) budget (an injected clock forces the cut-off deterministically), keeps the signals of rules that completed, records `CORRELATION_INCOMPLETE` for the unfinished rule and package (excluded from `realFailureCount`), and no row exceeds 64 KB. |
| **P2** | A 31-day-old live `ioc_match` row with `scanResultId = -1` is pruned; a persistent row is not. |
| **J1** | A live DNS fact and its `ioc_match` row join on `sourceKey = sourceEventKey` (both h128 BLOBs) in a real DAO query. |
| **D1** | Imported DNS finding time (lands in Phase 0). |

Taxonomy cross-checks and `ServiceActivationCrossCheckTest` are re-derived from the `evaluateRecords` call sites.

**Release battery** (standing policy):
- clean installs on the F916B and on emulators, including API 26 and a low-RAM image;
- scan twice;
- bug-report import;
- intrusion-log import twice;
- the maximal fixture on the low-RAM image;
- measure the stored-size factor;
- kill mid-import and relaunch;
- browse;
- close and bulk-close alerts through the credential prompt;
- compare the report's telemetry to the browser;
- note that a downgrade across schemas 19/20 wipes data.

## 10. Decisions

**Decided by the maintainer (2026-10-22):**

- Store everything; no caps. Disk cost is acceptable (§1.1).
- Snapshot records stay out of the timeline.
- Terminology must be consistent and precise across code, UI, docs and taxonomy.
- The bug-report telemetry loss is a defect.
- SQLite (queryable across scans), not files; a fact is stored once.
- Alerts stay open until a person closes them; state findings clear themselves.
- Correlation chains stay per-scan in this design; lasting correlation alerts move to a follow-up spec (2026-10-22, plan gate round 7).
- Taxonomy: collapse `dbinfo_audit` / `platform_compat_audit`; document the four emitter services with no rules.

**Plan-gate resolutions** (my calls; findings in `docs/superpowers/plans/2026-10-22-telemetry-store-plan-gate-round{1..7}-findings.md`):

- **Storage model**: content, facts and observations; content-checked source identity with a stored `sourceKey`; conditional envelope stripping.
- **Writer**: a push-session writer with per-chunk transactions; `IN_PROGRESS` scans; alerts created set-based at finish; every fact read filters `COMPLETE` scans.
- **Watermarks**: they always advance; a live fact is observed once; recent DNS is re-checked against IOCs that arrive later.
- **Findings and alerts**:
  - findings are per scan; alerts span scans;
  - correlation findings stay per-scan state findings (maintainer, 2026-10-22: lasting correlation alerts split to a follow-up);
  - `signal_member` is the single, indexed member store for signals, with a one-time backfill;
  - closing and bulk closing need the credential;
  - deletions leave audit rows instead of asking for the credential.
- **Bug-report records**: typed records that emit every fact; day-precision events never become correlation atoms; the wakelock time base is fixed.
- **Compression and keys**: immutable versioned dictionaries; 128-bit BLOB keys.
- **Storage protection**: preflight with "import anyway", plus a per-chunk reserve that nothing overrides.
- **Schema and Timeline**: one `TaxonomyContract`; a computed-column contract hash; composite indices and `level` in schema 19; keyset paging everywhere.
- **Reports**: streaming; complete escaping; a notice of the sensitive categories included; full telemetry kept per owner intent.
- **Phases**: replace-on-reimport removed in C3, together with a cleanup of legacy event rows; retention in Phase D.

**Left to the builder:** browser Compose structure; dictionary-build script wiring; import-card wording.

## 11. Follow-ups recorded, not scoped

- Differential timeline events from `changedBetween` and rules over them.
- Retroactive matching of stored `dns_monitor` facts older than the 24 h
  late-IOC window when IOCs change (needs an indexed lookup column).
- Replay of stored facts through a newer ruleset (`evaluateRecords`), which
  also recovers capability-skipped evaluation.
- Full-body search; JSON1 queries over snapshot bodies.
- #137 machine-readable schema from the taxonomy.
- The live `DnsEvent` table becoming `dns_monitor` facts (needs facts
  observed by the VPN, not only scans).
- `BatteryDailyModule`'s `package_downgrade` is a judgment computed in the
  emitter; move it to a rule.
- Usage-stats all apps, user-selectable. A richer alert case model.
- **Lasting correlation alerts** — `docs/superpowers/specs/2026-10-22-lasting-correlation-alerts-followup.md`, which records the design explored in plan-gate rounds 3–7 and the open problems found.

## 12. References

- osquery: snapshot vs. differential (event) query semantics.
- MVT: per-module results, `timeline.csv`, `*_detected.json`.
- Elastic Security alerts: ancestor event IDs; open/closed workflow status.
- SQLite JSON1; content-addressed storage; Deflate preset dictionaries
  (zlib checks the dictionary's Adler-32 — hence immutability); SQLite's
  999-variable limit before 3.32.
- Room `CursorWindow` 2 MB row limit (the origin of the #342 caps).
