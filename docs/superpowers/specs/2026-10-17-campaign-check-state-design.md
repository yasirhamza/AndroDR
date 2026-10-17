# Per-campaign check state in the mercenary check (#394): design

**Status:** design approved in chat 2026-10-17 (owner chose approach B). Supersedes the unconverged design in `docs/superpowers/specs/2026-10-16-campaign-check-state-followup.md` (branch `docs/ioc-attribution-provenance`, plan-gate rounds 7–13).

## Goal

The report's MERCENARY SPYWARE CHECK prints `[OK]  <Campaign>: not detected` for every campaign without a hit, plus one global note ("not detected" means none of the checks that ran matched). That overclaims when the checks able to detect a campaign did not run. Each row must say whether the campaign was fully checked and, if not, why and what to do.

**Readers (owner, 2026-10-17): both equally.**
- The person scanning their own phone needs a fix they can act on ("turn on DNS monitoring and scan again").
- An analyst or helper reading someone else's report needs to know exactly what evidence the scan covered, to weigh "not detected".

**Success:** `[OK]` appears only when every infection check for that campaign ran in full. Every other no-hit row says which checks were missing, why, and the fix. This holds for scans saved before the change too.

## Why the previous design did not converge, and what changes

The previous design had the app work out at scan time which detectors exist for each campaign: loaded rules, evaluable rules, the indicator cache's campaign keys, and bundled versus feed lists. It then stored a per-campaign state in a new column. Each review round found another state that this computation could not tell apart: rules skipped versus not loaded, the cache changing mid-scan, a registry change after the scan, history rows.

This design removes that computation from the app:
- **Which services can detect a campaign** is declared in the rules repo, per campaign, and CI derives and checks it.
- **Whether each service ran** comes from facts every scan already stores (`ScanResult.scannerErrors`).
- The row is computed at render time from those two inputs. There is no new column, no migration, and no scan-time campaign logic.

## Facts this design rests on (origin/main 60b0619, rules main 6cc5899)

- **7 campaigns are in `ioc-data/campaigns.yml`:** pegasus (alias nso), predator (intellexa, cytrox), graphite (paragon), cellebrite, landfall, massistant, midnight-mimosa.
- **Rules carrying a `campaign.*` tag:**
  - androdr-048..052 are `device_auditor`, `device_posture`: EXPOSED only.
  - androdr-108 predator is `file_scanner`, incident.
  - androdr-078 massistant and androdr-109 midnight-mimosa are `app_scanner`, incident.
- **ioc-data `campaign` values:**
  - `c2-domains.yml`: graphite 15, midnight-mimosa 5;
  - `package-names.yml`: midnight-mimosa 14, cellebrite 1;
  - `cert-hashes.yml`, `malware-hashes.yml`: none.
  - MVT attribution (`mvt-campaign-map.json`) is domain-only: pegasus, predator.
- **The IOC rules:**
  - androdr-001 (`package_ioc_db`), androdr-002 (`cert_hash_ioc_db`) and androdr-003 (`domain_ioc_db`) are `evidence_type: ioc_match`.
  - androdr-004 (`apk_hash_ioc_db`) is `none` until rules task A6.
- **Stored per scan:** `ScanResult.scannerErrors: List<ScannerFailure>` (Room JSON TEXT, schema 19), where `ScannerFailure(scanner, exception, message?, ruleId?, missingEvidence)`.
  - **Sentinels** (`NotEvaluatedReason`): `UnregisteredIocLookup`, `UnreadableArtifactPaths` (scanner `file_scanner`, per rule), `NoEventsToCheck`, `FeedsNotLoaded`, `CampaignSourcesNotLoaded`, and `DnsMonitorOff` (scanner `dns_monitor`, from `DnsVpnService.isRunning` read once at scan start).
  - **Real failures:** the 8 phase-1 scanners record their name on a crash (`appScanner`, `deviceAuditor`, `processScanner`, `fileArtifactScanner`, `accessibilityAuditScanner`, `receiverAuditScanner`, `appOpsScanner`, `usageStatsScanner`).
  - **A gap:** a failed `dnsEventDao.getRecentSnapshot()` read is swallowed today (`ScanOrchestrator.kt:384-386`).
- **App versions:** only 697+ parse `campaigns.yml` (656 has no `CampaignRegistry`). 697's `CampaignRegistry.parseYaml` reads only `key`, `label` and `aliases` and ignores other keys (e.g. `references`), so a new key is safe for every fielded version.
- **Rendering:** `campaignVerdicts(scan, campaigns, referenceTime, ruleCategoryById)` and `appendCampaignRows` in `reporting/CampaignVerdict.kt`. Both callers (`ReportExporter`, `HistoryViewModel`) get their inputs from `reporting/ReportInputs.kt`.

## Design

### 1. `detected_by` in `campaigns.yml` (rules repo)

Each campaign gets `detected_by`, a sorted list of logsource services whose findings can make the campaign DETECTED. These are the infection checks. Patch-level exposure is not declared: EXPOSED comes from the `device_posture` rules themselves.

```yaml
  - key: midnight-mimosa
    label: Midnight Mimosa
    detected_by: [app_scanner, dns_monitor]
  - key: landfall
    label: LANDFALL
    detected_by: []          # patch level only: no infection check exists
```

Values today:

| key | detected_by |
|---|---|
| pegasus | [dns_monitor] |
| predator | [dns_monitor, file_scanner] |
| graphite | [dns_monitor] |
| cellebrite | [app_scanner] |
| landfall | [] |
| massistant | [app_scanner] |
| midnight-mimosa | [app_scanner, dns_monitor] |

**Validation** (`validate-ioc-data.py`, campaigns file): `detected_by` is required, a list, sorted, without duplicates, and each value is a service in `validation/logsource-taxonomy.yml`.

**Derivation gate:** a new `validation/test_campaign_detected_by.py`, run by the existing `pytest validation/` CI job. For each key, the derived set is the union of:
1. **Rules.** Each rule listed in `rules.txt` (the set devices load; `staging/` rules never ship, so they don't count) with a tag `campaign.<key or one of its aliases>` whose category is not `device_posture` adds its `logsource.service`.
2. **ioc-data.** Each entry with `campaign: <key>` in a file whose lookup is used by an `evidence_type: ioc_match` rule adds that rule's service. The file-to-lookup map is `c2-domains.yml` → `domain_ioc_db`, `package-names.yml` → `package_ioc_db`, `cert-hashes.yml` → `cert_hash_ioc_db`, `malware-hashes.yml` → `apk_hash_ioc_db`. The rule is found by its `|ioc_lookup: <name>` matcher.
3. **The MVT map.** Each `mvt-campaign-map.json` entry adds `dns_monitor` for its `key`.

The test asserts declared == derived for every campaign, and reports the difference in both directions. Fixture tests prove three failure cases:
- a newly tagged incident rule on a new service, with the list not updated, fails;
- a declared service with no detector fails (overclaim);
- an ioc-data campaign entry in a file whose rule is not `ioc_match` does not count. This is androdr-004 today: after A6 flips it, CI will demand the lists change if any `malware-hashes.yml` entry carries a campaign.

**Manifest:** the `campaigns.yml` edit regenerates `ioc-data.sha256`. Safe ordering applies, because the app fetches `campaigns.yml` from rules main.

### 2. App data

- `Campaign` (`ioc/CampaignRegistry.kt`) gains `detectedBy: List<String>?`. `null` means the field is absent; `[]` means patch level only.
- `parseYaml` and `parseBundled` read it. They keep only values matching the taxonomy service-name shape (`[a-z_]+`), then sort and dedupe. A non-list value is treated as absent.
- `scripts/merge-ioc-data.py` emits `detected_by` into `known_campaigns.json`. The existing regenerate-and-diff gate (`bundle-provenance` job) catches drift.

### 3. Coverage per service: `reporting/CampaignCoverage.kt` (new, pure)

```kotlin
enum class ServiceCoverage { CHECKED, BUILT_IN_LISTS_ONLY, PARTLY_UNREADABLE, BLIND, NEEDS_IMPORT }

data class ServiceStatus(val service: String, val coverage: ServiceCoverage, val reason: String?)

fun campaignCoverage(
    detectedBy: List<String>,
    campaignKey: String,
    scannerErrors: List<ScannerFailure>,
    ruleCampaigns: Map<String, Set<String>>,   // ruleId -> campaign keys (aliases resolved)
): List<ServiceStatus>
```

The status for each service in `detectedBy` is the first that applies:

| Coverage | Condition |
|---|---|
| NEEDS_IMPORT | `service` is in `IMPORT_ONLY_SERVICES`: the services a live scan never evaluates (`network_monitor`, `security_log`, `tombstone_parser`, `wakelock_parser`, `battery_daily`, `package_install_history`, `platform_compat`, `db_info`, `timeline`). |
| BLIND | `dns_monitor`: there is a `DnsMonitorOff` entry, or a real failure with scanner `dnsSnapshot`. Any other service: a real failure whose scanner is `SCANNER_FOR_SERVICE[service]`. |
| PARTLY_UNREADABLE | `file_scanner`: there is an `UnreadableArtifactPaths` entry whose `ruleId` maps to a set containing `campaignKey`. |
| BUILT_IN_LISTS_ONLY | `dns_monitor` or `app_scanner`, with a `FeedsNotLoaded` or `CampaignSourcesNotLoaded` entry. |
| CHECKED | Otherwise. |

`SCANNER_FOR_SERVICE` is the single map from live-scan service to orchestrator scanner name:
- `app_scanner` → `appScanner`, `device_auditor` → `deviceAuditor`, `process_monitor` → `processScanner`, `file_scanner` → `fileArtifactScanner`;
- `accessibility_audit` → `accessibilityAuditScanner`, `receiver_audit` → `receiverAuditScanner`, `appops_audit` → `appOpsScanner`, `dns_monitor` → `dnsSnapshot`.

A "real failure" is a `ScannerFailure` whose `exception` is not a `NotEvaluatedReason` sentinel, the same test `realFailureCount` uses. A service that is in neither map nor set is treated as BLIND with reason "unknown check type". This fails closed: a future service shows as not checked until it's wired.

### 4. Orchestrator fix

`ScanOrchestrator`: when `dnsEventDao.getRecentSnapshot()` throws, record `ScannerFailure(scanner = "dnsSnapshot", exception = e.javaClass.simpleName, message = e.message)` and continue with an empty list. Today the failure is swallowed.

### 5. Report inputs

`ReportInputs` gains `ruleCampaigns(): Map<String, Set<String>>`, built from the loaded rules: each rule id maps to its `campaign.*` tag suffixes, resolved to keys through `campaignRegistry.keyFor` and dropping unknown ones. It sits next to `ruleCategoryById()`, so the export and History share one path. `campaignVerdicts` gains the parameter. A rule no longer loaded is absent, so its unreadable-paths entry doesn't count toward any campaign. That is an accepted residual for very old history scans.

### 6. Rows

`CampaignVerdict` gains `coverage: List<ServiceStatus>?`, which is null when `detectedBy` is null or the scan is an import.
- **Precedence is unchanged:** DETECTED, then EXPOSED, then EARLIER_HIT, then the import row, then no hit.
- **EXPOSED** appends `; infection check: <summary>`. The summary is "not detected" when every service is CHECKED, otherwise the same reason list as below.
- **No hit, live scan:**
  - `coverage == null` → today's `[OK]  <Label>: not detected`, and the global scope note stays.
  - `detectedBy == []` → `[--]  <Label>: no infection check exists for a live scan; patch level only`.
  - Every service CHECKED → `[OK]  <Label>: not detected`.
  - Otherwise → `[--]  <Label>: ` followed by `no hit in <checked services>; ` when some service was CHECKED, then one clause per service that was not, and finally the fixes. Each fix appears once per row, in the order of the clauses.

  Plain words per service: `dns_monitor` "DNS lookups", `app_scanner` "installed apps", `file_scanner` "files", `device_auditor` "device settings", `process_monitor` "running processes", `accessibility_audit` "accessibility services", `receiver_audit` "app receivers", `appops_audit` "app permissions in use"; any other service uses its name.

  | Coverage | Clause | Fix |
  |---|---|---|
  | BLIND (DNS off) | `DNS lookups not checked (DNS monitoring was off)` | `Turn on DNS monitoring, use the phone as usual, then scan again.` |
  | BLIND (crash, or snapshot read failed) | `<words> not checked (that check failed on this scan)` | `Scan again; if it keeps failing, export the report and send it to us.` |
  | PARTLY_UNREADABLE | `files only partly checked (some paths could not be read)` | — (the paths are listed under WHAT THIS SCAN COULD NOT CHECK) |
  | BUILT_IN_LISTS_ONLY | `<words> checked against the built-in list only (threat lists had not finished loading)` | `Scan again in a few minutes.` |
  | NEEDS_IMPORT | `<words> need a bug report or intrusion log` | `Import one to check this.` |

  The fixes go on an indented second line, as in:
  ```
  [--]  Pegasus: DNS lookups not checked (DNS monitoring was off)
        Turn on DNS monitoring, use the phone as usual, then scan again.
  [--]  Midnight Mimosa: no hit in installed apps; DNS lookups not checked (DNS monitoring was off)
        Turn on DNS monitoring, use the phone as usual, then scan again.
  [--]  LANDFALL: no infection check exists for a live scan; patch level only
  [OK]  Massistant: not detected
  ```
- **The global scope note** ("not detected" means none of the checks that ran…) is printed only when some row has `coverage == null`. The two count lines and WHAT THIS SCAN COULD NOT CHECK are unchanged.
- **Summary lines** (`appendCampaignSummary`): unchanged, DETECTED and EXPOSED only.
- **Imports:** unchanged, out of scope.

### Residuals accepted

- BUILT_IN_LISTS_ONLY is per service, not per campaign. For Pegasus the built-in list holds no Pegasus domains, so in effect nothing was checked. The row is still true and gives the right fix.
- DNS monitoring switched on shortly before a scan counts as CHECKED. Measuring DNS coverage hours is a separate improvement.
- History renders with the current `campaigns.yml` and the currently loaded rules, as the shipped rows already do.

## Tests (each is a deterministic gate, per the regression policy)

**Rules repo:**
- `test_campaign_detected_by.py`: the live data equals the derived lists, plus the three fixture failure cases from §1.
- The validator rejects a missing, unsorted, duplicated or unknown-service `detected_by`.

**AndroDR:**
- `CampaignRegistryTest`:
  - YAML and JSON parsing of `detected_by`: present, `[]`, absent → null, non-list → null, a junk value dropped;
  - the bundled JSON carries it for all 7 campaigns.
- `CampaignCoverageTest`: one test per row of the §3 table, with precedence (a crash beats feeds-not-loaded; a `dnsSnapshot` failure gives BLIND), an unknown service giving BLIND, and an unreadable-paths entry for another campaign's rule not counting.
- `ServiceScannerMapCrossCheckTest`: every taxonomy service with `status: active` is in exactly one of `SCANNER_FOR_SERVICE` and `IMPORT_ONLY_SERVICES`, and every mapped scanner name is one the orchestrator records. This catches a new service or a renamed scanner.
- `ReportFormatterTest` / `MercenaryCheckReportTest`: each row form in §6, EXPOSED with the suffix, the fallback with the global note, an import row unchanged, and a fix printed once when two services share it.
- `ScanOrchestratorErrorHandlingTest`: a throwing `getRecentSnapshot()` records `dnsSnapshot` and the scan completes.
- `scripts/test_merge_ioc_data.py`: `detected_by` is emitted.

**Adversary harness:**
- Update the patterns that assert `[OK]  <Campaign>: not detected` for campaigns the scenario can't fully check.
- Add `campaign_rows_dns_off`: VPN off, expect `[--]  Pegasus: DNS lookups not checked (DNS monitoring was off)` and `[OK]  Massistant: not detected`.

## Delivery order

1. Rules branch: `detected_by` + validator + derivation test, and `ioc-data.sha256` regenerated.
2. AndroDR PR with the submodule pinned to that branch commit: app changes, the regenerated `known_campaigns.json`, tests and harness patterns.
3. AndroDR CI `build-and-test` green (`submodule-check` is red by design at this point).
4. Merge the rules branch, point the submodule at rules main, CI fully green, merge AndroDR.
5. The full release battery before the next app upload, as standing policy.

Either order is safe for devices: until the new app ships the field is ignored, and the new app with an older cached `campaigns.yml` falls back to today's rows.

## Out of scope

- Import rows.
- DNS coverage hours.
- Per-campaign built-in-list precision.
- androdr-004 attribution (rules task A6). Once A6 lands, this design's CI gate will require the lists to be updated if hashes carry campaigns.
