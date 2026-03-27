# Interactive Adversary Simulation Test Harness

**Date:** 2026-03-28
**Extends:** `docs/superpowers/specs/2026-03-26-adversary-simulation-design.md`

---

## Goal

Add load and guided interactive modes to the existing adversary simulation harness, expand the scenario library from 20 to ~34 scenarios with risk prioritization, and add composable selection filters (profile, track, risk, random sampling).

---

## 1. Mode Structure

Three modes on `run.sh`, selected by flag:

| Mode | Flag | Behavior |
|------|------|----------|
| **Regression** | `--no-pause` or none | Existing sequential per-scenario flow. Unchanged. |
| **Load** | `--load` | Install selected scenarios, trigger one scan, block until ENTER, cleanup. |
| **Guided** | `--guided` | Install selected scenarios, trigger one scan, walk through detection categories with prompts and inline assertions, cleanup on ENTER. |

All three modes accept the same selection filters:

```bash
./run.sh --load emulator-5554                                    # all scenarios
./run.sh --load --profile pegasus emulator-5554                  # profile filter
./run.sh --load --track 1,3 emulator-5554                        # track filter
./run.sh --load --only cerberus_banker,surveillance_permissions emulator-5554  # specific
./run.sh --load --random 5 emulator-5554                         # random 5
./run.sh --guided --random 3 --track 2 emulator-5554             # composable
./run.sh --load --risk high emulator-5554                        # risk filter
./run.sh --load --profile journalist --random 3 emulator-5554    # profile + random
```

Fallback: `cleanup.sh <serial>` reads `/tmp/androdr-loaded-packages.txt` and uninstalls everything, removes injected artifacts.

---

## 2. Load Mode (`--load`)

```
1. Preflight checks (adb, AndroDR installed, python3+yaml)
2. Resolve selection filters → candidate scenario list
3. Download MalwareBazaar samples for selected scenarios
4. Install ALL selected APKs in one batch
5. Record packages to /tmp/androdr-loaded-packages.txt
6. Run ADB inject commands for selected adb_inject scenarios
7. Seed IOC DB (cert hash scenario, if selected)
8. Trigger ONE scan via ScanBroadcastReceiver
9. Wait for scan completion
10. Print summary:
    ✓ Installed 15 samples (6 Track 1, 3 Track 2, 6 Track 3)
    ✓ Injected 3 artifacts
    ✓ Scan triggered

    AndroDR is loaded. Open the app on the emulator to explore.
    Press ENTER when done to clean up.
    (If this script is interrupted, run: ./test-adversary/cleanup.sh <serial>)
11. Block on read — user explores manually
12. User presses ENTER → cleanup + delete state file
```

No pattern matching, no pass/fail. Purely "set up the battlefield."

---

## 3. Guided Mode (`--guided`)

After installing and scanning (same as load mode steps 1-9), walks through detection categories:

```
═══════════════════════════════════════════════════
  CATEGORY 1: Device Posture
═══════════════════════════════════════════════════

  Check the Device tab in AndroDR. You should see:
  - USB Debugging Enabled (HIGH) — triggered
  - No Screen Lock (CRITICAL) — triggered
  - Unpatched CVEs — depends on patch level

  Report assertions:
  ✓ "USB Debugging Enabled" found in report
  ✓ "No Screen Lock" found in report

  Press ENTER to continue to App Risks...

═══════════════════════════════════════════════════
  CATEGORY 2: App Risks — Commodity Malware
═══════════════════════════════════════════════════

  Check the Apps tab. You should see sideloaded apps flagged:
  - com.cave.series (Cerberus) — sideloaded
  - com.appser.verapp (SpyNote) — sideloaded

  Report assertions:
  ✓ "not installed from a trusted app store" found (3 instances)
  ✗ MISS: "surveillance capabilities" not found for com.cave.series

  Press ENTER to continue...

...categories continue...

═══════════════════════════════════════════════════
  SUMMARY
═══════════════════════════════════════════════════
  Assertions: 15 passed, 2 failed, 4 expected fail

  Press ENTER to clean up.
```

### Category grouping

Categories derived from installed scenarios, not hard-coded:

| Category | Source | What to check in UI |
|----------|--------|---------------------|
| Device Posture | device_auditor rules | Device tab — flags, CVE bottom sheet |
| Commodity Malware | Track 1 | Apps tab — sideloaded apps |
| Stalkerware | Track 2 | Apps tab — surveillance permissions |
| Mercenary Simulation | Track 3 | Apps tab — IOC matches, accessibility, device admin |
| CVE Detection | Track 4 | Device tab — CVE card, bottom sheet, campaign tags |
| Network | DNS/IP scenarios | Network tab — matched domains |

Only categories with installed scenarios are shown.

---

## 4. Selection Filters

### Manifest v3 schema

```yaml
version: 3

profiles:
  pegasus:
    description: "NSO Group Pegasus mercenary spyware"
    scenarios: [mercenary_package_name, cve_campaign_pegasus, surveillance_permissions, system_name_disguise]

  predator:
    description: "Intellexa Predator mercenary spyware"
    scenarios: [cve_predator_campaign, surveillance_permissions]

  graphite:
    description: "Paragon Graphite mercenary spyware"
    scenarios: [cve_graphite_campaign, surveillance_permissions]

  journalist:
    description: "Threat model for journalists/activists"
    profiles: [pegasus, predator, graphite]
    scenarios: [stalkerware_*, mercenary_*]

  banking:
    description: "Banking trojan threat landscape"
    scenarios: [cerberus_banker, anubis_banker, brata_rat, hydra_dropper, sharkbot_banker, ermac_stealer, godfather_banker, hookbot_rat]

  stalkerware:
    description: "Commercial surveillance / stalkerware"
    scenarios: [thetruthspy_stalkerware, andrmonitor_stalkerware, tispy_stalkerware, cocospy_stalkerware, mspy_stalkerware, eyezy_stalkerware]

  full:
    description: "All scenarios"
    scenarios: ["*"]

scenarios:
  - id: cerberus_banker
    track: 1
    risk: medium
    technique: T1429
    tactic: collection
    description: "Cerberus Android banking trojan"
    source: malwarebazaar
    sha256: "8beae1..."
    tags: [android, cerberus, banker]
    expected_patterns:
      - "not installed from a trusted app store"
```

Per-scenario fields added: `risk` (high|medium|low), `technique` (ATT&CK Mobile ID), `tactic` (kill chain phase).

### Selection resolution

Filters compose as intersection:

```
candidates = all scenarios
if --profile:  candidates &= scenarios in profile (recursively expanding nested profiles + globs)
if --track:    candidates &= scenarios matching track
if --risk:     candidates &= scenarios matching risk level
if --only:     candidates = only named scenarios (overrides all other filters)
if --random N: candidates = weighted sample of N from candidates
```

### Weighted random

When `--random N` is used, selection is weighted by risk:
- `high` = weight 3
- `medium` = weight 2
- `low` = weight 1

This ensures random sweeps prioritize active threats.

---

## 5. Enriched Scenario Library

### New Track 1 — Commodity Malware (4 new)

| ID | Risk | Technique | Source |
|----|------|-----------|--------|
| `sharkbot_banker` | high | T1429 | MalwareBazaar |
| `ermac_stealer` | high | T1417 | MalwareBazaar |
| `godfather_banker` | medium | T1429 | MalwareBazaar |
| `hookbot_rat` | medium | T1512 | MalwareBazaar |

### New Track 2 — Stalkerware (3 new)

| ID | Risk | Technique | Source |
|----|------|-----------|--------|
| `cocospy_stalkerware` | high | T1430 | MalwareBazaar |
| `mspy_stalkerware` | high | T1429 | MalwareBazaar |
| `eyezy_stalkerware` | medium | T1636 | MalwareBazaar |

### New Track 3 — Mercenary Simulation (4 new fixtures)

| ID | Risk | Technique | What it tests |
|----|------|-----------|--------------|
| `system_name_disguise` | high | T1036 | App masquerading as "System Update" |
| `impersonation_play_store` | high | T1036 | App impersonating Google Play |
| `multi_abuse_combo` | high | T1626+T1401 | Accessibility + device admin + surveillance in one APK |
| `firmware_implant_sim` | medium | T1542 | App mimicking system partition install path |

### New Track 4 — CVE Detection (3 new)

| ID | Risk | Technique | What it tests |
|----|------|-----------|--------------|
| `cve_stale_patch` | high | T1404 | Stale patch level finding |
| `cve_predator_campaign` | high | T1404 | Predator campaign rule |
| `cve_graphite_campaign` | high | T1404 | Graphite campaign rule |

### Total: ~34 scenarios

| Risk | Count |
|------|-------|
| high | ~18 |
| medium | ~12 |
| low | ~4 |

### Profile coverage

| Profile | Scenario count | Tracks |
|---------|---------------|--------|
| `pegasus` | 5-6 | 3, 4 |
| `predator` | 4-5 | 3, 4 |
| `graphite` | 3-4 | 3, 4 |
| `journalist` | 12-15 | 2, 3, 4 |
| `banking` | 8-10 | 1 |
| `stalkerware` | 6-8 | 2, 3 |
| `full` | all | all |

---

## 6. Cleanup Script

`test-adversary/cleanup.sh <serial>` — standalone fallback:

```bash
#!/usr/bin/env bash
SERIAL="${1:?Usage: cleanup.sh <serial>}"
STATE_FILE="/tmp/androdr-loaded-packages.txt"

if [ ! -f "$STATE_FILE" ]; then
    echo "No state file found. Nothing to clean up."
    exit 0
fi

while IFS= read -r pkg; do
    adb -s "$SERIAL" uninstall "$pkg" 2>/dev/null || true
done < "$STATE_FILE"

# Remove injected artifacts
adb -s "$SERIAL" shell rm -f /data/local/tmp/.raptor /data/local/tmp/.stat 2>/dev/null || true

rm -f "$STATE_FILE"
echo "Cleanup complete."
```

---

## 7. Testing Strategy

### Selection logic tests

`test-adversary/test_selection.py` — unit tests for manifest parsing and filter logic:
- Profile expansion resolves scenario lists correctly
- Nested profiles expand recursively
- Glob patterns in profiles match scenarios
- `--track` filters by track number
- `--risk` filters by risk level
- `--random N` returns N items with correct weighting
- Composable filters intersect
- `--only` overrides all other filters
- Empty result set prints helpful error

### Mode integration

Existing regression mode (`run.sh --no-pause`) unchanged and serves as integration test. New modes verified:
- `--load` installs, blocks, cleans up on ENTER
- `--load` + Ctrl+C → `cleanup.sh` removes everything
- `--guided` walks through categories, shows assertions
- Selection filters produce correct scenario sets

### New fixture APKs

`build-fixtures.sh` extended to build 4 new Track 3 APKs:
- `system-name-disguise.apk` — `package="com.android.systemupdate"`
- `impersonation-play-store.apk` — `package="com.android.vending.update"` with Google Play-like app name
- `multi-abuse-combo.apk` — accessibility + device admin + RECORD_AUDIO + CAMERA + ACCESS_FINE_LOCATION
- `firmware-implant-sim.apk` — system-app-like package name `com.android.providers.settings.backup`

---

## Files Changed

### Modified
- `test-adversary/run.sh` — add `--load`, `--guided`, `--profile`, `--track`, `--risk`, `--random`, `--only` flags; selection resolution; load mode flow; guided mode flow
- `test-adversary/manifest.yml` — bump to v3; add profiles block; add risk/technique/tactic per scenario; add 14 new scenarios
- `test-adversary/fixtures/mercenary/build-fixtures.sh` — build 4 new fixture APKs

### Created
- `test-adversary/cleanup.sh` — standalone cleanup fallback
- `test-adversary/test_selection.py` — unit tests for selection logic
- `test-adversary/fixtures/expected/` — pattern files for 14 new scenarios
- 4 new fixture APK project directories under `test-adversary/fixtures/mercenary/`
