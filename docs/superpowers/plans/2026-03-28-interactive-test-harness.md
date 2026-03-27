# Interactive Adversary Simulation Test Harness — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add load and guided interactive modes to the adversary simulation harness, with composable selection filters (profile, track, risk, random) and an expanded ~34-scenario library.

**Architecture:** Python helper (`selector.py`) handles manifest parsing, filter resolution, and weighted random sampling. Bash (`run.sh`) gains `--load` and `--guided` flags that call the selector, then install everything in batch and either block (load) or walk through categories (guided). `cleanup.sh` is a standalone fallback. 4 new fixture APKs extend Track 3.

**Tech Stack:** Bash, Python 3 (PyYAML), ADB, Android Gradle Plugin (fixture APKs)

**Spec:** `docs/superpowers/specs/2026-03-28-interactive-test-harness-design.md`

---

## File Structure

### New files
| File | Responsibility |
|------|---------------|
| `test-adversary/selector.py` | Manifest parsing, profile expansion, filter resolution, weighted random sampling |
| `test-adversary/test_selection.py` | Unit tests for selector.py |
| `test-adversary/cleanup.sh` | Standalone cleanup fallback — reads state file, uninstalls packages, removes artifacts |
| `test-adversary/fixtures/mercenary/system-name-disguise/build.gradle.kts` | Fixture: app masquerading as "System Update" |
| `test-adversary/fixtures/mercenary/system-name-disguise/src/main/AndroidManifest.xml` | Manifest with `package="com.android.systemupdate"` |
| `test-adversary/fixtures/mercenary/impersonation-play-store/build.gradle.kts` | Fixture: app impersonating Google Play |
| `test-adversary/fixtures/mercenary/impersonation-play-store/src/main/AndroidManifest.xml` | Manifest with `package="com.android.vending.update"` |
| `test-adversary/fixtures/mercenary/multi-abuse-combo/build.gradle.kts` | Fixture: accessibility + device admin + surveillance |
| `test-adversary/fixtures/mercenary/multi-abuse-combo/src/main/AndroidManifest.xml` | Manifest with all abuse patterns combined |
| `test-adversary/fixtures/mercenary/firmware-implant-sim/build.gradle.kts` | Fixture: system-app-like package |
| `test-adversary/fixtures/mercenary/firmware-implant-sim/src/main/AndroidManifest.xml` | Manifest with `package="com.android.providers.settings.backup"` |
| `test-adversary/fixtures/expected/` | 14 new pattern files for new scenarios |

### Modified files
| File | Change |
|------|--------|
| `test-adversary/run.sh` | Add `--load`, `--guided`, `--profile`, `--track`, `--risk`, `--random`, `--only` flags; load mode flow; guided mode flow; call `selector.py` for scenario resolution |
| `test-adversary/manifest.yml` | Bump to v3; add `profiles` block; add `risk`, `technique`, `tactic` per scenario; add 14 new scenarios |
| `test-adversary/fixtures/mercenary/build-fixtures.sh` | Add 4 new modules to MODULES array |
| `test-adversary/fixtures/mercenary/settings.gradle.kts` | Include 4 new modules |

---

## Task 1: Python Selector — Filter Resolution Engine

**Files:**
- Create: `test-adversary/selector.py`
- Create: `test-adversary/test_selection.py`

- [ ] **Step 1: Write failing tests**

```python
# test-adversary/test_selection.py
import unittest
import sys
import os
sys.path.insert(0, os.path.dirname(__file__))
from selector import load_manifest, resolve_scenarios

MINI_MANIFEST = {
    "version": 3,
    "profiles": {
        "pegasus": {
            "description": "Pegasus",
            "scenarios": ["merc_pkg", "cve_pegasus"]
        },
        "journalist": {
            "description": "Journalist",
            "profiles": ["pegasus"],
            "scenarios": ["stalk_*"]
        },
        "banking": {
            "description": "Banking",
            "scenarios": ["cerberus", "anubis"]
        }
    },
    "scenarios": [
        {"id": "cerberus", "track": 1, "risk": "medium", "technique": "T1429", "tactic": "collection"},
        {"id": "anubis", "track": 1, "risk": "medium", "technique": "T1429", "tactic": "collection"},
        {"id": "stalk_truth", "track": 2, "risk": "high", "technique": "T1430", "tactic": "collection"},
        {"id": "stalk_mspy", "track": 2, "risk": "high", "technique": "T1429", "tactic": "collection"},
        {"id": "merc_pkg", "track": 3, "risk": "high", "technique": "T1418", "tactic": "discovery"},
        {"id": "cve_pegasus", "track": 4, "risk": "high", "technique": "T1404", "tactic": "initial-access"},
    ]
}

class TestResolveScenarios(unittest.TestCase):
    def test_no_filters_returns_all(self):
        result = resolve_scenarios(MINI_MANIFEST)
        self.assertEqual(len(result), 6)

    def test_track_filter(self):
        result = resolve_scenarios(MINI_MANIFEST, tracks=[1])
        ids = [s["id"] for s in result]
        self.assertEqual(ids, ["cerberus", "anubis"])

    def test_risk_filter(self):
        result = resolve_scenarios(MINI_MANIFEST, risks=["high"])
        ids = [s["id"] for s in result]
        self.assertNotIn("cerberus", ids)
        self.assertIn("stalk_truth", ids)

    def test_profile_filter(self):
        result = resolve_scenarios(MINI_MANIFEST, profile="banking")
        ids = [s["id"] for s in result]
        self.assertEqual(ids, ["cerberus", "anubis"])

    def test_nested_profile(self):
        result = resolve_scenarios(MINI_MANIFEST, profile="journalist")
        ids = [s["id"] for s in result]
        # journalist = pegasus scenarios + stalk_* glob
        self.assertIn("merc_pkg", ids)
        self.assertIn("cve_pegasus", ids)
        self.assertIn("stalk_truth", ids)
        self.assertIn("stalk_mspy", ids)

    def test_only_overrides_all(self):
        result = resolve_scenarios(MINI_MANIFEST, tracks=[1], only=["stalk_truth"])
        ids = [s["id"] for s in result]
        self.assertEqual(ids, ["stalk_truth"])

    def test_random_returns_n(self):
        result = resolve_scenarios(MINI_MANIFEST, random_n=2)
        self.assertEqual(len(result), 2)

    def test_random_weighted_favors_high(self):
        # Run 100 times, high-risk should appear more often
        counts = {"high": 0, "medium": 0}
        for _ in range(100):
            result = resolve_scenarios(MINI_MANIFEST, random_n=1)
            counts[result[0]["risk"]] += 1
        self.assertGreater(counts["high"], counts["medium"])

    def test_composable_track_and_risk(self):
        result = resolve_scenarios(MINI_MANIFEST, tracks=[2], risks=["high"])
        ids = [s["id"] for s in result]
        self.assertEqual(len(ids), 2)
        self.assertTrue(all(s["track"] == 2 for s in result))

    def test_empty_result_returns_empty(self):
        result = resolve_scenarios(MINI_MANIFEST, tracks=[99])
        self.assertEqual(len(result), 0)

    def test_glob_pattern_in_profile(self):
        result = resolve_scenarios(MINI_MANIFEST, profile="journalist")
        ids = [s["id"] for s in result]
        self.assertIn("stalk_truth", ids)
        self.assertIn("stalk_mspy", ids)

if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd test-adversary && python3 test_selection.py 2>&1 | tail -5`

Expected: `ModuleNotFoundError: No module named 'selector'`

- [ ] **Step 3: Implement selector.py**

```python
#!/usr/bin/env python3
"""Manifest parser and scenario selector for the adversary simulation harness."""
import fnmatch
import random
import sys
import yaml

RISK_WEIGHTS = {"high": 3, "medium": 2, "low": 1}

def load_manifest(path):
    with open(path) as f:
        return yaml.safe_load(f)

def _expand_profile(manifest, profile_name, visited=None):
    """Recursively expand a profile into a set of scenario ID patterns."""
    if visited is None:
        visited = set()
    if profile_name in visited:
        return set()
    visited.add(profile_name)

    profiles = manifest.get("profiles", {})
    profile = profiles.get(profile_name)
    if not profile:
        return set()

    patterns = set(profile.get("scenarios", []))

    # Recursively expand nested profiles
    for nested in profile.get("profiles", []):
        patterns |= _expand_profile(manifest, nested, visited)

    return patterns

def _match_patterns(scenario_id, patterns):
    """Check if a scenario ID matches any of the glob patterns."""
    return any(fnmatch.fnmatch(scenario_id, p) for p in patterns)

def resolve_scenarios(manifest, profile=None, tracks=None, risks=None, only=None, random_n=None):
    """Resolve selection filters into a list of scenario dicts."""
    scenarios = manifest.get("scenarios", [])

    # --only overrides everything
    if only:
        return [s for s in scenarios if s["id"] in only]

    candidates = list(scenarios)

    # --profile filter
    if profile:
        patterns = _expand_profile(manifest, profile)
        if patterns:
            candidates = [s for s in candidates if _match_patterns(s["id"], patterns)]

    # --track filter
    if tracks:
        candidates = [s for s in candidates if s.get("track") in tracks]

    # --risk filter
    if risks:
        candidates = [s for s in candidates if s.get("risk") in risks]

    # --random N: weighted sample
    if random_n and random_n < len(candidates):
        weights = [RISK_WEIGHTS.get(s.get("risk", "low"), 1) for s in candidates]
        candidates = random.choices(candidates, weights=weights, k=random_n)
        # Deduplicate while preserving order
        seen = set()
        deduped = []
        for s in candidates:
            if s["id"] not in seen:
                seen.add(s["id"])
                deduped.append(s)
        candidates = deduped

    return candidates

def main():
    """CLI entry point: selector.py <manifest> [--profile X] [--track N,M] [--risk high,medium] [--only a,b] [--random N]"""
    import argparse
    parser = argparse.ArgumentParser(description="Resolve scenario selection filters")
    parser.add_argument("manifest", help="Path to manifest.yml")
    parser.add_argument("--profile", default=None)
    parser.add_argument("--track", default=None, help="Comma-separated track numbers")
    parser.add_argument("--risk", default=None, help="Comma-separated risk levels")
    parser.add_argument("--only", default=None, help="Comma-separated scenario IDs")
    parser.add_argument("--random", type=int, default=None, dest="random_n")
    args = parser.parse_args()

    manifest = load_manifest(args.manifest)
    tracks = [int(t) for t in args.track.split(",")] if args.track else None
    risks = args.risk.split(",") if args.risk else None
    only = args.only.split(",") if args.only else None

    result = resolve_scenarios(manifest, profile=args.profile, tracks=tracks, risks=risks, only=only, random_n=args.random_n)

    if not result:
        print("No scenarios match the given filters.", file=sys.stderr)
        sys.exit(1)

    for s in result:
        print(s["id"])

if __name__ == "__main__":
    main()
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd test-adversary && python3 test_selection.py -v 2>&1 | tail -15`

Expected: 11 tests, all OK

- [ ] **Step 5: Commit**

```bash
git add test-adversary/selector.py test-adversary/test_selection.py
git commit -m "feat: add scenario selector with profile, track, risk, and random filters"
```

---

## Task 2: Manifest v3 — Profiles, Risk, and New Scenarios

**Files:**
- Modify: `test-adversary/manifest.yml`

- [ ] **Step 1: Rewrite manifest.yml to v3 schema**

Add `profiles` block at top, add `risk`, `technique`, `tactic` to every existing scenario, and add 14 new scenarios. The full manifest is large — key additions:

**Profiles block** (add after `version: 3`):

```yaml
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
    scenarios: [thetruthspy_stalkerware, andrmonitor_stalkerware, tispy_stalkerware, cocospy_stalkerware, mspy_stalkerware, eyezy_stalkerware, mercenary_*]

  banking:
    description: "Banking trojan threat landscape"
    scenarios: [cerberus_banker, anubis_banker, brata_rat, hydra_dropper, vultur_rat, sharkbot_banker, ermac_stealer, godfather_banker, hookbot_rat]

  stalkerware:
    description: "Commercial surveillance / stalkerware"
    scenarios: [thetruthspy_stalkerware, andrmonitor_stalkerware, tispy_stalkerware, cocospy_stalkerware, mspy_stalkerware, eyezy_stalkerware]

  full:
    description: "All scenarios"
    scenarios: ["*"]
```

**Per existing scenario**, add `risk`, `technique`, `tactic`. Example for cerberus_banker:

```yaml
  - id: cerberus_banker
    track: 1
    risk: medium
    technique: T1429
    tactic: collection
    description: "Cerberus Android banking trojan"
    source: malwarebazaar
    sha256: "8beae1f6b21cec17eed82fb7af25e1782d5b7bf10fd22369603313f1b1a5e5e4"
    tags: [android, cerberus, banker]
    expected_patterns:
      - "not installed from a trusted app store"
```

**New scenarios to add** (14 total — use `sha256: "<pin>"` for MalwareBazaar samples until hashes are obtained):

Track 1 (4 new): `sharkbot_banker` (high, T1429), `ermac_stealer` (high, T1417), `godfather_banker` (medium, T1429), `hookbot_rat` (medium, T1512)

Track 2 (3 new): `cocospy_stalkerware` (high, T1430), `mspy_stalkerware` (high, T1429), `eyezy_stalkerware` (medium, T1636)

Track 3 (4 new fixtures): `system_name_disguise` (high, T1036), `impersonation_play_store` (high, T1036), `multi_abuse_combo` (high, T1626), `firmware_implant_sim` (medium, T1542)

Track 4 (3 new): `cve_stale_patch` (high, T1404), `cve_predator_campaign` (high, T1404), `cve_graphite_campaign` (high, T1404)

- [ ] **Step 2: Create expected pattern files for all 14 new scenarios**

Create one `.patterns` file per new scenario in `test-adversary/fixtures/expected/`:

```bash
echo "not installed from a trusted app store" > test-adversary/fixtures/expected/sharkbot_banker.patterns
echo "not installed from a trusted app store" > test-adversary/fixtures/expected/ermac_stealer.patterns
echo "not installed from a trusted app store" > test-adversary/fixtures/expected/godfather_banker.patterns
echo "not installed from a trusted app store" > test-adversary/fixtures/expected/hookbot_rat.patterns
printf "surveillance capabilities\nnot installed from a trusted app store\n" > test-adversary/fixtures/expected/cocospy_stalkerware.patterns
printf "surveillance capabilities\nnot installed from a trusted app store\n" > test-adversary/fixtures/expected/mspy_stalkerware.patterns
printf "surveillance capabilities\nnot installed from a trusted app store\n" > test-adversary/fixtures/expected/eyezy_stalkerware.patterns
echo "system-impersonating name" > test-adversary/fixtures/expected/system_name_disguise.patterns
echo "system-impersonating name" > test-adversary/fixtures/expected/impersonation_play_store.patterns
printf "surveillance capabilities\naccessibility\ndevice administrator\n" > test-adversary/fixtures/expected/multi_abuse_combo.patterns
echo "system-impersonating name" > test-adversary/fixtures/expected/firmware_implant_sim.patterns
echo "Security Patch Outdated" > test-adversary/fixtures/expected/cve_stale_patch.patterns
echo "Predator" > test-adversary/fixtures/expected/cve_predator_campaign.patterns
echo "Graphite" > test-adversary/fixtures/expected/cve_graphite_campaign.patterns
```

- [ ] **Step 3: Verify selector parses new manifest**

Run: `cd test-adversary && python3 selector.py manifest.yml --profile pegasus 2>&1`

Expected: prints scenario IDs in the pegasus profile

- [ ] **Step 4: Commit**

```bash
git add test-adversary/manifest.yml test-adversary/fixtures/expected/
git commit -m "feat: manifest v3 with profiles, risk levels, and 14 new scenarios"
```

---

## Task 3: New Fixture APKs (4 new Track 3)

**Files:**
- Create: 4 new fixture module directories under `test-adversary/fixtures/mercenary/`
- Modify: `test-adversary/fixtures/mercenary/settings.gradle.kts`
- Modify: `test-adversary/fixtures/mercenary/build-fixtures.sh`

- [ ] **Step 1: Create system-name-disguise fixture**

```bash
mkdir -p test-adversary/fixtures/mercenary/system-name-disguise/src/main
```

`test-adversary/fixtures/mercenary/system-name-disguise/build.gradle.kts`:
```kotlin
plugins { id("com.android.application") }
android {
    namespace = "com.android.systemupdate"
    compileSdk = 34
    defaultConfig {
        applicationId = "com.android.systemupdate"
        minSdk = 21
        targetSdk = 34
        versionCode = 1
        versionName = "1.0"
    }
}
```

`test-adversary/fixtures/mercenary/system-name-disguise/src/main/AndroidManifest.xml`:
```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
    <application android:label="System Update" />
</manifest>
```

- [ ] **Step 2: Create impersonation-play-store fixture**

```bash
mkdir -p test-adversary/fixtures/mercenary/impersonation-play-store/src/main
```

`build.gradle.kts`:
```kotlin
plugins { id("com.android.application") }
android {
    namespace = "com.android.vending.update"
    compileSdk = 34
    defaultConfig {
        applicationId = "com.android.vending.update"
        minSdk = 21
        targetSdk = 34
        versionCode = 1
        versionName = "1.0"
    }
}
```

`AndroidManifest.xml`:
```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
    <application android:label="Google Play Services" />
</manifest>
```

- [ ] **Step 3: Create multi-abuse-combo fixture**

```bash
mkdir -p test-adversary/fixtures/mercenary/multi-abuse-combo/src/main/res/xml
```

`build.gradle.kts`:
```kotlin
plugins { id("com.android.application") }
android {
    namespace = "com.androdr.fixture.multiabuse"
    compileSdk = 34
    defaultConfig {
        applicationId = "com.androdr.fixture.multiabuse"
        minSdk = 21
        targetSdk = 34
        versionCode = 1
        versionName = "1.0"
    }
}
```

`AndroidManifest.xml`:
```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
    <uses-permission android:name="android.permission.RECORD_AUDIO" />
    <uses-permission android:name="android.permission.CAMERA" />
    <uses-permission android:name="android.permission.ACCESS_FINE_LOCATION" />
    <uses-permission android:name="android.permission.READ_CONTACTS" />
    <uses-permission android:name="android.permission.READ_CALL_LOG" />
    <application android:label="SecuritySuper">
        <service android:name=".Svc"
            android:permission="android.permission.BIND_ACCESSIBILITY_SERVICE"
            android:exported="false">
            <intent-filter>
                <action android:name="android.accessibilityservice.AccessibilityService" />
            </intent-filter>
            <meta-data android:name="android.accessibilityservice"
                android:resource="@xml/accessibility_config" />
        </service>
        <receiver android:name=".Recv"
            android:permission="android.permission.BIND_DEVICE_ADMIN"
            android:exported="false">
            <intent-filter>
                <action android:name="android.app.action.DEVICE_ADMIN_ENABLED" />
            </intent-filter>
            <meta-data android:name="android.app.device_admin"
                android:resource="@xml/device_admin" />
        </receiver>
    </application>
</manifest>
```

`res/xml/accessibility_config.xml`:
```xml
<?xml version="1.0" encoding="utf-8"?>
<accessibility-service xmlns:android="http://schemas.android.com/apk/res/android"
    android:accessibilityEventTypes="typeAllMask"
    android:accessibilityFeedbackType="feedbackGeneric" />
```

`res/xml/device_admin.xml`:
```xml
<?xml version="1.0" encoding="utf-8"?>
<device-admin><uses-policies /></device-admin>
```

- [ ] **Step 4: Create firmware-implant-sim fixture**

```bash
mkdir -p test-adversary/fixtures/mercenary/firmware-implant-sim/src/main
```

`build.gradle.kts`:
```kotlin
plugins { id("com.android.application") }
android {
    namespace = "com.android.providers.settings.backup"
    compileSdk = 34
    defaultConfig {
        applicationId = "com.android.providers.settings.backup"
        minSdk = 21
        targetSdk = 34
        versionCode = 1
        versionName = "1.0"
    }
}
```

`AndroidManifest.xml`:
```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
    <application android:label="Settings Storage" />
</manifest>
```

- [ ] **Step 5: Update settings.gradle.kts to include new modules**

Read the existing `test-adversary/fixtures/mercenary/settings.gradle.kts` and add:
```kotlin
include(":system-name-disguise")
include(":impersonation-play-store")
include(":multi-abuse-combo")
include(":firmware-implant-sim")
```

- [ ] **Step 6: Update build-fixtures.sh MODULES array**

Add to the `MODULES` array (after `"surveillance-permissions"`):
```bash
    "system-name-disguise"
    "impersonation-play-store"
    "multi-abuse-combo"
    "firmware-implant-sim"
```

- [ ] **Step 7: Build fixtures**

Run: `cd test-adversary/fixtures/mercenary && ./build-fixtures.sh 2>&1 | tail -20`

Expected: 9 APKs built with SHA256 hashes printed.

- [ ] **Step 8: Update manifest.yml with new fixture SHA256 hashes**

Replace `<pin>` placeholders for the 4 new fixture scenarios with actual hashes from build output.

- [ ] **Step 9: Commit**

```bash
git add test-adversary/fixtures/mercenary/ test-adversary/manifest.yml
git commit -m "feat: add 4 new fixture APKs (system disguise, play store impersonation, multi-abuse, firmware implant)"
```

---

## Task 4: cleanup.sh — Standalone Fallback

**Files:**
- Create: `test-adversary/cleanup.sh`

- [ ] **Step 1: Create cleanup.sh**

```bash
#!/usr/bin/env bash
# test-adversary/cleanup.sh — Standalone cleanup for --load / --guided mode
# Usage: ./cleanup.sh <emulator-serial>
set -euo pipefail

SERIAL="${1:?Usage: $0 <emulator-serial>}"
STATE_FILE="/tmp/androdr-loaded-packages.txt"

# Resolve adb
if command -v adb &>/dev/null; then
    ADB="adb -s $SERIAL"
elif [ -n "${ANDROID_HOME:-}" ] && [ -x "$ANDROID_HOME/platform-tools/adb" ]; then
    ADB="$ANDROID_HOME/platform-tools/adb -s $SERIAL"
else
    echo "ERROR: adb not found." >&2
    exit 1
fi

if [ ! -f "$STATE_FILE" ]; then
    echo "No state file found at $STATE_FILE. Nothing to clean up."
    exit 0
fi

echo "=== AndroDR Adversary Cleanup ==="
echo ""

count=0
while IFS= read -r pkg || [ -n "$pkg" ]; do
    [ -z "$pkg" ] && continue
    if $ADB uninstall "$pkg" 2>/dev/null | grep -q "Success"; then
        echo "  Uninstalled: $pkg"
        ((count++)) || true
    else
        echo "  Skip (not installed): $pkg"
    fi
done < "$STATE_FILE"

# Remove injected artifacts
$ADB shell rm -f /data/local/tmp/.raptor /data/local/tmp/.stat 2>/dev/null || true

rm -f "$STATE_FILE"
echo ""
echo "Cleanup complete. Removed $count packages."
```

- [ ] **Step 2: Make executable**

```bash
chmod +x test-adversary/cleanup.sh
```

- [ ] **Step 3: Commit**

```bash
git add test-adversary/cleanup.sh
git commit -m "feat: add standalone cleanup.sh fallback for load/guided modes"
```

---

## Task 5: run.sh — Load Mode

**Files:**
- Modify: `test-adversary/run.sh`

- [ ] **Step 1: Add flag parsing for new modes and filters**

Replace lines 7-16 (the current flag parsing block) with:

```bash
MODE="regression"  # regression | load | guided
NO_PAUSE=false
SKIP_ISOLATION=true
PROFILE=""
TRACK_FILTER=""
RISK_FILTER=""
ONLY_FILTER=""
RANDOM_N=""

while [[ "${1:-}" == --* ]]; do
    case "$1" in
        --no-pause) NO_PAUSE=true ;;
        --isolate) SKIP_ISOLATION=false ;;
        --load) MODE="load" ;;
        --guided) MODE="guided" ;;
        --profile) shift; PROFILE="$1" ;;
        --track) shift; TRACK_FILTER="$1" ;;
        --risk) shift; RISK_FILTER="$1" ;;
        --only) shift; ONLY_FILTER="$1" ;;
        --random) shift; RANDOM_N="$1" ;;
        *) echo "Unknown flag: $1" >&2; exit 1 ;;
    esac
    shift
done
SERIAL="${1:?Usage: $0 [--load|--guided] [--profile X] [--track N] [--risk high,medium] [--random N] [--only a,b] <emulator-serial>}"
```

- [ ] **Step 2: Add scenario resolution via selector.py**

After the preflight section (after line 99 "IOC database populated"), add:

```bash
# ── Scenario selection ───────────────────────────────────────────────────────

SELECTOR_ARGS="$MANIFEST"
[ -n "$PROFILE" ] && SELECTOR_ARGS="$SELECTOR_ARGS --profile $PROFILE"
[ -n "$TRACK_FILTER" ] && SELECTOR_ARGS="$SELECTOR_ARGS --track $TRACK_FILTER"
[ -n "$RISK_FILTER" ] && SELECTOR_ARGS="$SELECTOR_ARGS --risk $RISK_FILTER"
[ -n "$ONLY_FILTER" ] && SELECTOR_ARGS="$SELECTOR_ARGS --only $ONLY_FILTER"
[ -n "$RANDOM_N" ] && SELECTOR_ARGS="$SELECTOR_ARGS --random $RANDOM_N"

SELECTED_IDS=$(python3 "$SCRIPT_DIR/selector.py" $SELECTOR_ARGS 2>&1)
if [ $? -ne 0 ]; then
    echo "ERROR: $SELECTED_IDS" >&2
    exit 1
fi

SCENARIO_COUNT=$(echo "$SELECTED_IDS" | wc -l)
echo "Selected $SCENARIO_COUNT scenarios."
echo ""
```

- [ ] **Step 3: Add load mode implementation**

After the scenario selection block, add the load mode branch:

```bash
STATE_FILE="/tmp/androdr-loaded-packages.txt"

if [ "$MODE" = "load" ] || [ "$MODE" = "guided" ]; then
    # ── Batch install all selected scenarios ─────────────────────────────
    > "$STATE_FILE"  # clear state file

    for scenario_id in $SELECTED_IDS; do
        source=$(get_field "$scenario_id" "source")
        sha256=$(get_field "$scenario_id" "sha256")
        fixture=$(get_field "$scenario_id" "fixture")
        apk_path=""

        case "$source" in
            malwarebazaar)
                if [ -z "${MALWAREBAZAAR_API_KEY:-}" ]; then
                    echo "  SKIP $scenario_id — no API key"
                    continue
                fi
                if [ "$sha256" = "<pin>" ] || [ -z "$sha256" ]; then
                    echo "  SKIP $scenario_id — SHA256 not pinned"
                    continue
                fi
                echo "  Downloading $scenario_id..."
                curl -s -X POST https://mb-api.abuse.ch/api/v1/ \
                    -d "query=get_file&sha256_hash=$sha256" \
                    -H "Auth-Key: $MALWAREBAZAAR_API_KEY" \
                    -o "$WORKDIR/sample-${scenario_id}.zip"
                cd "$WORKDIR"
                7z x -pinfected -aoa -o"$WORKDIR" "sample-${scenario_id}.zip" >/dev/null 2>&1 || true
                apk_path=$(find "$WORKDIR" -name "*.apk" -newer "$WORKDIR/sample-${scenario_id}.zip" | head -1 || true)
                [ -z "$apk_path" ] && apk_path="$WORKDIR/${sha256}.apk"
                [ -f "$apk_path" ] || apk_path="$WORKDIR/$sha256"
                if [ ! -f "$apk_path" ]; then
                    echo "  FAIL $scenario_id — could not extract"
                    continue
                fi
                ;;
            fixture)
                apk_path="$SCRIPT_DIR/$fixture"
                [ -f "$apk_path" ] || { echo "  FAIL $scenario_id — fixture not found"; continue; }
                ;;
            adb_inject) ;;
            *) continue ;;
        esac

        # Install APK
        if [ -n "$apk_path" ]; then
            echo "  Installing $scenario_id..."
            if $ADB install -t "$apk_path" 2>&1 | tail -1 | grep -q "Success"; then
                local_pkg=$(get_pkg_name "$apk_path")
                [ -n "$local_pkg" ] && echo "$local_pkg" >> "$STATE_FILE"
                INSTALLED_PACKAGES+=("$local_pkg")
                echo "  Installed: $local_pkg"
            else
                echo "  WARNING: $scenario_id install may have failed"
            fi
        fi

        # Inject
        if [ "$source" = "adb_inject" ]; then
            while IFS= read -r cmd; do
                [ -z "$cmd" ] && continue
                echo "  Injecting ($scenario_id): adb $cmd"
                $ADB $cmd 2>/dev/null || true
            done < <(get_inject_cmds "$scenario_id")
        fi

        # Seed IOC DB
        if [ "$scenario_id" = "mercenary_cert_hash" ] && [ -n "$apk_path" ]; then
            echo "  Seeding cert hash..."
            cert_hash=$(keytool -printcert -jarfile "$apk_path" 2>/dev/null | grep "SHA256:" | head -1 | awk '{print $2}' | tr -d ':' | tr 'A-F' 'a-f')
            if [ -n "$cert_hash" ]; then
                $ADB shell "run-as com.androdr.debug sqlite3 /data/data/com.androdr.debug/databases/androdr.db \
                    \"INSERT OR REPLACE INTO cert_hash_ioc_entries \
                    (certHash, familyName, category, severity, description, source, fetchedAt) \
                    VALUES ('$cert_hash', 'Test Fixture', 'TEST', 'CRITICAL', \
                    'Adversary simulation test cert', 'adversary-test', $(date +%s000));\"" 2>/dev/null || true
            fi
        fi
    done

    # Trigger ONE scan
    echo ""
    echo "  Triggering scan..."
    $ADB shell am broadcast -a com.androdr.ACTION_SCAN -n com.androdr.debug/com.androdr.debug.ScanBroadcastReceiver >/dev/null 2>&1
    sleep 15

    # Pull report
    REPORT="$WORKDIR/androdr-loaded.txt"
    $ADB pull /sdcard/Android/data/com.androdr.debug/files/androdr_last_report.txt "$REPORT" 2>/dev/null || true

    installed_count=$(wc -l < "$STATE_FILE" 2>/dev/null || echo 0)

    echo ""
    echo "============================================================"
    echo "  AndroDR loaded with $installed_count samples."
    echo "  Open the app on the emulator to explore."
    echo ""
    echo "  Press ENTER when done to clean up."
    echo "  (If interrupted: ./test-adversary/cleanup.sh $SERIAL)"
    echo "============================================================"

    if [ "$MODE" = "load" ]; then
        read -r _
        exit 0  # cleanup trap fires
    fi

    # Guided mode continues below...
fi
```

- [ ] **Step 4: Add get_pkg_name helper**

Add after the existing YAML helpers (after line 159):

```bash
# Extracts package name from an APK file
get_pkg_name() {
    local apk="$1"
    local pkg=""
    if [ -n "${ANDROID_HOME:-}" ]; then
        local aapt_bin="$ANDROID_HOME/build-tools/$(ls "$ANDROID_HOME/build-tools/" 2>/dev/null | sort -V | tail -1)/aapt2"
        pkg=$("$aapt_bin" dump packagename "$apk" 2>/dev/null || true)
    fi
    [ -z "$pkg" ] && pkg=$(aapt2 dump packagename "$apk" 2>/dev/null || true)
    echo "$pkg"
}
```

- [ ] **Step 5: Update main loop to use SELECTED_IDS for regression mode**

Replace the existing main loop (lines 371-374):

```bash
# ── Main loop (regression mode) ─────────────────────────────────────────────
if [ "$MODE" = "regression" ] || [ "$MODE" = "" ]; then
    for scenario_id in $SELECTED_IDS; do
        run_scenario "$scenario_id" || true
    done
fi
```

- [ ] **Step 6: Verify load mode works**

Run: `./test-adversary/run.sh --load --track 3 --no-pause emulator-5554 2>&1 | head -30`

Expected: installs Track 3 fixtures, triggers scan, shows summary.

- [ ] **Step 7: Commit**

```bash
git add test-adversary/run.sh
git commit -m "feat: add --load mode with composable selection filters to run.sh"
```

---

## Task 6: run.sh — Guided Mode

**Files:**
- Modify: `test-adversary/run.sh`

- [ ] **Step 1: Add guided mode category walkthrough**

After the `if [ "$MODE" = "load" ]` block (which exits after ENTER), add the guided continuation:

```bash
# ── Guided mode: category walkthrough ────────────────────────────────────────

CATEGORY_MAP=(
    "1:Device Posture:device_auditor rules"
    "2:Commodity Malware:Track 1 — sideloaded app detection"
    "3:Stalkerware:Track 2 — surveillance permission clusters"
    "4:Mercenary Simulation:Track 3 — IOC matches, impersonation, abuse patterns"
    "5:CVE Detection:Track 4 — unpatched CVEs, campaign attribution"
    "6:Network:DNS/IP scenarios"
)

# Map tracks to category indices
track_to_cat() {
    case "$1" in
        1) echo 2 ;; 2) echo 3 ;; 3) echo 4 ;; 4) echo 5 ;;
        *) echo 6 ;;
    esac
}

# Determine which categories have scenarios
declare -A ACTIVE_CATS
ACTIVE_CATS[1]=true  # Device posture always active
for scenario_id in $SELECTED_IDS; do
    t=$(get_field "$scenario_id" "track")
    cat_idx=$(track_to_cat "$t")
    ACTIVE_CATS[$cat_idx]=true
done

# Also check for adb_inject DNS/IP scenarios
for scenario_id in $SELECTED_IDS; do
    src=$(get_field "$scenario_id" "source")
    if [ "$src" = "adb_inject" ]; then
        t=$(get_field "$scenario_id" "track")
        if [ "$t" = "3" ]; then
            desc=$(get_field "$scenario_id" "description")
            if echo "$desc" | grep -qiE "dns|ip|c2"; then
                ACTIVE_CATS[6]=true
            fi
        fi
    fi
done

GUIDED_PASS=0
GUIDED_FAIL=0
GUIDED_EXPECTED=0

for cat_entry in "${CATEGORY_MAP[@]}"; do
    IFS=: read -r cat_idx cat_name cat_desc <<< "$cat_entry"
    [ "${ACTIVE_CATS[$cat_idx]:-}" = "true" ] || continue

    echo ""
    echo "═══════════════════════════════════════════════════"
    echo "  CATEGORY $cat_idx: $cat_name"
    echo "═══════════════════════════════════════════════════"
    echo "  $cat_desc"
    echo ""

    if [ "$cat_idx" = "1" ]; then
        echo "  Check the Device tab in AndroDR."
        echo ""
        echo "  Report assertions:"
        # Assert device check patterns
        for pattern in "USB Debugging" "Screen Lock" "CVEs"; do
            if grep -qF "$pattern" "$REPORT" 2>/dev/null; then
                echo "  ✓ \"$pattern\" found"
                ((GUIDED_PASS++)) || true
            else
                echo "  ✗ \"$pattern\" not found"
                ((GUIDED_FAIL++)) || true
            fi
        done
    else
        # Assert patterns for scenarios in this category
        for scenario_id in $SELECTED_IDS; do
            t=$(get_field "$scenario_id" "track")
            sc=$(track_to_cat "$t")
            [ "$sc" = "$cat_idx" ] || continue

            roadmap=$(get_field "$scenario_id" "roadmap_issue")
            patterns_file="$EXPECTED_DIR/${scenario_id}.patterns"
            [ -f "$patterns_file" ] || continue

            echo "  Scenario: $scenario_id"
            while IFS= read -r pattern || [ -n "$pattern" ]; do
                [ -z "$pattern" ] && continue
                if grep -qF "$pattern" "$REPORT" 2>/dev/null; then
                    echo "    ✓ \"$pattern\""
                    ((GUIDED_PASS++)) || true
                else
                    if [ -n "$roadmap" ] && [ "$roadmap" != "None" ] && [ "$roadmap" != "" ]; then
                        echo "    ○ \"$pattern\" (expected fail — roadmap #$roadmap)"
                        ((GUIDED_EXPECTED++)) || true
                    else
                        echo "    ✗ \"$pattern\" MISS"
                        ((GUIDED_FAIL++)) || true
                    fi
                fi
            done < "$patterns_file"
        done
    fi

    echo ""
    echo "  Press ENTER to continue..."
    read -r _
done

echo ""
echo "═══════════════════════════════════════════════════"
echo "  GUIDED SUMMARY"
echo "═══════════════════════════════════════════════════"
echo "  Assertions: $GUIDED_PASS passed, $GUIDED_FAIL failed, $GUIDED_EXPECTED expected fail"
echo ""
echo "  Press ENTER to clean up."
read -r _
```

- [ ] **Step 2: Verify guided mode works**

Run: `./test-adversary/run.sh --guided --track 3 emulator-5554`

Expected: installs Track 3, scans, walks through Mercenary Simulation category with assertions, pauses at each.

- [ ] **Step 3: Commit**

```bash
git add test-adversary/run.sh
git commit -m "feat: add --guided mode with category walkthrough and inline assertions"
```

---

## Task 7: Integration Test + README Update

**Files:**
- Modify: `test-adversary/README.md`

- [ ] **Step 1: Run selector tests**

Run: `cd test-adversary && python3 test_selection.py -v`

Expected: all 11 tests pass.

- [ ] **Step 2: Run regression mode (quick sanity)**

Run: `./test-adversary/run.sh --no-pause --track 4 emulator-5554 2>&1 | tail -20`

Expected: Track 4 CVE scenarios run and produce PASS/FAIL results.

- [ ] **Step 3: Test load mode**

Run: `./test-adversary/run.sh --load --track 3 --no-pause emulator-5554 2>&1`

Note: `--no-pause` with `--load` should auto-press ENTER (or we use a timeout). For testing, pipe ENTER: `echo | ./test-adversary/run.sh --load --track 3 emulator-5554 2>&1 | tail -20`

Expected: installs fixtures, scans, shows summary, cleans up.

- [ ] **Step 4: Test cleanup.sh**

Run: `echo | ./test-adversary/run.sh --load --track 3 emulator-5554` then Ctrl+C midway, then `./test-adversary/cleanup.sh emulator-5554`

Expected: cleanup removes packages listed in state file.

- [ ] **Step 5: Update README.md**

Add sections for new modes:

```markdown
## Modes

### Regression (default)
Sequential per-scenario install→scan→diff→cleanup:
```bash
./test-adversary/run.sh emulator-5554              # interactive
./test-adversary/run.sh --no-pause emulator-5554   # unattended
```

### Load (interactive exploration)
Install all selected samples, scan once, explore manually:
```bash
./test-adversary/run.sh --load emulator-5554
./test-adversary/run.sh --load --profile pegasus emulator-5554
./test-adversary/run.sh --load --track 1,3 --risk high emulator-5554
./test-adversary/run.sh --load --random 5 emulator-5554
```

### Guided (hybrid walkthrough)
Install, scan, then guided category-by-category review with assertions:
```bash
./test-adversary/run.sh --guided emulator-5554
./test-adversary/run.sh --guided --profile journalist emulator-5554
```

## Selection Filters

| Flag | Example | Effect |
|------|---------|--------|
| `--profile` | `--profile pegasus` | Select scenarios from a named profile |
| `--track` | `--track 1,3` | Filter by track number |
| `--risk` | `--risk high,medium` | Filter by risk level |
| `--only` | `--only cerberus_banker` | Select specific scenarios (overrides other filters) |
| `--random` | `--random 5` | Random sample (weighted by risk) |

## Profiles

| Profile | Description |
|---------|-------------|
| `pegasus` | NSO Group Pegasus mercenary spyware |
| `predator` | Intellexa Predator |
| `graphite` | Paragon Graphite |
| `journalist` | Journalist/activist threat model |
| `banking` | Banking trojan landscape |
| `stalkerware` | Commercial stalkerware |
| `full` | All scenarios |

## Cleanup

If `--load` or `--guided` is interrupted:
```bash
./test-adversary/cleanup.sh emulator-5554
```
```

- [ ] **Step 6: Commit**

```bash
git add test-adversary/README.md
git commit -m "docs: update README with load, guided, and filter documentation"
```
