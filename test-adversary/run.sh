#!/usr/bin/env bash
# test-adversary/run.sh — AndroDR adversary simulation test harness
# Usage: ./run.sh <emulator-serial>
# Prerequisites: Linux host, MALWAREBAZAAR_API_KEY set, emulator running with com.androdr.debug installed
set -euo pipefail

MODE="regression"
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
SERIAL="${1:?Usage: $0 [--load|--guided] [--profile X] [--track N] [--risk high,medium] [--random N] [--only a,b] [--no-pause] <emulator-serial>}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
MANIFEST="$SCRIPT_DIR/manifest.yml"
EXPECTED_DIR="$SCRIPT_DIR/fixtures/expected"
FIXTURE_DIR="$SCRIPT_DIR/fixtures/mercenary"

# Resolve adb from ANDROID_HOME if not on PATH
if command -v adb &>/dev/null; then
    ADB="adb -s $SERIAL"
elif [ -n "${ANDROID_HOME:-}" ] && [ -x "$ANDROID_HOME/platform-tools/adb" ]; then
    ADB="$ANDROID_HOME/platform-tools/adb -s $SERIAL"
else
    echo "ERROR: adb not found. Set ANDROID_HOME or add adb to PATH." >&2
    exit 1
fi
WORKDIR=$(mktemp -d /tmp/androdr-adversary-XXXXXX)

# Track results for summary
declare -A RESULTS

# Cleanup trap — always restore network and uninstall test APKs
INSTALLED_PACKAGES=()

cleanup() {
    echo ""
    echo ">>> Cleaning up..."
    for pkg in "${INSTALLED_PACKAGES[@]+"${INSTALLED_PACKAGES[@]}"}"; do
        $ADB uninstall "$pkg" 2>/dev/null || true
    done
    # Restore network inside emulator
    if ! ${SKIP_ISOLATION:-true}; then
        $ADB shell svc wifi enable 2>/dev/null || true
        $ADB shell svc data enable 2>/dev/null || true
    fi
    rm -rf "$WORKDIR"
}
trap cleanup EXIT

# ── Preflight ─────────────────────────────────────────────────────────────────

echo "=== AndroDR Adversary Simulation ==="
echo ""

# Network isolation uses adb shell svc wifi/data disable — works on any host OS

# Check emulator online
if ! $ADB get-state 2>/dev/null | grep -q "device"; then
    echo "ERROR: Emulator $SERIAL not found or not online." >&2
    echo "Available devices:" >&2
    $ADB devices >&2
    exit 1
fi

# Check AndroDR installed
if ! $ADB shell pm list packages 2>/dev/null | grep -q "com.androdr.debug"; then
    echo "ERROR: com.androdr.debug not installed on $SERIAL." >&2
    exit 1
fi

# Check YAML parser (python3+PyYAML required for inject command extraction)
if ! python3 -c "import yaml" 2>/dev/null; then
    echo "ERROR: python3 with PyYAML required. Install: pip3 install pyyaml" >&2
    exit 1
fi

# Check 7z (needed for AES-encrypted MalwareBazaar ZIPs)
if ! command -v 7z &>/dev/null; then
    echo "WARNING: 7z not found — Track 1 & 2 downloads will fail. Install: sudo apt install p7zip-full"
fi

# Check MalwareBazaar key (only warn — not needed for fixture-only runs)
if [ -z "${MALWAREBAZAAR_API_KEY:-}" ]; then
    echo "WARNING: MALWAREBAZAAR_API_KEY not set — Track 1 & 2 scenarios will be skipped."
fi

echo "Preflight OK. Serial=$SERIAL"
echo ""

# Launch AndroDR once to populate IOC database from bundled data
echo "Launching AndroDR to populate IOC database..."
$ADB shell am start -n com.androdr.debug/com.androdr.MainActivity >/dev/null 2>&1
sleep 8
echo "IOC database populated."
echo ""

# ── Scenario selection ───────────────────────────────────────────────────────

SELECTOR_ARGS="$MANIFEST"
[ -n "$PROFILE" ] && SELECTOR_ARGS="$SELECTOR_ARGS --profile $PROFILE"
[ -n "$TRACK_FILTER" ] && SELECTOR_ARGS="$SELECTOR_ARGS --track $TRACK_FILTER"
[ -n "$RISK_FILTER" ] && SELECTOR_ARGS="$SELECTOR_ARGS --risk $RISK_FILTER"
[ -n "$ONLY_FILTER" ] && SELECTOR_ARGS="$SELECTOR_ARGS --only $ONLY_FILTER"
[ -n "$RANDOM_N" ] && SELECTOR_ARGS="$SELECTOR_ARGS --random $RANDOM_N"

SELECTED_IDS=$(python3 "$SCRIPT_DIR/selector.py" $SELECTOR_ARGS)
if [ $? -ne 0 ] || [ -z "$SELECTED_IDS" ]; then
    echo "ERROR: No scenarios selected. Check your filters." >&2
    exit 1
fi

SCENARIO_COUNT=$(echo "$SELECTED_IDS" | wc -l)
echo "Selected $SCENARIO_COUNT scenarios."
echo ""

# ── YAML helpers ──────────────────────────────────────────────────────────────

# Extracts a field from a scenario block. Usage: get_field <scenario_id> <field>
get_field() {
    local id="$1" field="$2"
    python3 -c "
import yaml
with open('$MANIFEST') as f:
    m = yaml.safe_load(f)
for s in m['scenarios']:
    if s['id'] == '$id':
        v = s.get('$field', '')
        if isinstance(v, list):
            print('\n'.join(str(x) for x in v))
        else:
            print(v if v else '')
        break
" 2>/dev/null
}

# Returns all scenario IDs
get_scenario_ids() {
    python3 -c "
import yaml
with open('$MANIFEST') as f:
    m = yaml.safe_load(f)
for s in m['scenarios']:
    print(s['id'])
"
}

# Returns inject commands for adb_inject scenarios
get_inject_cmds() {
    local id="$1"
    python3 -c "
import yaml
with open('$MANIFEST') as f:
    m = yaml.safe_load(f)
for s in m['scenarios']:
    if s['id'] == '$id' and 'inject' in s:
        for inj in s['inject']:
            print(inj.get('adb_cmd', ''))
"
}

get_cleanup_cmds() {
    local id="$1"
    python3 -c "
import yaml
with open('$MANIFEST') as f:
    m = yaml.safe_load(f)
for s in m['scenarios']:
    if s['id'] == '$id' and 'inject' in s:
        for inj in s['inject']:
            c = inj.get('cleanup', '')
            if c:
                print(c)
"
}

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

# ── Per-scenario execution ────────────────────────────────────────────────────

run_scenario() {
    local id="$1"
    local source track sha256 fixture roadmap_issue pkg_name apk_path

    source=$(get_field "$id" "source")
    track=$(get_field "$id" "track")
    roadmap_issue=$(get_field "$id" "roadmap_issue")
    sha256=$(get_field "$id" "sha256")
    fixture=$(get_field "$id" "fixture")

    echo "──────────────────────────────────────────────────────────"
    echo "  Scenario: $id  (Track $track, source=$source)"
    echo "──────────────────────────────────────────────────────────"

    apk_path=""

    # Step 1: DOWNLOAD / LOCATE APK
    case "$source" in
        malwarebazaar)
            if [ -z "${MALWAREBAZAAR_API_KEY:-}" ]; then
                echo "  SKIPPED — MALWAREBAZAAR_API_KEY not set"
                RESULTS[$id]="SKIPPED"
                return
            fi
            if [ "$sha256" = "<pin>" ] || [ -z "$sha256" ]; then
                echo "  SKIPPED — SHA256 not pinned in manifest"
                RESULTS[$id]="SKIPPED"
                return
            fi
            echo "  Downloading from MalwareBazaar..."
            curl -s -X POST https://mb-api.abuse.ch/api/v1/ \
                -d "query=get_file&sha256_hash=$sha256" \
                -H "Auth-Key: $MALWAREBAZAAR_API_KEY" \
                -o "$WORKDIR/sample.zip"
            cd "$WORKDIR"
            7z x -pinfected -aoa -o"$WORKDIR" sample.zip >/dev/null 2>&1 || true
            # MalwareBazaar zips contain the file named <sha256>.apk
            apk_path="$WORKDIR/${sha256}.apk"
            if [ ! -f "$apk_path" ]; then
                apk_path="$WORKDIR/$sha256"
            fi
            if [ ! -f "$apk_path" ]; then
                apk_path=$(find "$WORKDIR" -name "*.apk" | head -1 || true)
            fi
            if [ ! -f "$apk_path" ]; then
                echo "  FAIL — could not extract sample from ZIP"
                RESULTS[$id]="FAIL"
                return
            fi
            # Verify hash
            actual_hash=$(sha256sum "$apk_path" | awk '{print $1}')
            if [ "$actual_hash" != "$sha256" ]; then
                echo "  FAIL — SHA256 mismatch: expected $sha256, got $actual_hash"
                RESULTS[$id]="FAIL"
                return
            fi
            ;;
        fixture)
            apk_path="$SCRIPT_DIR/$fixture"
            if [ ! -f "$apk_path" ]; then
                echo "  FAIL — fixture APK not found: $apk_path"
                echo "  Run: cd test-adversary/fixtures/mercenary && ./build-fixtures.sh"
                RESULTS[$id]="FAIL"
                return
            fi
            ;;
        adb_inject)
            # No APK to install
            ;;
        *)
            echo "  FAIL — unknown source: $source"
            RESULTS[$id]="FAIL"
            return
            ;;
    esac

    # Step 2: NETWORK CUT (optional — malware APKs are installed but never executed)
    if ! $SKIP_ISOLATION; then
        $ADB shell svc wifi disable 2>/dev/null || true
        $ADB shell svc data disable 2>/dev/null || true
        echo "  Network isolated"
    fi

    # Step 3: INSTALL
    if [ -n "$apk_path" ]; then
        echo "  Installing $apk_path..."
        if $ADB install -t "$apk_path" 2>&1 | tail -1 | grep -q "Success"; then
            # Extract package name: use aapt2 if available, then grep pm list
            pkg_name=$(aapt2 dump packagename "$apk_path" 2>/dev/null || true)
            if [ -z "$pkg_name" ] && [ -n "${ANDROID_HOME:-}" ]; then
                local aapt_bin="$ANDROID_HOME/build-tools/$(ls "$ANDROID_HOME/build-tools/" 2>/dev/null | sort -V | tail -1)/aapt2"
                pkg_name=$("$aapt_bin" dump packagename "$apk_path" 2>/dev/null || true)
            fi
            if [ -z "$pkg_name" ]; then
                # Last resort: diff pm list before/after install
                pkg_name=$($ADB shell pm list packages 2>/dev/null | tail -1 | sed 's/package://' || true)
            fi
            if [ -n "$pkg_name" ]; then
                INSTALLED_PACKAGES+=("$pkg_name")
            fi
            echo "  Installed: $pkg_name"
        else
            echo "  WARNING: install may have failed"
        fi
    fi

    # Step 4: INJECT (adb_inject scenarios)
    if [ "$source" = "adb_inject" ]; then
        while IFS= read -r cmd; do
            [ -z "$cmd" ] && continue
            echo "  Injecting: adb $cmd"
            $ADB $cmd 2>/dev/null || true
        done < <(get_inject_cmds "$id")
    fi

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

    # Step 6: TRIGGER SCAN
    echo "  Triggering scan..."
    $ADB shell am broadcast -a com.androdr.ACTION_SCAN -p com.androdr.debug >/dev/null 2>&1
    sleep 12

    # Step 6: PULL REPORT
    local report="$WORKDIR/androdr-${id}.txt"
    $ADB pull /sdcard/Android/data/com.androdr.debug/files/androdr_last_report.txt "$report" 2>/dev/null || true

    # Step 7: NETWORK RESTORE
    if ! $SKIP_ISOLATION; then
        $ADB shell svc wifi enable 2>/dev/null || true
        $ADB shell svc data enable 2>/dev/null || true
        echo "  Network restored"
    fi

    # Step 8: UI REVIEW
    if ! $NO_PAUSE; then
        echo ""
        echo "  >>> Review AndroDR UI on the emulator. Press ENTER to continue."
        read -r _
    fi

    # Step 9: DIFF
    local patterns_file="$EXPECTED_DIR/${id}.patterns"
    local fail=false
    if [ ! -f "$report" ]; then
        echo "  Could not pull report — no file at expected path"
        fail=true
    elif [ ! -f "$patterns_file" ]; then
        echo "  No patterns file: $patterns_file"
        fail=true
    else
        while IFS= read -r pattern || [ -n "$pattern" ]; do
            [ -z "$pattern" ] && continue
            if ! grep -qF "$pattern" "$report"; then
                echo "  MISS: pattern not found: '$pattern'"
                fail=true
            fi
        done < "$patterns_file"
    fi

    # Step 10: RESULT
    if $fail; then
        if [ -n "$roadmap_issue" ] && [ "$roadmap_issue" != "None" ] && [ "$roadmap_issue" != "" ]; then
            echo "  → EXPECTED FAIL (roadmap #$roadmap_issue)"
            RESULTS[$id]="EXPECTED FAIL (#$roadmap_issue)"
        else
            echo "  → FAIL"
            RESULTS[$id]="FAIL"
        fi
    else
        echo "  → PASS"
        RESULTS[$id]="PASS"
    fi

    # Step 11: CLEANUP
    if [ "$source" = "adb_inject" ]; then
        while IFS= read -r cmd; do
            [ -z "$cmd" ] && continue
            $ADB $cmd 2>/dev/null || true
        done < <(get_cleanup_cmds "$id")
    fi
    if [ -n "${pkg_name:-}" ]; then
        $ADB uninstall "$pkg_name" >/dev/null 2>&1 || true
        # Remove from tracked array (safe for empty arrays)
        local new_arr=()
        for p in "${INSTALLED_PACKAGES[@]+"${INSTALLED_PACKAGES[@]}"}"; do
            [ "$p" != "$pkg_name" ] && new_arr+=("$p")
        done
        INSTALLED_PACKAGES=("${new_arr[@]+"${new_arr[@]}"}")
    fi
    echo ""
}

STATE_FILE="/tmp/androdr-loaded-packages.txt"

if [ "$MODE" = "load" ] || [ "$MODE" = "guided" ]; then
    # ── Batch install all selected scenarios ─────────────────────────────
    > "$STATE_FILE"

    for scenario_id in $SELECTED_IDS; do
        source=$(get_field "$scenario_id" "source")
        sha256=$(get_field "$scenario_id" "sha256")
        fixture=$(get_field "$scenario_id" "fixture")
        apk_path=""

        case "$source" in
            malwarebazaar)
                if [ -z "${MALWAREBAZAAR_API_KEY:-}" ]; then
                    echo "  SKIP $scenario_id — no API key"; continue
                fi
                if [ "$sha256" = "<pin>" ] || [ -z "$sha256" ]; then
                    echo "  SKIP $scenario_id — SHA256 not pinned"; continue
                fi
                echo "  Downloading $scenario_id..."
                curl -s -X POST https://mb-api.abuse.ch/api/v1/ \
                    -d "query=get_file&sha256_hash=$sha256" \
                    -H "Auth-Key: $MALWAREBAZAAR_API_KEY" \
                    -o "$WORKDIR/sample-${scenario_id}.zip"
                cd "$WORKDIR"
                7z x -pinfected -aoa -o"$WORKDIR" "sample-${scenario_id}.zip" >/dev/null 2>&1 || true
                apk_path="$WORKDIR/${sha256}.apk"
                [ -f "$apk_path" ] || apk_path="$WORKDIR/$sha256"
                [ -f "$apk_path" ] || apk_path=$(find "$WORKDIR" -name "*.apk" -newer "$WORKDIR/sample-${scenario_id}.zip" 2>/dev/null | head -1 || true)
                [ -f "$apk_path" ] || { echo "  FAIL $scenario_id — could not extract"; continue; }
                ;;
            fixture)
                apk_path="$SCRIPT_DIR/$fixture"
                [ -f "$apk_path" ] || { echo "  FAIL $scenario_id — fixture not found: $apk_path"; continue; }
                ;;
            adb_inject) ;;
            *) continue ;;
        esac

        if [ -n "$apk_path" ]; then
            echo "  Installing $scenario_id..."
            if $ADB install -t "$apk_path" 2>&1 | tail -1 | grep -q "Success"; then
                local_pkg=$(get_pkg_name "$apk_path")
                [ -n "$local_pkg" ] && echo "$local_pkg" >> "$STATE_FILE"
                INSTALLED_PACKAGES+=("${local_pkg:-unknown}")
                echo "  Installed: $local_pkg"
            else
                echo "  WARNING: $scenario_id install may have failed"
            fi
        fi

        if [ "$source" = "adb_inject" ]; then
            while IFS= read -r cmd; do
                [ -z "$cmd" ] && continue
                echo "  Injecting ($scenario_id): adb $cmd"
                $ADB $cmd 2>/dev/null || true
            done < <(get_inject_cmds "$scenario_id")
        fi

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

    echo ""
    echo "  Triggering scan..."
    $ADB shell am broadcast -a com.androdr.ACTION_SCAN -n com.androdr.debug/com.androdr.debug.ScanBroadcastReceiver >/dev/null 2>&1
    sleep 15

    REPORT="$WORKDIR/androdr-loaded.txt"
    $ADB pull /sdcard/Android/data/com.androdr.debug/files/androdr_last_report.txt "$REPORT" 2>/dev/null || true

    installed_count=$(wc -l < "$STATE_FILE" 2>/dev/null || echo 0)

    echo ""
    echo "============================================================"
    echo "  AndroDR loaded with $installed_count samples."
    echo "  Open the app on the emulator to explore."
    echo ""
    if [ "$MODE" = "load" ]; then
        echo "  Press ENTER when done to clean up."
        echo "  (If interrupted: ./test-adversary/cleanup.sh $SERIAL)"
        echo "============================================================"
        read -r _
        exit 0
    fi

    # ── Guided mode: category walkthrough ────────────────────────────────
    echo "  Guided walkthrough starting. Press ENTER after each category."
    echo "  (If interrupted: ./test-adversary/cleanup.sh $SERIAL)"
    echo "============================================================"
    echo ""

    GUIDED_PASS=0
    GUIDED_FAIL=0
    GUIDED_EXPECTED=0

    # Category 1: Device Posture (always shown)
    echo "═══════════════════════════════════════════════════"
    echo "  CATEGORY 1: Device Posture"
    echo "═══════════════════════════════════════════════════"
    echo "  Check the Device tab in AndroDR."
    echo ""
    echo "  Report assertions:"
    for pattern in "USB Debugging" "Screen Lock" "CVEs"; do
        if grep -qF "$pattern" "$REPORT" 2>/dev/null; then
            echo "  ✓ \"$pattern\" found"
            ((GUIDED_PASS++)) || true
        else
            echo "  ✗ \"$pattern\" not found"
            ((GUIDED_FAIL++)) || true
        fi
    done
    echo ""
    echo "  Press ENTER to continue..."
    read -r _

    # Remaining categories by track
    declare -A TRACK_CATS
    TRACK_CATS[1]="Commodity Malware"
    TRACK_CATS[2]="Stalkerware"
    TRACK_CATS[3]="Mercenary Simulation"
    TRACK_CATS[4]="CVE Detection"

    cat_num=2
    for track_num in 1 2 3 4; do
        cat_name="${TRACK_CATS[$track_num]}"
        has_scenarios=false

        for scenario_id in $SELECTED_IDS; do
            t=$(get_field "$scenario_id" "track")
            [ "$t" = "$track_num" ] && has_scenarios=true && break
        done
        $has_scenarios || continue

        echo ""
        echo "═══════════════════════════════════════════════════"
        echo "  CATEGORY $cat_num: $cat_name"
        echo "═══════════════════════════════════════════════════"
        echo ""

        for scenario_id in $SELECTED_IDS; do
            t=$(get_field "$scenario_id" "track")
            [ "$t" = "$track_num" ] || continue

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

        echo ""
        echo "  Press ENTER to continue..."
        read -r _
        ((cat_num++)) || true
    done

    echo ""
    echo "═══════════════════════════════════════════════════"
    echo "  GUIDED SUMMARY"
    echo "═══════════════════════════════════════════════════"
    echo "  Assertions: $GUIDED_PASS passed, $GUIDED_FAIL failed, $GUIDED_EXPECTED expected fail"
    echo ""
    echo "  Press ENTER to clean up."
    read -r _
    exit 0
fi

# ── Main loop ─────────────────────────────────────────────────────────────────

# ── Regression mode ──────────────────────────────────────────────────────────
for scenario_id in $SELECTED_IDS; do
    run_scenario "$scenario_id" || true
done

# ── Summary ───────────────────────────────────────────────────────────────────

echo "============================================================"
echo "  SUMMARY"
echo "============================================================"
printf "  %-30s  %s\n" "SCENARIO" "RESULT"
printf "  %-30s  %s\n" "--------" "------"
for id in $SELECTED_IDS; do
    result="${RESULTS[$id]:-NOT RUN}"
    printf "  %-30s  %s\n" "$id" "$result"
done
echo "============================================================"

pass=$(echo "${RESULTS[@]}" | tr ' ' '\n' | grep -c "^PASS$" || true)
fail=$(echo "${RESULTS[@]}" | tr ' ' '\n' | grep -c "^FAIL$" || true)
expected=$(echo "${RESULTS[@]}" | tr ' ' '\n' | grep -c "^EXPECTED" || true)
skip=$(echo "${RESULTS[@]}" | tr ' ' '\n' | grep -c "^SKIP" || true)
echo "  PASS: $pass  FAIL: $fail  EXPECTED FAIL: $expected  SKIPPED: $skip"
echo "============================================================"
