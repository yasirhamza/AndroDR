#!/usr/bin/env bash
# test-adversary/run.sh — AndroDR adversary simulation test harness
# Usage: ./run.sh <emulator-serial>
# Prerequisites: Linux host, MALWAREBAZAAR_API_KEY set, emulator running with com.androdr.debug installed
set -euo pipefail

NO_PAUSE=false
if [ "${1:-}" = "--no-pause" ]; then
    NO_PAUSE=true
    shift
fi
SERIAL="${1:?Usage: $0 [--no-pause] <emulator-serial>}"
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
    $ADB shell svc wifi enable 2>/dev/null || true
    $ADB shell svc data enable 2>/dev/null || true
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

# Check MalwareBazaar key (only warn — not needed for fixture-only runs)
if [ -z "${MALWAREBAZAAR_API_KEY:-}" ]; then
    echo "WARNING: MALWAREBAZAAR_API_KEY not set — Track 1 & 2 scenarios will be skipped."
fi

echo "Preflight OK. Serial=$SERIAL"
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
                -d "query=get_file&sha256=$sha256" \
                -H "Auth-Key: $MALWAREBAZAAR_API_KEY" \
                -o "$WORKDIR/sample.zip"
            cd "$WORKDIR"
            unzip -q -o sample.zip 2>/dev/null || true
            # MalwareBazaar zips contain the file with its sha256 as the name
            apk_path="$WORKDIR/$sha256"
            if [ ! -f "$apk_path" ]; then
                # try finding any APK
                apk_path=$(find "$WORKDIR" -name "*.apk" -o -name "$sha256" | head -1)
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

    # Step 2: NETWORK CUT (disable network inside emulator — no sudo needed)
    $ADB shell svc wifi disable 2>/dev/null || true
    $ADB shell svc data disable 2>/dev/null || true
    echo "  Network isolated (wifi+data disabled inside emulator)"

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
        cert_hash=$(keytool -printcert -jarfile "$apk_path" 2>/dev/null | grep "SHA256:" | head -1 | awk '{print $2}' | tr -d ':')
        if [ -n "$cert_hash" ]; then
            # Push cert hash into Room DB via adb shell using sqlite3 (available on emulator)
            local db_path="/data/data/com.androdr.debug/databases/androdr.db"
            $ADB shell "run-as com.androdr.debug sqlite3 $db_path \
                \"INSERT OR REPLACE INTO ioc_entries (package_name, source_id, fetched_at) \
                VALUES ('cert:$cert_hash', 'adversary-test', $(date +%s000));\"" 2>/dev/null || \
                echo "  WARNING: Could not seed cert hash — roadmap #7 test will fail regardless"
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
    $ADB shell svc wifi enable 2>/dev/null || true
    $ADB shell svc data enable 2>/dev/null || true
    echo "  Network restored"

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

# ── Main loop ─────────────────────────────────────────────────────────────────

while IFS= read -r scenario_id; do
    run_scenario "$scenario_id" || true
done < <(get_scenario_ids)

# ── Summary ───────────────────────────────────────────────────────────────────

echo "============================================================"
echo "  SUMMARY"
echo "============================================================"
printf "  %-30s  %s\n" "SCENARIO" "RESULT"
printf "  %-30s  %s\n" "--------" "------"
for id in $(get_scenario_ids); do
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
