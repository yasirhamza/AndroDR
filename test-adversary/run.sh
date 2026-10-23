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
# Longer than DnsLogBuffer's 2 s flush interval: injected DNS must be stored before a scan starts.
DNS_FLUSH_WAIT_S=5
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

# Cleanup trap — always restore network, uninstall test APKs, and remove
# injected artifacts (files, properties, etc.) that adb_inject scenarios created.
INSTALLED_PACKAGES=()
INJECTED_SCENARIOS=()

cleanup() {
    echo ""
    echo ">>> Cleaning up..."
    for pkg in "${INSTALLED_PACKAGES[@]+"${INSTALLED_PACKAGES[@]}"}"; do
        $ADB uninstall "$pkg" 2>/dev/null || true
    done
    # Reverse every adb_inject scenario's cleanup commands from the manifest.
    # Without this, files like /data/local/tmp/.raptor persist across runs
    # and trip the spyware artifact rule on the next scan.
    for scenario_id in "${INJECTED_SCENARIOS[@]+"${INJECTED_SCENARIOS[@]}"}"; do
        while IFS= read -r cmd; do
            [ -z "$cmd" ] && continue
            $ADB $cmd </dev/null 2>/dev/null || true
        done < <(get_cleanup_cmds "$scenario_id")
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

# Launch AndroDR and trigger threat database update (IOCs + CVEs)
echo "Launching AndroDR and updating threat databases..."
$ADB shell am start -n com.androdr.debug/com.androdr.MainActivity </dev/null >/dev/null 2>&1
sleep 5
$ADB shell am broadcast -a com.androdr.ACTION_UPDATE -n com.androdr.debug/com.androdr.debug.ScanBroadcastReceiver </dev/null >/dev/null 2>&1
echo "  Waiting for CVE + IOC download (up to 45s)..."
sleep 45
echo "Threat databases updated."
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

# Install APK as sideloaded (no trusted installer).
# ADB install sets initiatingPackageName=com.android.shell which is treated as
# a trusted OEM installer. Push + pm install -i <real-pkg> uses a non-OEM
# installer so AndroDR correctly marks the app as sideloaded.
sideload_install() {
    local apk="$1"
    local remote="/data/local/tmp/$(basename "$apk")"
    $ADB push "$apk" "$remote" </dev/null >/dev/null 2>&1 || return 1
    $ADB shell pm install -t -i com.androdr.debug "$remote" </dev/null 2>&1 | tail -1 | grep -q "Success"
    local rc=$?
    $ADB shell rm -f "$remote" </dev/null 2>/dev/null
    return $rc
}

# ── Cert-hash IOC seeding (mercenary_cert_hash) ───────────────────────────────
#
# Writes the fixture's signing cert into the `indicators` table as a feed row, then
# makes the app reload its indicator cache. The INSERT's column list is the schema-19
# `indicators` entity (app/schemas/com.androdr.data.db.AppDatabase/19.json), pinned by
# test_run_sh_seed.py: a schema change fails CI instead of failing on a device.
# Category must be one IocSanitizer.CATEGORIES accepts; reference "" is what the
# mirror feeds store (attribution() derives feed:<source>#<family> at read time).
#
# Returns non-zero, with the reason on stdout, when any step fails, so the caller
# reports a setup failure. Before schema 19's column renames broke it, this step's
# errors went to /dev/null and the scenario simply never detected anything.
SEED_DB="/data/data/com.androdr.debug/databases/androdr.db"
SEED_UPDATE_TIMEOUT=300
# Logged only by IndicatorResolver.refreshCache(); see seed_cert_hash.
CACHE_REFRESH_TAG="IndicatorResolver"
CACHE_REFRESH_LINE="Indicator cache: "

seed_cert_hash() {
    local apk="$1" cert_hash n before after waited
    cert_hash=$(keytool -printcert -jarfile "$apk" 2>/dev/null | grep "SHA256:" | head -1 | awk '{print $2}' | tr -d ':' | tr 'A-F' 'a-f' || true)
    if [ -z "$cert_hash" ]; then
        echo "  could not read the fixture's signing cert (keytool -printcert)"
        return 1
    fi
    local sql="INSERT OR REPLACE INTO indicators (type, value, family, category, campaignKey, severity, description, source, reference, fetchedAt) VALUES ('cert_hash', '$cert_hash', 'Test Fixture', 'MALWARE', '', 'CRITICAL', 'Adversary simulation test cert', 'adversary-test', '', $(date +%s000));"
    if ! $ADB shell "run-as com.androdr.debug sqlite3 $SEED_DB \"$sql\"" </dev/null; then
        echo "  seeding INSERT failed (see the sqlite3 error above)"
        return 1
    fi
    # adb shell exit codes are not trusted on every image: read the row back.
    n=$($ADB shell "run-as com.androdr.debug sqlite3 $SEED_DB \"SELECT COUNT(*) FROM indicators WHERE type='cert_hash' AND value='$cert_hash';\"" </dev/null 2>&1 | tr -d '\r[:space:]')
    if [ "$n" != "1" ]; then
        echo "  seeded cert row not found in indicators (read back: '$n')"
        return 1
    fi
    # IndicatorResolver answers cert lookups from an in-memory cache built at app start
    # and after a feed update, never from Room directly. A threat-DB update ends in
    # refreshCache() and, unlike a force-stop, leaves the VPN running for DNS scenarios.
    # Wait for refreshCache()'s own line (IndicatorResolver "Indicator cache: ..."), not
    # the receiver's "Update complete": when another update holds IndicatorUpdater's
    # lock, update() returns without refreshing and the receiver still logs that. Any
    # refresh logged after the INSERT above has read the seeded row, including the
    # one that ends a concurrent update. Pinned by test_run_sh_seed.py.
    before=$($ADB logcat -d -s "$CACHE_REFRESH_TAG:I" </dev/null 2>/dev/null | grep -c "$CACHE_REFRESH_LINE" || true)
    $ADB shell am broadcast -a com.androdr.ACTION_UPDATE -n com.androdr.debug/com.androdr.debug.ScanBroadcastReceiver </dev/null >/dev/null 2>&1
    waited=0
    while [ $waited -lt $SEED_UPDATE_TIMEOUT ]; do
        after=$($ADB logcat -d -s "$CACHE_REFRESH_TAG:I" </dev/null 2>/dev/null | grep -c "$CACHE_REFRESH_LINE" || true)
        [ "${after:-0}" -gt "${before:-0}" ] && return 0
        sleep 3; waited=$((waited + 3))
    done
    echo "  indicator cache not reloaded: no '$CACHE_REFRESH_TAG: $CACHE_REFRESH_LINE' line within ${SEED_UPDATE_TIMEOUT}s"
    return 1
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
        baseline)
            # Nothing installed, nothing injected — the device as-is. Asserts what
            # the report says when there is no threat, which every other scenario
            # by construction cannot (#332).
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

    # Step 3: INSTALL (as sideloaded — no trusted installer)
    if [ -n "$apk_path" ]; then
        echo "  Installing $apk_path..."
        if sideload_install "$apk_path"; then
            pkg_name=$(get_pkg_name "$apk_path")
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
        INJECTED_SCENARIOS+=("$id")
        while IFS= read -r cmd; do
            [ -z "$cmd" ] && continue
            echo "  Injecting: adb $cmd"
            $ADB $cmd 2>/dev/null || true
        done < <(get_inject_cmds "$id")
        # The scan reads DNS from the stored log at its start, and DnsLogBuffer flushes every 2 s:
        # wait past one flush so an injected query is in the scan's own dns_monitor records.
        sleep "$DNS_FLUSH_WAIT_S"
    fi

    # Step 5: SEED IOC DB (cert-hash scenario only). A failed seed is a setup
    # failure: without the row the scenario cannot detect anything.
    if [ "$id" = "mercenary_cert_hash" ] && [ -n "$apk_path" ]; then
        echo "  Seeding cert hash into IOC DB..."
        if ! seed_cert_hash "$apk_path"; then
            echo "  FAIL — setup: cert hash IOC could not be seeded"
            RESULTS[$id]="FAIL"
            if [ -n "${pkg_name:-}" ]; then
                $ADB uninstall "$pkg_name" >/dev/null 2>&1 || true
            fi
            if ! $SKIP_ISOLATION; then
                $ADB shell svc wifi enable 2>/dev/null || true
                $ADB shell svc data enable 2>/dev/null || true
            fi
            return
        fi
    fi

    # Step 6: TRIGGER SCAN
    echo "  Triggering scan..."
    # Delete the previous report first; otherwise the poll loop below sees a
    # stale file from the initial threat-DB update or a prior scenario and pulls
    # the wrong scan output. Load mode does the same on its single-scan path.
    $ADB shell rm -f /sdcard/Android/data/com.androdr.debug/files/androdr_last_report.txt 2>/dev/null || true
    $ADB shell am broadcast -a com.androdr.ACTION_SCAN -n com.androdr.debug/com.androdr.debug.ScanBroadcastReceiver </dev/null >/dev/null 2>&1
    # Poll for report file instead of fixed sleep
    local waited=0
    while [ $waited -lt 60 ]; do
        if $ADB shell "[ -f /sdcard/Android/data/com.androdr.debug/files/androdr_last_report.txt ]" 2>/dev/null; then
            sleep 2; break  # small grace period after file appears
        fi
        sleep 2; waited=$((waited + 2))
    done

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
    # Assertions live in check-patterns.sh so they are unit-testable without a
    # device (test_check_patterns.py) — a `!`-prefixed line asserts absence.
    if ! bash "$SCRIPT_DIR/check-patterns.sh" "$report" "$patterns_file"; then
        fail=true
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
    SETUP_FAILED=()

    # Save stdin fd, redirect to /dev/null for install phase (ADB/keytool consume stdin)
    exec 3<&0 0</dev/null

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
            if sideload_install "$apk_path"; then
                local_pkg=$(get_pkg_name "$apk_path")
                [ -n "$local_pkg" ] && echo "$local_pkg" >> "$STATE_FILE"
                INSTALLED_PACKAGES+=("${local_pkg:-unknown}")
                echo "  Installed: $local_pkg"
            else
                echo "  WARNING: $scenario_id install may have failed"
            fi
        fi

        if [ "$source" = "adb_inject" ]; then
            INJECTED_SCENARIOS+=("$scenario_id")
            while IFS= read -r cmd; do
                [ -z "$cmd" ] && continue
                echo "  Injecting ($scenario_id): adb $cmd"
                $ADB $cmd </dev/null 2>/dev/null || true
            done < <(get_inject_cmds "$scenario_id")
        fi

        if [ "$scenario_id" = "mercenary_cert_hash" ] && [ -n "$apk_path" ]; then
            echo "  Seeding cert hash..."
            if ! seed_cert_hash "$apk_path"; then
                echo "  FAIL $scenario_id — setup: cert hash IOC could not be seeded"
                SETUP_FAILED+=("$scenario_id")
            fi
        fi
    done

    # Restore stdin for interactive prompts
    exec 0<&3 3<&-

    # Same flush wait as the per-scenario path, once for every injection above.
    sleep "$DNS_FLUSH_WAIT_S"

    echo ""
    echo "  Triggering scan..."
    # Delete old report so we can detect the new one
    $ADB shell rm /sdcard/Android/data/com.androdr.debug/files/androdr_last_report.txt 2>/dev/null || true
    $ADB shell am broadcast -a com.androdr.ACTION_SCAN -n com.androdr.debug/com.androdr.debug.ScanBroadcastReceiver </dev/null >/dev/null 2>&1
    # Poll for report file instead of fixed sleep
    scan_waited=0
    while [ $scan_waited -lt 90 ]; do
        if $ADB shell "[ -f /sdcard/Android/data/com.androdr.debug/files/androdr_last_report.txt ]" 2>/dev/null; then
            sleep 2; break
        fi
        sleep 2; scan_waited=$((scan_waited + 2))
    done

    REPORT="$WORKDIR/androdr-loaded.txt"
    $ADB pull /sdcard/Android/data/com.androdr.debug/files/androdr_last_report.txt "$REPORT" 2>/dev/null || true

    installed_count=$(wc -l < "$STATE_FILE" 2>/dev/null || echo 0)

    echo ""
    echo "============================================================"
    echo "  AndroDR loaded with $installed_count samples."
    if [ ${#SETUP_FAILED[@]} -gt 0 ]; then
        echo "  SETUP FAILED (do not trust these scenarios' results): ${SETUP_FAILED[*]}"
    fi
    echo "  Open the app on the emulator to explore."
    echo ""
    if [ "$MODE" = "load" ]; then
        if $NO_PAUSE; then
            echo "  Run ./test-adversary/cleanup.sh $SERIAL when done."
            echo "============================================================"
        else
            echo "  Press ENTER when done to clean up."
            echo "  (If interrupted: ./test-adversary/cleanup.sh $SERIAL)"
            echo "============================================================"
            read -r _
        fi
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
    TRACK_CATS[5]="Benign Baseline"

    cat_num=2
    for track_num in 1 2 3 4 5; do
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
                pattern="${pattern%$'\r'}"
                [ -z "$pattern" ] && continue
                case "$pattern" in '#'*) continue ;; esac
                # Every sigil (`!`, `~`, `!~`, record-scoped `@` / `!@`) means exactly what it
                # means to check-patterns.sh, the non-guided path: one assertion per run.
                one_pattern=$(mktemp)
                printf '%s\n' "$pattern" > "$one_pattern"
                if bash "$SCRIPT_DIR/check-patterns.sh" "$REPORT" "$one_pattern" >/dev/null 2>&1; then
                    satisfied=true
                else
                    satisfied=false
                fi
                rm -f "$one_pattern"
                label="$pattern"

                if [ "$satisfied" = true ]; then
                    echo "    ✓ \"$label\""
                    ((GUIDED_PASS++)) || true
                else
                    if [ -n "$roadmap" ] && [ "$roadmap" != "None" ] && [ "$roadmap" != "" ]; then
                        echo "    ○ \"$label\" (expected fail — roadmap #$roadmap)"
                        ((GUIDED_EXPECTED++)) || true
                    else
                        echo "    ✗ \"$label\" MISS"
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
FAIL_COUNT=0
for id in $SELECTED_IDS; do
    result="${RESULTS[$id]:-NOT RUN}"
    printf "  %-30s  %s\n" "$id" "$result"
    [ "$result" = "FAIL" ] && ((FAIL_COUNT++)) || true
done
echo "============================================================"
if [ "$FAIL_COUNT" -gt 0 ]; then
    echo "  $FAIL_COUNT scenario(s) FAILED"
    exit 1
fi

pass=$(echo "${RESULTS[@]}" | tr ' ' '\n' | grep -c "^PASS$" || true)
fail=$(echo "${RESULTS[@]}" | tr ' ' '\n' | grep -c "^FAIL$" || true)
expected=$(echo "${RESULTS[@]}" | tr ' ' '\n' | grep -c "^EXPECTED" || true)
skip=$(echo "${RESULTS[@]}" | tr ' ' '\n' | grep -c "^SKIP" || true)
echo "  PASS: $pass  FAIL: $fail  EXPECTED FAIL: $expected  SKIPPED: $skip"
echo "============================================================"
