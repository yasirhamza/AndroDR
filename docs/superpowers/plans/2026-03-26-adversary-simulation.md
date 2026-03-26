# Adversary Simulation Test Suite Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a developer-run end-to-end test harness that validates AndroDR's detection against real malware APKs and synthetic mercenary spyware artifacts.

**Architecture:** Shell harness (`run.sh`) orchestrates everything via ADB. One small app/ change adds a debug-only `ScanBroadcastReceiver`. Five fixture APKs are built from a standalone Gradle project under `test-adversary/fixtures/mercenary/`. No CI integration — manual UAT only.

**Tech Stack:** Bash, ADB, iptables, MalwareBazaar API, Android Gradle Plugin (fixture APKs), Hilt `@AndroidEntryPoint` (ScanBroadcastReceiver)

**Spec:** `docs/superpowers/specs/2026-03-26-adversary-simulation-design.md`

---

## File Structure

```
# New files
app/src/debug/AndroidManifest.xml                              # registers ScanBroadcastReceiver
app/src/debug/java/com/androdr/debug/ScanBroadcastReceiver.kt  # ACTION_SCAN → scan → export report

test-adversary/
├── manifest.yml                                               # hash-pinned scenario registry
├── run.sh                                                     # end-to-end UAT harness
├── README.md                                                  # developer instructions
├── fixtures/
│   ├── expected/                                              # per-scenario grep patterns (11 files)
│   │   ├── cerberus_banker.patterns
│   │   ├── spynote_rat.patterns
│   │   ├── flexispy_stalkerware.patterns
│   │   ├── mercenary_package_name.patterns
│   │   ├── mercenary_cert_hash.patterns
│   │   ├── mercenary_accessibility.patterns
│   │   ├── mercenary_device_admin.patterns
│   │   ├── surveillance_permissions.patterns
│   │   ├── mercenary_file_artifacts.patterns
│   │   ├── mercenary_dns_c2.patterns
│   │   └── mercenary_ip_c2.patterns
│   └── mercenary/                                             # fixture APK Gradle project
│       ├── build-fixtures.sh                                  # builds all 5 APKs + pins SHA256
│       ├── settings.gradle.kts
│       ├── build.gradle.kts                                   # root build (AGP plugin)
│       ├── cert-hash-ioc-keystore.jks                         # generated signing key (gitignored)
│       ├── spyware-package-name/
│       │   ├── build.gradle.kts
│       │   └── src/main/AndroidManifest.xml
│       ├── cert-hash-ioc/
│       │   ├── build.gradle.kts
│       │   └── src/main/AndroidManifest.xml
│       ├── accessibility-abuse/
│       │   ├── build.gradle.kts
│       │   └── src/main/AndroidManifest.xml
│       ├── device-admin-abuse/
│       │   ├── build.gradle.kts
│       │   └── src/main/
│       │       ├── AndroidManifest.xml
│       │       └── res/xml/device_admin.xml
│       └── surveillance-permissions/
│           ├── build.gradle.kts
│           └── src/main/AndroidManifest.xml

# Modified files
iocs/known_bad_packages.json                                   # add com.android.bsp (Pegasus disguise)
.gitignore                                                     # add fixture APK + keystore ignores
```

---

### Task 1: ScanBroadcastReceiver (debug-only)

**Files:**
- Create: `app/src/debug/AndroidManifest.xml`
- Create: `app/src/debug/java/com/androdr/debug/ScanBroadcastReceiver.kt`

**Context:** The harness needs a way to trigger a scan and retrieve the report via ADB. This receiver lives in the `debug` source set so it's excluded from release builds. It uses `goAsync()` to extend the 10-second BroadcastReceiver limit and runs the scan in a coroutine.

**Dependencies to inject:**
- `ScanOrchestrator` — `runFullScan()` returns `ScanResult`
- `DnsEventDao` — `getRecentSnapshot()` returns `List<DnsEvent>` (one-shot, not Flow)
- `ReportFormatter.formatScanReport(scan, dnsEvents, logLines)` — static, no injection needed

**Output path:** `/sdcard/Android/data/com.androdr.debug/files/androdr_last_report.txt` — world-readable via ADB without root.

- [ ] **Step 1: Create the debug AndroidManifest.xml**

```xml
<!-- app/src/debug/AndroidManifest.xml -->
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
    <application>
        <receiver
            android:name="com.androdr.debug.ScanBroadcastReceiver"
            android:exported="true">
            <intent-filter>
                <action android:name="com.androdr.ACTION_SCAN" />
            </intent-filter>
        </receiver>
    </application>
</manifest>
```

- [ ] **Step 2: Create ScanBroadcastReceiver.kt**

```kotlin
// app/src/debug/java/com/androdr/debug/ScanBroadcastReceiver.kt
package com.androdr.debug

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.util.Log
import com.androdr.data.db.DnsEventDao
import com.androdr.reporting.ReportFormatter
import com.androdr.scanner.ScanOrchestrator
import dagger.hilt.android.AndroidEntryPoint
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import java.io.File
import javax.inject.Inject

@AndroidEntryPoint
class ScanBroadcastReceiver : BroadcastReceiver() {

    @Inject lateinit var scanOrchestrator: ScanOrchestrator
    @Inject lateinit var dnsEventDao: DnsEventDao

    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != "com.androdr.ACTION_SCAN") return
        val pending = goAsync()
        CoroutineScope(Dispatchers.IO).launch {
            try {
                val scan = scanOrchestrator.runFullScan()
                val dns = dnsEventDao.getRecentSnapshot()
                val report = ReportFormatter.formatScanReport(scan, dns, emptyList())
                val outDir = context.getExternalFilesDir(null) ?: return@launch
                File(outDir, "androdr_last_report.txt").writeText(report)
                Log.i(TAG, "Scan complete, report written to ${outDir.absolutePath}")
            } catch (e: Exception) {
                Log.e(TAG, "Scan failed", e)
            } finally {
                pending.finish()
            }
        }
    }

    companion object {
        private const val TAG = "ScanBroadcastReceiver"
    }
}
```

- [ ] **Step 3: Build and verify**

Run: `export JAVA_HOME=/home/yasir/Applications/android-studio/jbr && ./gradlew assembleDebug`
Expected: BUILD SUCCESSFUL

Verify receiver is in the merged manifest:
Run: `grep -r "ScanBroadcastReceiver" app/build/intermediates/merged_manifests/debug/`
Expected: Shows the receiver registration

- [ ] **Step 4: Commit**

```bash
git add app/src/debug/
git commit -m "feat: add debug-only ScanBroadcastReceiver for adversary simulation harness"
```

---

### Task 2: Add Pegasus disguise package to IOC DB

**Files:**
- Modify: `iocs/known_bad_packages.json`

**Context:** The `mercenary_package_name` scenario installs an APK with package `com.android.bsp` — a documented Pegasus disguise name. This package must be in the IOC database for `AppScanner` to flag it.

- [ ] **Step 1: Read `iocs/known_bad_packages.json` and find the entries array**

Look for the array structure and the last entry.

- [ ] **Step 2: Add `com.android.bsp` entry**

Add to the JSON entries array:
```json
{
  "package_name": "com.android.bsp",
  "name": "Pegasus Disguise (com.android.bsp)",
  "category": "spyware",
  "source": "mvt-indicators"
}
```

Also add other known Pegasus disguise package names from MVT indicators:
```json
{
  "package_name": "com.network.android",
  "name": "Pegasus Disguise (com.network.android)",
  "category": "spyware",
  "source": "mvt-indicators"
}
```

- [ ] **Step 3: Validate JSON syntax**

Run: `python3 -m json.tool iocs/known_bad_packages.json > /dev/null`
Expected: No output (valid JSON)

- [ ] **Step 4: Run unit tests to verify IOC loading still works**

Run: `export JAVA_HOME=/home/yasir/Applications/android-studio/jbr && ./gradlew testDebugUnitTest`
Expected: BUILD SUCCESSFUL

- [ ] **Step 5: Commit**

```bash
git add iocs/known_bad_packages.json
git commit -m "feat: add Pegasus disguise package names to IOC database"
```

---

### Task 3: Fixture APK Gradle project

**Files:**
- Create: `test-adversary/fixtures/mercenary/settings.gradle.kts`
- Create: `test-adversary/fixtures/mercenary/build.gradle.kts`
- Create: `test-adversary/fixtures/mercenary/build-fixtures.sh`
- Create: 5 module directories, each with `build.gradle.kts` and `src/main/AndroidManifest.xml`
- Create: `test-adversary/fixtures/mercenary/device-admin-abuse/src/main/res/xml/device_admin.xml`
- Modify: `.gitignore`

**Context:** Each fixture APK is a minimal Android project — just a manifest, no code. The `build-fixtures.sh` script builds all 5, copies the APKs to the parent directory, and prints their SHA256 hashes for pinning in `manifest.yml`.

- [ ] **Step 1: Create root `settings.gradle.kts`**

```kotlin
// test-adversary/fixtures/mercenary/settings.gradle.kts
pluginManagement {
    repositories {
        google()
        mavenCentral()
    }
}
dependencyResolutionManagement {
    repositories {
        google()
        mavenCentral()
    }
}
rootProject.name = "adversary-fixtures"
include(
    ":spyware-package-name",
    ":cert-hash-ioc",
    ":accessibility-abuse",
    ":device-admin-abuse",
    ":surveillance-permissions"
)
```

- [ ] **Step 2: Create root `build.gradle.kts`**

```kotlin
// test-adversary/fixtures/mercenary/build.gradle.kts
plugins {
    id("com.android.application") version "8.4.2" apply false
}
```

Check the AGP version used in the main project's `build.gradle.kts` and match it exactly.

- [ ] **Step 3: Create `spyware-package-name` module**

`test-adversary/fixtures/mercenary/spyware-package-name/build.gradle.kts`:
```kotlin
plugins { id("com.android.application") }
android {
    namespace = "com.android.bsp"
    compileSdk = 34
    defaultConfig {
        applicationId = "com.android.bsp"
        minSdk = 21
        targetSdk = 34
        versionCode = 1
        versionName = "1.0"
    }
}
```

`test-adversary/fixtures/mercenary/spyware-package-name/src/main/AndroidManifest.xml`:
```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
    <application android:label="System Service" />
</manifest>
```

- [ ] **Step 4: Create `cert-hash-ioc` module**

`test-adversary/fixtures/mercenary/cert-hash-ioc/build.gradle.kts`:
```kotlin
plugins { id("com.android.application") }
android {
    namespace = "com.androdr.fixture.certhash"
    compileSdk = 34
    defaultConfig {
        applicationId = "com.androdr.fixture.certhash"
        minSdk = 21
        targetSdk = 34
        versionCode = 1
        versionName = "1.0"
    }
    signingConfigs {
        create("certHashTest") {
            storeFile = file("../cert-hash-ioc-keystore.jks")
            storePassword = "adversary-test"
            keyAlias = "cert-hash-test"
            keyPassword = "adversary-test"
        }
    }
    buildTypes {
        getByName("debug") {
            signingConfig = signingConfigs.getByName("certHashTest")
        }
    }
}
```

`test-adversary/fixtures/mercenary/cert-hash-ioc/src/main/AndroidManifest.xml`:
```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
    <application android:label="Cert Hash Test" />
</manifest>
```

- [ ] **Step 5: Create `accessibility-abuse` module**

`test-adversary/fixtures/mercenary/accessibility-abuse/build.gradle.kts`:
```kotlin
plugins { id("com.android.application") }
android {
    namespace = "com.androdr.fixture.accessibility"
    compileSdk = 34
    defaultConfig {
        applicationId = "com.androdr.fixture.accessibility"
        minSdk = 21
        targetSdk = 34
        versionCode = 1
        versionName = "1.0"
    }
}
```

`test-adversary/fixtures/mercenary/accessibility-abuse/src/main/AndroidManifest.xml`:
```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
    <application android:label="Accessibility Test">
        <service
            android:name="com.androdr.fixture.accessibility.Svc"
            android:permission="android.permission.BIND_ACCESSIBILITY_SERVICE"
            android:exported="false">
            <intent-filter>
                <action android:name="android.accessibilityservice.AccessibilityService" />
            </intent-filter>
            <meta-data
                android:name="android.accessibilityservice"
                android:resource="@xml/accessibility_service_config" />
        </service>
    </application>
</manifest>
```

Also create `test-adversary/fixtures/mercenary/accessibility-abuse/src/main/res/xml/accessibility_service_config.xml`:
```xml
<?xml version="1.0" encoding="utf-8"?>
<accessibility-service xmlns:android="http://schemas.android.com/apk/res/android"
    android:accessibilityEventTypes="typeAllMask"
    android:accessibilityFeedbackType="feedbackGeneric"
    android:canRetrieveWindowContent="true"
    android:description="@string/app_name" />
```

Note: The `Svc` class does not need to exist — the APK will install fine without it; the manifest just declares it. However, if the build fails because the class is missing, create an empty stub:

```kotlin
// accessibility-abuse/src/main/java/com/androdr/fixture/accessibility/Svc.kt
package com.androdr.fixture.accessibility
import android.accessibilityservice.AccessibilityService
import android.view.accessibility.AccessibilityEvent
class Svc : AccessibilityService() {
    override fun onAccessibilityEvent(event: AccessibilityEvent?) {}
    override fun onInterrupt() {}
}
```

- [ ] **Step 6: Create `device-admin-abuse` module**

`test-adversary/fixtures/mercenary/device-admin-abuse/build.gradle.kts`:
```kotlin
plugins { id("com.android.application") }
android {
    namespace = "com.androdr.fixture.deviceadmin"
    compileSdk = 34
    defaultConfig {
        applicationId = "com.androdr.fixture.deviceadmin"
        minSdk = 21
        targetSdk = 34
        versionCode = 1
        versionName = "1.0"
    }
}
```

`test-adversary/fixtures/mercenary/device-admin-abuse/src/main/AndroidManifest.xml`:
```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
    <application android:label="Device Admin Test">
        <receiver
            android:name="com.androdr.fixture.deviceadmin.Recv"
            android:permission="android.permission.BIND_DEVICE_ADMIN"
            android:exported="false">
            <meta-data
                android:name="android.app.device_admin"
                android:resource="@xml/device_admin" />
            <intent-filter>
                <action android:name="android.app.action.DEVICE_ADMIN_ENABLED" />
            </intent-filter>
        </receiver>
    </application>
</manifest>
```

`test-adversary/fixtures/mercenary/device-admin-abuse/src/main/res/xml/device_admin.xml`:
```xml
<?xml version="1.0" encoding="utf-8"?>
<device-admin>
    <uses-policies>
        <force-lock />
        <wipe-data />
    </uses-policies>
</device-admin>
```

Same note as accessibility: create an empty `Recv` stub if the build requires it:
```kotlin
// device-admin-abuse/src/main/java/com/androdr/fixture/deviceadmin/Recv.kt
package com.androdr.fixture.deviceadmin
import android.app.admin.DeviceAdminReceiver
class Recv : DeviceAdminReceiver()
```

- [ ] **Step 7: Create `surveillance-permissions` module**

`test-adversary/fixtures/mercenary/surveillance-permissions/build.gradle.kts`:
```kotlin
plugins { id("com.android.application") }
android {
    namespace = "com.androdr.fixture.surveillance"
    compileSdk = 34
    defaultConfig {
        applicationId = "com.androdr.fixture.surveillance"
        minSdk = 21
        targetSdk = 34
        versionCode = 1
        versionName = "1.0"
    }
}
```

`test-adversary/fixtures/mercenary/surveillance-permissions/src/main/AndroidManifest.xml`:
```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
    <uses-permission android:name="android.permission.RECORD_AUDIO" />
    <uses-permission android:name="android.permission.CAMERA" />
    <uses-permission android:name="android.permission.ACCESS_FINE_LOCATION" />
    <uses-permission android:name="android.permission.READ_CONTACTS" />
    <uses-permission android:name="android.permission.READ_CALL_LOG" />
    <uses-permission android:name="android.permission.READ_SMS" />
    <application android:label="Surveillance Perms Test" />
</manifest>
```

- [ ] **Step 8: Create `build-fixtures.sh`**

```bash
#!/usr/bin/env bash
# test-adversary/fixtures/mercenary/build-fixtures.sh
# Builds all 5 fixture APKs, copies them to the parent directory,
# and prints SHA256 hashes for pinning in manifest.yml.
set -euo pipefail
cd "$(dirname "$0")"

JAVA_HOME="${JAVA_HOME:-/home/yasir/Applications/android-studio/jbr}"
export JAVA_HOME

# Create local.properties if missing
if [ ! -f local.properties ]; then
    if [ -z "${ANDROID_HOME:-}" ]; then
        echo "ERROR: ANDROID_HOME not set and no local.properties found" >&2
        exit 1
    fi
    echo "sdk.dir=$ANDROID_HOME" > local.properties
    echo "Created local.properties with sdk.dir=$ANDROID_HOME"
fi

# Generate cert-hash-ioc signing key if it doesn't exist
KEYSTORE="cert-hash-ioc-keystore.jks"
if [ ! -f "$KEYSTORE" ]; then
    echo "Generating signing key for cert-hash-ioc fixture..."
    keytool -genkeypair -v \
        -keystore "$KEYSTORE" \
        -alias cert-hash-test \
        -keyalg RSA -keysize 2048 \
        -validity 10000 \
        -storepass adversary-test \
        -keypass adversary-test \
        -dname "CN=Adversary Test, O=AndroDR Fixtures"
fi

# Build all modules
echo "Building fixture APKs..."
./gradlew assembleDebug --quiet 2>/dev/null || ./gradlew assembleDebug

# Copy APKs and print SHA256 hashes
MODULES=(
    "spyware-package-name"
    "cert-hash-ioc"
    "accessibility-abuse"
    "device-admin-abuse"
    "surveillance-permissions"
)

echo ""
echo "=== Fixture APKs ==="
for mod in "${MODULES[@]}"; do
    src="${mod}/build/outputs/apk/debug/${mod}-debug.apk"
    dest="${mod}.apk"
    if [ -f "$src" ]; then
        cp "$src" "$dest"
        hash=$(sha256sum "$dest" | awk '{print $1}')
        echo "$dest  sha256:$hash"
    else
        echo "WARNING: $src not found" >&2
    fi
done

# Print cert hash for cert-hash-ioc APK (needed for IOC DB seeding)
echo ""
echo "=== Cert Hash for IOC DB Seeding ==="
keytool -printcert -jarfile cert-hash-ioc.apk 2>/dev/null | grep "SHA256:" | head -1 || \
    echo "WARNING: Could not extract cert hash from cert-hash-ioc.apk"

echo ""
echo "Done. Update manifest.yml sha256 fields with the hashes above."
```

- [ ] **Step 9: Add gitignore entries**

Append to `.gitignore`:
```
# Adversary simulation fixtures (rebuilt from source via build-fixtures.sh)
test-adversary/fixtures/mercenary/*.apk
test-adversary/fixtures/mercenary/*.jks
test-adversary/fixtures/mercenary/local.properties
test-adversary/fixtures/mercenary/**/build/
test-adversary/fixtures/mercenary/.gradle/
```

- [ ] **Step 10: Add Gradle wrapper to fixture project**

The fixture Gradle project needs its own wrapper. Copy from the main project:

```bash
cp -r gradle test-adversary/fixtures/mercenary/gradle
cp gradlew test-adversary/fixtures/mercenary/gradlew
cp gradlew.bat test-adversary/fixtures/mercenary/gradlew.bat
```

- [ ] **Step 11: Build and verify all 5 APKs**

```bash
cd test-adversary/fixtures/mercenary
chmod +x build-fixtures.sh gradlew
./build-fixtures.sh
```

Expected output: 5 APK files created with SHA256 hashes printed.

- [ ] **Step 12: Commit**

```bash
git add test-adversary/fixtures/mercenary/ .gitignore
git commit -m "feat: add fixture APK Gradle project for adversary simulation"
```

Note: Do NOT commit `*.apk`, `*.jks`, `local.properties`, or `build/` directories — they are gitignored.

---

### Task 4: manifest.yml + expected patterns

**Files:**
- Create: `test-adversary/manifest.yml`
- Create: 11 files in `test-adversary/fixtures/expected/`

**Context:** Copy `manifest.yml` from the spec verbatim. For `<pin>` placeholders in Track 3 (fixture) scenarios, replace with SHA256 hashes from `build-fixtures.sh` output. Track 1 & 2 `<pin>` placeholders stay as `<pin>` — filled in when the developer registers at MalwareBazaar and selects specific samples.

- [ ] **Step 1: Create `test-adversary/manifest.yml`**

Copy the full manifest from the spec (`docs/superpowers/specs/2026-03-26-adversary-simulation-design.md`, lines 112–245). Update the `sha256` fields for `source: fixture` scenarios with the actual hashes from `build-fixtures.sh` output. Leave `source: malwarebazaar` hashes as `"<pin>"`.

- [ ] **Step 2: Create expected pattern files**

One file per scenario, one grep pattern per line:

`test-adversary/fixtures/expected/cerberus_banker.patterns`:
```
Package name matches known malware or stalkerware IOC database entry
```

`test-adversary/fixtures/expected/spynote_rat.patterns`:
```
Package name matches known malware or stalkerware IOC database entry
```

`test-adversary/fixtures/expected/flexispy_stalkerware.patterns`:
```
sensitive surveillance-capable permissions simultaneously
App was not installed via a trusted app store
```

`test-adversary/fixtures/expected/mercenary_package_name.patterns`:
```
com.android.bsp
Package name matches known malware or stalkerware IOC database entry
```

`test-adversary/fixtures/expected/mercenary_cert_hash.patterns`:
```
Known malicious signing certificate
```

`test-adversary/fixtures/expected/mercenary_accessibility.patterns`:
```
Registered as an accessibility service
```

`test-adversary/fixtures/expected/mercenary_device_admin.patterns`:
```
Registered as a device administrator
```

`test-adversary/fixtures/expected/surveillance_permissions.patterns`:
```
sensitive surveillance-capable permissions simultaneously
App was not installed via a trusted app store
```

`test-adversary/fixtures/expected/mercenary_file_artifacts.patterns`:
```
file_artifact
```

`test-adversary/fixtures/expected/mercenary_dns_c2.patterns`:
```
[BLOCKED]
cdn-tp2.xyz
```

`test-adversary/fixtures/expected/mercenary_ip_c2.patterns`:
```
198.199.119.161
```

- [ ] **Step 3: Commit**

```bash
git add test-adversary/manifest.yml test-adversary/fixtures/expected/
git commit -m "feat: add adversary simulation manifest and expected detection patterns"
```

---

### Task 5: run.sh harness

**Files:**
- Create: `test-adversary/run.sh`

**Context:** The main harness script. Parses `manifest.yml` with a simple `awk`/`grep` approach (no YAML parser dependency — keep it portable). Implements all 11 steps from the spec.

**Important implementation notes:**
- Require `python3` with PyYAML for parsing manifest.yml (needed for inject command extraction). Check in preflight.
- `iptables` requires `sudo` — document this in the script header.
- The script must clean up (uninstall APKs, restore iptables, remove files) even on `Ctrl-C` — use a `trap` handler.
- MalwareBazaar returns a ZIP file containing the sample — unzip and verify SHA256 of the extracted file.

- [ ] **Step 1: Create `test-adversary/run.sh`**

```bash
#!/usr/bin/env bash
# test-adversary/run.sh — AndroDR adversary simulation test harness
# Usage: ./run.sh <emulator-serial>
# Prerequisites: Linux host, MALWAREBAZAAR_API_KEY set, emulator running with com.androdr.debug installed
set -euo pipefail

SERIAL="${1:?Usage: $0 <emulator-serial>}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
MANIFEST="$SCRIPT_DIR/manifest.yml"
EXPECTED_DIR="$SCRIPT_DIR/fixtures/expected"
FIXTURE_DIR="$SCRIPT_DIR/fixtures/mercenary"
ADB="adb -s $SERIAL"
WORKDIR=$(mktemp -d /tmp/androdr-adversary-XXXXXX)

# Track results for summary
declare -A RESULTS

# Cleanup trap — always restore network and uninstall test APKs
INSTALLED_PACKAGES=()
IPTABLES_RULE_ACTIVE=false
EMULATOR_IF=""

cleanup() {
    echo ""
    echo ">>> Cleaning up..."
    for pkg in "${INSTALLED_PACKAGES[@]}"; do
        $ADB uninstall "$pkg" 2>/dev/null || true
    done
    if $IPTABLES_RULE_ACTIVE && [ -n "$EMULATOR_IF" ]; then
        sudo iptables -D FORWARD -o "$EMULATOR_IF" -j DROP 2>/dev/null || true
    fi
    rm -rf "$WORKDIR"
}
trap cleanup EXIT

# ── Preflight ─────────────────────────────────────────────────────────────────

echo "=== AndroDR Adversary Simulation ==="
echo ""

# Check Linux
if [ "$(uname)" != "Linux" ]; then
    echo "ERROR: This harness requires Linux (iptables for network isolation)." >&2
    exit 1
fi

# Check emulator online
if ! $ADB get-state 2>/dev/null | grep -q "device"; then
    echo "ERROR: Emulator $SERIAL not found or not online." >&2
    echo "Available devices:" >&2
    adb devices >&2
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

    # Step 2: NETWORK CUT
    EMULATOR_IF=$($ADB shell ip route 2>/dev/null | grep default | awk '{print $5}' | head -1)
    if [ -n "$EMULATOR_IF" ]; then
        sudo iptables -I FORWARD -o "$EMULATOR_IF" -j DROP 2>/dev/null || true
        IPTABLES_RULE_ACTIVE=true
        echo "  Network isolated (interface=$EMULATOR_IF)"
    fi

    # Step 3: INSTALL
    if [ -n "$apk_path" ]; then
        echo "  Installing $apk_path..."
        if $ADB install -t "$apk_path" 2>&1 | tail -1 | grep -q "Success"; then
            # Extract package name for cleanup
            pkg_name=$($ADB shell pm list packages -f 2>/dev/null | grep "$(basename "$apk_path" .apk)" | head -1 | sed 's/.*=//' || true)
            if [ -z "$pkg_name" ]; then
                # Fallback: try to get from aapt
                pkg_name=$(aapt2 dump packagename "$apk_path" 2>/dev/null || true)
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
    if $IPTABLES_RULE_ACTIVE && [ -n "$EMULATOR_IF" ]; then
        sudo iptables -D FORWARD -o "$EMULATOR_IF" -j DROP 2>/dev/null || true
        IPTABLES_RULE_ACTIVE=false
        echo "  Network restored"
    fi

    # Step 8: UI REVIEW
    echo ""
    echo "  >>> Review AndroDR UI on the emulator. Press ENTER to continue."
    read -r _

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
        while IFS= read -r pattern; do
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
        $ADB uninstall "$pkg_name" 2>/dev/null || true
        INSTALLED_PACKAGES=("${INSTALLED_PACKAGES[@]/$pkg_name}")
    fi
    echo ""
}

# ── Main loop ─────────────────────────────────────────────────────────────────

while IFS= read -r scenario_id; do
    run_scenario "$scenario_id"
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
```

- [ ] **Step 2: Make executable**

```bash
chmod +x test-adversary/run.sh
```

- [ ] **Step 3: Syntax check**

Run: `bash -n test-adversary/run.sh`
Expected: No output (valid syntax)

- [ ] **Step 4: Commit**

```bash
git add test-adversary/run.sh
git commit -m "feat: add adversary simulation test harness (run.sh)"
```

---

### Task 6: README + final verification

**Files:**
- Create: `test-adversary/README.md`

- [ ] **Step 1: Create README**

```markdown
# Adversary Simulation Test Suite

Manual developer UAT harness for validating AndroDR's detection against
real malware and synthetic adversary artifacts.

## Prerequisites

- **Linux host** (iptables required for network isolation)
- **ANDROID_HOME** set, `adb` on PATH
- **Emulator** running (`Medium_Phone_API_36.1` recommended)
- **AndroDR debug build** installed: `./gradlew installDebug`
- **yq** or **python3 with PyYAML** for manifest parsing
- **MalwareBazaar API key** (optional — only for Track 1 & 2):
  set `MALWAREBAZAAR_API_KEY` env var (free at https://bazaar.abuse.ch)

## Quick Start

```bash
# 1. Build fixture APKs (one-time)
cd test-adversary/fixtures/mercenary
./build-fixtures.sh
cd ../../..

# 2. Update manifest.yml with fixture SHA256 hashes
#    (printed by build-fixtures.sh)

# 3. Run the harness
./test-adversary/run.sh <emulator-serial>
```

## Test Tracks

| Track | Source | Samples |
|-------|--------|---------|
| 1 | MalwareBazaar | Commodity RATs (Cerberus, SpyNote) |
| 2 | MalwareBazaar | Stalkerware (FlexiSpy) |
| 3 | Synthetic fixtures | Mercenary spyware simulation |

Track 3 runs without MalwareBazaar credentials.

## Expected Failures

Scenarios tagged with `roadmap_issue` test detectors that don't exist yet.
These print `EXPECTED FAIL (roadmap #N)` — not real failures.

| Scenario | Roadmap Issue | Missing Detector |
|----------|---------------|-----------------|
| mercenary_cert_hash | #7 | APK cert hash IOC matching |
| mercenary_accessibility | #10 | Accessibility service abuse |
| mercenary_device_admin | #10 | Device admin abuse |
| mercenary_file_artifacts | #8 | File system artifact scanning |
| mercenary_ip_c2 | #6 | IP address IOC detection |

## Adding New Scenarios

1. Add entry to `manifest.yml` with unique `id`, `source`, `sha256`, and `expected_patterns`
2. Create `fixtures/expected/<id>.patterns` with one grep pattern per line
3. If `source: fixture`, build the APK and add to `fixtures/mercenary/`
```

- [ ] **Step 2: Build AndroDR debug APK to verify ScanBroadcastReceiver**

```bash
export JAVA_HOME=/home/yasir/Applications/android-studio/jbr
./gradlew assembleDebug
```

Expected: BUILD SUCCESSFUL

- [ ] **Step 3: Run unit tests**

```bash
./gradlew testDebugUnitTest
```

Expected: BUILD SUCCESSFUL, all tests pass

- [ ] **Step 4: Commit everything**

```bash
git add test-adversary/README.md
git commit -m "docs: add adversary simulation README"
```

- [ ] **Step 5: Push branch**

```bash
git push origin claude/android-edr-setup-rl68Y
```
