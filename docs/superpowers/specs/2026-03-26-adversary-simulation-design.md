# Adversary Simulation Test Suite Design

## Goal

A developer-run end-to-end test harness that validates AndroDR's detection capabilities against realistic adversary artifacts — real malware APKs from MalwareBazaar and synthetic mercenary spyware artifacts — covering all current detection surfaces and pre-defining expected failures for roadmap detection gaps.

---

## Architecture

### Option selected: Hybrid (shell harness only)

One small `app/` change is required: a debug-only `ScanBroadcastReceiver` that triggers a scan and exports the plaintext report to external storage. All other harness components live outside `app/`.

```
test-adversary/
├── manifest.yml          # hash-pinned scenario registry (ATT&CK-tagged)
├── run.sh                # end-to-end UAT harness
├── fixtures/
│   ├── mercenary/        # pre-built synthetic fixture APKs
│   │   ├── spyware-package-name.apk
│   │   ├── cert-hash-ioc.apk
│   │   ├── accessibility-abuse.apk
│   │   ├── device-admin-abuse.apk
│   │   └── surveillance-permissions.apk
│   └── expected/         # per-scenario grep pattern files
│       └── <scenario-id>.patterns
└── README.md

app/src/debug/                       # debug-only source set
├── AndroidManifest.xml              # registers ScanBroadcastReceiver
└── java/com/androdr/debug/
    └── ScanBroadcastReceiver.kt     # ACTION_SCAN → runFullScan → export to /sdcard
```

### Execution mode

Manual developer UAT only — no CI integration, Linux host required (iptables).

```bash
./test-adversary/run.sh <emulator-serial>
```

---

## Required App Change: `ScanBroadcastReceiver` (debug only)

A single Kotlin file added to `app/src/debug/` (not included in release builds):

```kotlin
// app/src/debug/java/com/androdr/debug/ScanBroadcastReceiver.kt
// Receives com.androdr.ACTION_SCAN, runs a full scan, and writes the plaintext
// report to /sdcard/Android/data/com.androdr.debug/files/androdr_last_report.txt
// (world-readable; accessible via ADB without root).
```

Registered in `app/src/debug/AndroidManifest.xml`:
```xml
<receiver android:name="com.androdr.debug.ScanBroadcastReceiver" android:exported="true">
    <intent-filter>
        <action android:name="com.androdr.ACTION_SCAN" />
    </intent-filter>
</receiver>
```

Triggered by harness:
```bash
adb -s $SERIAL shell am broadcast -a com.androdr.ACTION_SCAN -p com.androdr.debug
sleep 10  # wait for scan + export to complete
adb -s $SERIAL pull \
  /sdcard/Android/data/com.androdr.debug/files/androdr_last_report.txt \
  /tmp/androdr-$SCENARIO_ID.txt
```

---

## Test Tracks

| Track | Source | Threat category |
|-------|--------|----------------|
| 1 | MalwareBazaar (hash-pinned) | Commodity RATs / banking malware |
| 2 | MalwareBazaar (hash-pinned) | Stalkerware / commercial spyware |
| 3 | Synthetic fixtures + ADB injection | Mercenary spyware simulation |

---

## TTP Coverage

| Scenario | Track | ATT&CK | Detection method | Roadmap issue |
|----------|-------|--------|-----------------|---------------|
| Cerberus banker | 1 | T1429, T1636 | Package IOC + permissions | — |
| SpyNote RAT | 1 | T1429, T1430, T1512 | Package IOC + permissions | — |
| FlexiSpy stalkerware | 2 | T1429, T1430, T1512, T1636 | Permission heuristics + sideload | — |
| Spyware package name | 3 | T1418 | Package name IOC match | — |
| Malicious cert hash | 3 | T1628 | APK signing cert hash IOC | #7 |
| Accessibility abuse | 3 | T1626 | AccessibilityService registration | #10 |
| Device admin abuse | 3 | T1401 | DeviceAdminReceiver registration | #10 |
| Surveillance permission cluster | 3 | T1429/T1430/T1512/T1636 | Permission combination heuristic | — |
| File system artifacts | 3 | T1533 | File path scanning | #8 |
| DNS C2 beaconing | 3 | T1437 | Domain IOC match | — |
| Direct IP C2 | 3 | T1437.001 | IP address IOC match | #6 |

**Notes:**
- T1476 (app delivery) is a delivery-side technique not observable by an on-device EDR; omitted from detection claims.
- Carrier-based / zero-click delivery (Pegasus iMessage/WhatsApp exploits, SIM-based) is not detectable by AndroDR and is out of scope.
- Scenarios with a roadmap issue print `EXPECTED FAIL (roadmap #N)` rather than `FAIL`.

---

## Manifest Schema (`manifest.yml`)

```yaml
version: 1

scenarios:

  # ── Track 1: Commodity malware ─────────────────────────────────────────
  - id: cerberus_banker
    track: 1
    description: "Cerberus Android banking trojan"
    source: malwarebazaar
    sha256: "<pin>"
    tags: [android, cerberus, banker]
    attack: [T1429, T1636]
    expected_patterns:
      - "Package name matches known malware or stalkerware IOC database entry"

  - id: spynote_rat
    track: 1
    description: "SpyNote remote access trojan"
    source: malwarebazaar
    sha256: "<pin>"
    tags: [android, spynote, rat]
    attack: [T1429, T1430, T1512]
    expected_patterns:
      - "Package name matches known malware or stalkerware IOC database entry"

  # ── Track 2: Stalkerware ───────────────────────────────────────────────
  - id: flexispy_stalkerware
    track: 2
    description: "FlexiSpy-derived commercial stalkerware"
    source: malwarebazaar
    sha256: "<pin>"
    tags: [android, stalkerware]
    attack: [T1429, T1430, T1512, T1636]
    expected_patterns:
      # IOC match may also appear if sample is in the IOC DB — that is acceptable
      - "sensitive surveillance-capable permissions simultaneously"
      - "App was not installed via a trusted app store"

  # ── Track 3: Mercenary spyware simulation ──────────────────────────────
  - id: mercenary_package_name
    track: 3
    description: "App using known Pegasus disguise package name (com.android.bsp)"
    source: fixture
    fixture: fixtures/mercenary/spyware-package-name.apk
    sha256: "<pin>"
    attack: [T1418]
    expected_patterns:
      - "Package name matches known malware or stalkerware IOC database entry"

  - id: mercenary_cert_hash
    track: 3
    description: "App signed with cert hash seeded into IOC DB"
    source: fixture
    fixture: fixtures/mercenary/cert-hash-ioc.apk
    sha256: "<pin>"
    attack: [T1628]
    expected_patterns:
      - "Known malicious signing certificate"   # reason string added by roadmap #7
    roadmap_issue: 7

  - id: mercenary_accessibility
    track: 3
    description: "App registering AccessibilityService"
    source: fixture
    fixture: fixtures/mercenary/accessibility-abuse.apk
    sha256: "<pin>"
    attack: [T1626]
    expected_patterns:
      - "Registered as an accessibility service"   # reason string added by roadmap #10
    roadmap_issue: 10

  - id: mercenary_device_admin
    track: 3
    description: "App registering DeviceAdminReceiver"
    source: fixture
    fixture: fixtures/mercenary/device-admin-abuse.apk
    sha256: "<pin>"
    attack: [T1401]
    expected_patterns:
      - "Registered as a device administrator"   # reason string added by roadmap #10
    roadmap_issue: 10

  - id: surveillance_permissions
    track: 3
    description: "Sideloaded app with full surveillance permission cluster"
    source: fixture
    fixture: fixtures/mercenary/surveillance-permissions.apk
    sha256: "<pin>"
    attack: [T1429, T1430, T1512, T1636]
    expected_patterns:
      - "sensitive surveillance-capable permissions simultaneously"
      - "App was not installed via a trusted app store"

  - id: mercenary_file_artifacts
    track: 3
    description: "Known spyware file paths injected via ADB"
    source: adb_inject
    inject:
      - type: file
        adb_cmd: "shell touch /data/local/tmp/.raptor"
        cleanup: "shell rm -f /data/local/tmp/.raptor"
      - type: file
        adb_cmd: "shell touch /data/local/tmp/.stat"
        cleanup: "shell rm -f /data/local/tmp/.stat"
    attack: [T1533]
    expected_patterns:
      - "file_artifact"   # DeviceFlag id added by roadmap #8
    roadmap_issue: 8

  - id: mercenary_dns_c2
    track: 3
    description: "DNS query to known Predator C2 domain"
    source: adb_inject
    inject:
      - type: dns_query
        adb_cmd: "shell nslookup cdn-tp2.xyz 10.0.0.2"
    attack: [T1437]
    expected_patterns:
      - "[BLOCKED]"
      - "cdn-tp2.xyz"

  - id: mercenary_ip_c2
    track: 3
    description: "Direct TCP connection to known C2 IP"
    source: adb_inject
    inject:
      - type: tcp_connect
        adb_cmd: "shell curl --connect-timeout 3 --max-time 5 -sk https://198.199.119.161:443 || true"
    attack: [T1437.001]
    expected_patterns:
      - "198.199.119.161"   # network event added by roadmap #6
    roadmap_issue: 6
```

---

## `run.sh` Harness Flow

```
run.sh <emulator-serial>

Prerequisites checked at startup:
  - $SERIAL is online in `adb devices`
  - $MALWAREBAZAAR_API_KEY is set
  - com.androdr.debug is installed on the emulator
  - running on Linux (iptables required for network isolation)

For each scenario in manifest.yml:

  1. DOWNLOAD (source=malwarebazaar)
     curl -s -X POST https://mb-api.abuse.ch/api/v1/ \
       -d "query=get_file&sha256=$SHA256" \
       -H "Auth-Key: $MALWAREBAZAAR_API_KEY" -o sample.zip
     unzip sample.zip; verify sha256sum matches manifest; abort if mismatch

  2. NETWORK CUT
     EMULATOR_IF=$(adb -s $SERIAL shell ip route | grep default | awk '{print $5}')
     iptables -I FORWARD -o $EMULATOR_IF -j DROP

  3. INSTALL (source=fixture or malwarebazaar)
     adb -s $SERIAL install -t <apk>

  4. INJECT (source=adb_inject)
     Execute each inject.adb_cmd: adb -s $SERIAL <adb_cmd>

  5. SEED IOC DB (scenario=mercenary_cert_hash only)
     Extract SHA-256 from cert-hash-ioc.apk signing cert:
       keytool -printcert -jarfile cert-hash-ioc.apk | grep SHA256 | awk '{print $2}'
     Insert into AndroDR IOC DB via adb shell content provider or direct DB push

  6. TRIGGER SCAN
     adb -s $SERIAL shell am broadcast -a com.androdr.ACTION_SCAN -p com.androdr.debug
     sleep 10

  7. PULL REPORT
     adb -s $SERIAL pull \
       /sdcard/Android/data/com.androdr.debug/files/androdr_last_report.txt \
       /tmp/androdr-$SCENARIO_ID.txt

  8. NETWORK RESTORE
     iptables -D FORWARD -o $EMULATOR_IF -j DROP

  9. UI REVIEW PAUSE
     echo ">>> AndroDR scan complete. Review the UI on the emulator, then press ENTER."
     read -r _

  10. DIFF
      For each pattern in expected_patterns:
        grep -qF "$pattern" /tmp/androdr-$SCENARIO_ID.txt || FAIL=true
      If roadmap_issue is set and FAIL=true: print "EXPECTED FAIL (roadmap #N)"
      Else if FAIL=true: print "FAIL"
      Else: print "PASS"

  11. CLEANUP
      adb -s $SERIAL uninstall <package> (if APK was installed)
      Execute each inject.cleanup command (if adb_inject)
      rm -f sample.zip <apk>

Print summary table: scenario | track | result | roadmap flag
```

---

## Fixture APK Specs

Each APK is a minimal Android project (empty `MainActivity`, no runtime logic). Built once and checked in; SHA-256 pinned in `manifest.yml`.

| APK | Key `AndroidManifest.xml` content |
|-----|------------------------------------|
| `spyware-package-name.apk` | `package="com.android.bsp"` |
| `cert-hash-ioc.apk` | Standard package; signed with a generated test key. SHA-256 of signing cert extracted at harness runtime and seeded into the IOC DB (step 5 above). |
| `accessibility-abuse.apk` | `<service android:name=".Svc" android:permission="android.permission.BIND_ACCESSIBILITY_SERVICE">` with `AccessibilityService` intent-filter |
| `device-admin-abuse.apk` | `<receiver android:name=".Recv" android:permission="android.permission.BIND_DEVICE_ADMIN">` with `android.app.device_admin` meta-data and `res/xml/device_admin.xml` |
| `surveillance-permissions.apk` | `uses-permission`: RECORD_AUDIO, CAMERA, ACCESS_FINE_LOCATION, READ_CONTACTS, READ_CALL_LOG, READ_SMS. Installed via `adb install` (no Play Store installer record). |

---

## Expected Pattern Files (`fixtures/expected/<scenario-id>.patterns`)

One pattern per line. `run.sh` step 10 runs `grep -qF` for each. All patterns must match for PASS.

Example — `fixtures/expected/mercenary_package_name.patterns`:
```
com.android.bsp
Package name matches known malware or stalkerware IOC database entry
```

Example — `fixtures/expected/mercenary_dns_c2.patterns`:
```
[BLOCKED]
cdn-tp2.xyz
```

---

## Prerequisites for Developers

- Linux host (iptables required for network isolation step)
- `MALWAREBAZAAR_API_KEY` env var (free registration at malwarebazaar.abuse.ch)
- `ANDROID_HOME` set, `adb` and `keytool` on PATH
- Emulator `Medium_Phone_API_36.1` (API 36) running with `com.androdr.debug` installed
- AndroDR debug build must include `ScanBroadcastReceiver` (see Required App Change above)

---

## Out of Scope

- CI/CD integration (manual UAT only)
- macOS / Windows host support
- New Kotlin unit tests or instrumented test code
- Automated malware execution or dynamic analysis
- iOS / non-Android platforms
- Carrier-based / zero-click delivery detection (Pegasus iMessage/WhatsApp exploits)
