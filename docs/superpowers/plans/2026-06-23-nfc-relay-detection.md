# NFC-Relay Detection (androdr-087) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a high-severity detection for NFC-relay malware — a sideloaded, unvetted app that registers an NFC card-emulation (HCE) service and holds the NFC permission.

**Architecture:** Pure SIGMA YAML rule (androdr-087) matching existing telemetry — `service_permissions` (already emitted) for the `BIND_NFC_SERVICE` HCE signal, plus one new exposed permission (`NFC`) via the existing `highRiskPermissions` scanner hook. Companion C2 IOCs ship via the rules repo. No new scanner subsystem.

**Tech Stack:** Kotlin, Android, SIGMA-style YAML rules, JUnit/MockK, the android-sigma-rules submodule.

## Global Constraints

- **Env for every gradle/adb command:** `export JAVA_HOME=/home/yasir/Applications/android-studio/jbr ANDROID_HOME=/home/yasir/Android/Sdk; export PATH="$JAVA_HOME/bin:$ANDROID_HOME/platform-tools:$ANDROID_HOME/emulator:$PATH"`
- **Rule ID:** `androdr-087` (next free; 086 is the current max; 087 never existed).
- **Category convention:** there is NO `TROJAN` IOC category — NFC-relay families are `MALWARE`.
- **Telemetry field formats (critical — fixtures MUST match real scanner output):** `service_permissions` holds **fully-qualified** permission names (`android.permission.BIND_NFC_SERVICE`); `permissions` holds **short** names (`NFC`, `SYSTEM_ALERT_WINDOW`). The rule matches via `|contains` substrings, which works against both.
- **Mirror convention:** every bundled `res/raw` rule is mirrored to the android-sigma-rules submodule. The rules-repo change is a separate PR + (if it touches `rules.txt`) `rules.sha256` regen; the 087 mirror goes under `staging/app_scanner/` and is NOT in `rules.txt`, so no sha256 impact.
- **IP filtering is parked:** IOC additions are domains only, never IPs.
- **Review gate:** the 4-agent ceremony (correctness / quality / architect / code-security) runs before commit/PR.

---

### Task 1: Expose the NFC permission in scanner telemetry

**Files:**
- Modify: `app/src/main/java/com/androdr/scanner/AppScanner.kt` (the `highRiskPermissions` set, ~line 81)
- Test: `app/src/test/java/com/androdr/scanner/AppScannerTelemetryTest.kt`

**Interfaces:**
- Consumes: existing `highRiskPermissions: Set<String>`, `AppTelemetry.permissions: List<String>`, `AppTelemetry.surveillancePermissionCount: Int`.
- Produces: `permissions` telemetry now contains `"NFC"` (short-named) when an app declares `android.permission.NFC`; `surveillancePermissionCount` unchanged.

- [ ] **Step 1: Write the failing test**

Add to `AppScannerTelemetryTest.kt` after the existing `SYSTEM_ALERT_WINDOW` test (~line 248):

```kotlin
    @Test
    fun `NFC permission is exposed in permissions but not counted as surveillance`() = runTest {
        val pkg = buildPackageInfo(
            pkgName = "com.shady.nfc",
            installerPkg = null,
            permissions = arrayOf(
                Manifest.permission.NFC,
                Manifest.permission.INTERNET
            )
        )
        installPackages(pkg)

        val result = scanner.collectTelemetry()

        assertEquals(1, result.size)
        val telemetry = result[0]
        assertTrue("Expected NFC (short-named) in permissions", telemetry.permissions.contains("NFC"))
        assertEquals("NFC must not inflate surveillance count", 0, telemetry.surveillancePermissionCount)
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./gradlew testDebugUnitTest --tests "com.androdr.scanner.AppScannerTelemetryTest"`
Expected: FAIL — `permissions` does not contain `"NFC"` (assertTrue fails).

- [ ] **Step 3: Add NFC to the high-risk permission set**

In `AppScanner.kt`, change the `highRiskPermissions` set:

```kotlin
    private val highRiskPermissions = setOf(
        Manifest.permission.SYSTEM_ALERT_WINDOW,
        Manifest.permission.NFC
    )
```

- [ ] **Step 4: Run test to verify it passes**

Run: `./gradlew testDebugUnitTest --tests "com.androdr.scanner.AppScannerTelemetryTest"`
Expected: PASS (all cases, including the existing SYSTEM_ALERT_WINDOW test).

- [ ] **Step 5: Commit**

```bash
git add app/src/main/java/com/androdr/scanner/AppScanner.kt app/src/test/java/com/androdr/scanner/AppScannerTelemetryTest.kt
git commit -m "feat(scan): expose NFC permission in telemetry (high-risk, not surveillance)"
```

---

### Task 2: The androdr-087 rule + gate4 fixture + registration

**Files:**
- Create: `app/src/main/res/raw/sigma_androdr_087_nfc_relay.yml`
- Modify: `app/src/main/java/com/androdr/sigma/SigmaRuleEngine.kt` (BUNDLED_RULE_IDS, after line 353)
- Create: `app/src/test/resources/gate4-fixtures/nfc-relay.yml`

**Interfaces:**
- Consumes: telemetry fields `is_sideloaded` (Boolean), `service_permissions` (List, FQN), `permissions` (List, short), and the `known_good_app_db` ioc_lookup.
- Produces: a bundled, registered rule that `GateFourFixtureTest`, `BundledRulesSchemaCrossCheckTest`, `BundledRulesManifestCompletenessTest`, and `AllRulesHaveCategoryTest` all exercise.

- [ ] **Step 1: Write the gate4 fixture (the failing test)**

Create `app/src/test/resources/gate4-fixtures/nfc-relay.yml`:

```yaml
# Fixture for androdr-087: sideloaded NFC card-emulation (HCE) app.
# Telemetry mirrors real AppScanner output:
#   service_permissions = fully-qualified (android.permission.BIND_NFC_SERVICE)
#   permissions         = short-named ("NFC")
rule_file: sigma_androdr_087_nfc_relay.yml
service: app_scanner
ioc_stubs:
  known_good_app_db:
    - "com.trusted.wallet"

true_positives:
  - package_name: "com.shady.nfcrelay"
    is_sideloaded: true
    service_permissions:
      - "android.permission.BIND_NFC_SERVICE"
    permissions:
      - "NFC"

true_negatives:
  # Play-installed wallet — not sideloaded
  - package_name: "com.google.android.apps.walletnfcrel"
    is_sideloaded: false
    service_permissions:
      - "android.permission.BIND_NFC_SERVICE"
    permissions:
      - "NFC"
  # Known-good sideloaded wallet — filtered by known_good_app_db
  - package_name: "com.trusted.wallet"
    is_sideloaded: true
    service_permissions:
      - "android.permission.BIND_NFC_SERVICE"
    permissions:
      - "NFC"
  # Sideloaded app with NFC perm but NO HCE service
  - package_name: "com.shady.nohce"
    is_sideloaded: true
    service_permissions: []
    permissions:
      - "NFC"
  # Sideloaded HCE service but NO NFC permission (edge) — composite requires both
  - package_name: "com.shady.nonfcperm"
    is_sideloaded: true
    service_permissions:
      - "android.permission.BIND_NFC_SERVICE"
    permissions: []
```

- [ ] **Step 2: Run gate4 to verify it fails**

Run: `./gradlew testDebugUnitTest --tests "com.androdr.sigma.GateFourFixtureTest"`
Expected: FAIL — the fixture references `sigma_androdr_087_nfc_relay.yml`, which does not exist yet (rule file not found / not registered).

- [ ] **Step 3: Create the rule**

Create `app/src/main/res/raw/sigma_androdr_087_nfc_relay.yml`:

```yaml
title: Sideloaded app emulating a contactless payment card (NFC relay)
id: androdr-087
status: experimental
category: incident
description: >
    A sideloaded app registers an NFC Host Card Emulation (HCE) service
    (BIND_NFC_SERVICE) and holds the NFC permission. NFC-relay malware such
    as SuperCard X and the "Ghost Tapped" cluster uses an HCE service to
    relay a victim's contactless payment card to a criminal's POS or ATM
    terminal in real time. Legitimate apps with this capability are almost
    always installed from an app store or are known-good.
author: AndroDR
date: 2026/06/23
references:
    - https://www.cleafy.com/cleafy-labs/supercardx-exposing-chinese-speaker-maas-for-nfc-relay-fraud-operation
    - https://www.group-ib.com/blog/ghost-tapped-chinese-malware/
tags:
    - attack.t1646
logsource:
    product: androdr
    service: app_scanner
detection:
    selection:
        is_sideloaded: true
        service_permissions|contains: "BIND_NFC_SERVICE"
        permissions|contains: "NFC"
    filter_known_good:
        package_name|ioc_lookup: known_good_app_db
    condition: selection and not filter_known_good
level: high
falsepositives:
    - "Sideloaded but legitimate contactless apps: third-party wallets, transit or payment cards, crypto hardware-wallet companions, and tap-to-pay tools installed outside an app store. Popular ones are suppressed by filter_known_good."
display:
    category: app_risk
    icon: contactless
    triggered_title: "NFC Card Emulation (Sideloaded)"
    evidence_type: none
remediation:
    - "This sideloaded app can emulate a contactless payment card (NFC HCE). NFC-relay malware abuses this to relay your bank card to a criminal's payment terminal in real time. If you didn't install a wallet you trust, uninstall it: Settings > Apps > [this app] > Uninstall."
implies_flags:
    - sideloaded
```

- [ ] **Step 4: Register the rule**

In `SigmaRuleEngine.kt`, add to `BUNDLED_RULE_IDS` immediately after `R.raw.sigma_androdr_083_broker_sdk_with_location_permission,` (line 353):

```kotlin
            R.raw.sigma_androdr_087_nfc_relay,
```

- [ ] **Step 5: Run the rule test suites to verify they pass**

Run: `./gradlew testDebugUnitTest --tests "com.androdr.sigma.GateFourFixtureTest" --tests "com.androdr.sigma.BundledRulesSchemaCrossCheckTest" --tests "com.androdr.sigma.BundledRulesManifestCompletenessTest" --tests "com.androdr.sigma.AllRulesHaveCategoryTest"`
Expected: PASS. The `nfc-relay` fixture's TP fires and all 4 TNs are correctly suppressed; the rule is schema-valid and registered.

- [ ] **Step 6: Commit**

```bash
git add app/src/main/res/raw/sigma_androdr_087_nfc_relay.yml app/src/main/java/com/androdr/sigma/SigmaRuleEngine.kt app/src/test/resources/gate4-fixtures/nfc-relay.yml
git commit -m "feat(rules): add androdr-087 NFC-relay detection (sideloaded HCE + NFC)"
```

---

### Task 3: Adversary fixture module (`nfc-relay`)

**Files:**
- Create: `test-adversary/fixtures/mercenary/nfc-relay/build.gradle.kts`
- Create: `test-adversary/fixtures/mercenary/nfc-relay/src/main/AndroidManifest.xml`
- Create: `test-adversary/fixtures/mercenary/nfc-relay/src/main/java/com/androdr/fixture/nfcrelay/RelayApduService.java`
- Modify: `test-adversary/fixtures/mercenary/settings.gradle.kts`

**Interfaces:**
- Produces: a buildable, sideloadable `nfc-relay-debug.apk` declaring a `BIND_NFC_SERVICE` HCE service + `NFC` permission — the on-device positive case for androdr-087.

- [ ] **Step 1: Create the build file**

`test-adversary/fixtures/mercenary/nfc-relay/build.gradle.kts`:

```kotlin
plugins { id("com.android.application") }
android {
    namespace = "com.androdr.fixture.nfcrelay"
    compileSdk = 34
    defaultConfig {
        applicationId = "com.androdr.fixture.nfcrelay"
        minSdk = 21
        targetSdk = 34
        versionCode = 1
        versionName = "1.0"
    }
}
```

- [ ] **Step 2: Create the manifest**

`test-adversary/fixtures/mercenary/nfc-relay/src/main/AndroidManifest.xml`:

```xml
<?xml version="1.0" encoding="utf-8"?>
<!--
  Adversary fixture for androdr-087 (NFC Card Emulation / Sideloaded).
  Declares an HCE HostApduService protected by BIND_NFC_SERVICE plus the NFC
  permission — the minimal NFC-relay malware fingerprint. The service class is
  a stub; the scanner reads the manifest declaration statically, never starts it.
-->
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
    <uses-permission android:name="android.permission.NFC" />
    <application android:label="NFC Relay Test">
        <service
            android:name=".RelayApduService"
            android:exported="true"
            android:permission="android.permission.BIND_NFC_SERVICE">
            <intent-filter>
                <action android:name="android.nfc.cardemulation.action.HOST_APDU_SERVICE" />
            </intent-filter>
        </service>
    </application>
</manifest>
```

- [ ] **Step 3: Create the stub service class**

`test-adversary/fixtures/mercenary/nfc-relay/src/main/java/com/androdr/fixture/nfcrelay/RelayApduService.java`:

```java
package com.androdr.fixture.nfcrelay;

// Stub — never instantiated. The scanner only reads the manifest <service>
// declaration (its android:permission), not the class. Present so the manifest
// reference resolves and lint does not flag MissingClass.
public class RelayApduService {}
```

- [ ] **Step 4: Register the module**

In `test-adversary/fixtures/mercenary/settings.gradle.kts`, add `:nfc-relay` to the `include(...)` list (after `:overlay-permission`):

```kotlin
    ":overlay-permission",
    ":nfc-relay"
```

- [ ] **Step 5: Build the fixture APK**

```bash
export JAVA_HOME=/home/yasir/Applications/android-studio/jbr ANDROID_HOME=/home/yasir/Android/Sdk
export PATH="$JAVA_HOME/bin:$ANDROID_HOME/platform-tools:$PATH"
cd test-adversary/fixtures/mercenary
./gradlew :nfc-relay:assembleDebug --quiet
ls nfc-relay/build/outputs/apk/debug/nfc-relay-debug.apk
cd /home/yasir/AndroDR
```
Expected: the APK exists.

- [ ] **Step 6: Commit**

```bash
git add test-adversary/fixtures/mercenary/nfc-relay/ test-adversary/fixtures/mercenary/settings.gradle.kts
git commit -m "test(adversary): add nfc-relay HCE fixture for androdr-087"
```

---

### Task 4: On-device verification (emulator smoke + real device)

**Files:** none (verification only).

**Interfaces:**
- Consumes: the fixture APK from Task 3, the debug AndroDR build.
- Produces: evidence that androdr-087 fires on real hardware for the fixture and not for a Play-installed HCE app.

- [ ] **Step 1: Emulator smoke harness**

```bash
export JAVA_HOME=/home/yasir/Applications/android-studio/jbr ANDROID_HOME=/home/yasir/Android/Sdk
export PATH="$JAVA_HOME/bin:$ANDROID_HOME/platform-tools:$ANDROID_HOME/emulator:$PATH"
export ANDROID_SERIAL=emulator-5554   # only if a real device is also attached
bash scripts/smoke-test.sh
```
Expected: `SMOKE TEST PASSED`.

- [ ] **Step 2: Install AndroDR debug + the fixture on the real device**

```bash
unset ANDROID_SERIAL
ADB="$ANDROID_HOME/platform-tools/adb -s R3CR300WRRH"
$ADB install -r app/build/outputs/apk/debug/app-debug.apk
$ADB install -r test-adversary/fixtures/mercenary/nfc-relay/build/outputs/apk/debug/nfc-relay-debug.apk
$ADB shell dumpsys package com.androdr.fixture.nfcrelay | grep -E "BIND_NFC_SERVICE|permission.NFC|installerPackageName"
```
Expected: the fixture holds `BIND_NFC_SERVICE` (on the service) + `android.permission.NFC`, with no trusted-store installer (sideloaded).

- [ ] **Step 3: Run a scan and confirm androdr-087 fires**

```bash
$ADB shell am start -n com.androdr.debug/com.androdr.MainActivity; sleep 6
$ADB shell uiautomator dump /sdcard/ui.xml && $ADB pull /sdcard/ui.xml /tmp/ui.xml
# locate "Run Scan" bounds, tap center, wait for "Scan complete" in logcat:
$ADB logcat -c; $ADB shell input tap <x> <y>
# poll: $ADB logcat -d -s ScanOrchestrator:D | grep "Scan complete"
$ADB exec-out run-as com.androdr.debug cat databases/androdr.db > /tmp/androdr.db
python3 - <<'PY'
import sqlite3, json
con = sqlite3.connect('/tmp/androdr.db')
findings = json.loads(con.execute("SELECT findings FROM ScanResult ORDER BY id DESC LIMIT 1").fetchone()[0])
hits = [f for f in findings if str(f.get('ruleId','')).lower() == 'androdr-087']
print("androdr-087 findings:", [(f.get('matchContext') or {}).get('package_name') for f in hits])
con.close()
PY
```
Expected: `androdr-087 findings: ['com.androdr.fixture.nfcrelay']` and no Play-installed package.

- [ ] **Step 4: Clean up the device**

```bash
$ADB uninstall com.androdr.fixture.nfcrelay
rm -f /tmp/androdr.db /tmp/ui.xml
```

- [ ] **Step 5: Full suite + lint gate**

```bash
./gradlew testDebugUnitTest lintDebug
```
Expected: `BUILD SUCCESSFUL`, all tests pass.

---

### Task 5: Companion rules-repo PR (staging mirror + IOCs)

**Files (in the android-sigma-rules submodule, on a branch off rules `main`):**
- Create: `staging/app_scanner/androdr_087_nfc_relay.yml` (identical to the `res/raw` rule)
- Modify: `ioc-data/c2-domains.yml`

**Interfaces:**
- Produces: the mirrored rule + verified NFC-relay C2 domains for the on-device 12h feed (consumed by androdr-003 domain-IOC rule).

- [ ] **Step 1: Branch the submodule off current rules main**

```bash
cd third-party/android-sigma-rules
git fetch origin main --quiet
git checkout -b feat/androdr-087-nfc-relay origin/main
```

- [ ] **Step 2: Mirror the rule**

Copy the exact `res/raw/sigma_androdr_087_nfc_relay.yml` content into `staging/app_scanner/androdr_087_nfc_relay.yml`.

- [ ] **Step 3: Append the C2 IOCs**

Append to the `entries:` list in `ioc-data/c2-domains.yml` (one block per domain, `category: "MALWARE"`, `severity: "CRITICAL"`, `source: "threat_research"`):

```yaml
  # NFC-relay fraud (SuperCard X / Ghost Tapped) — research-verified
  - indicator: "nfc.rc8820.com"
    family: "GhostTapped"
    category: "MALWARE"
    severity: "CRITICAL"
    description: "Ghost Tapped NFC-relay C2 (Group-IB)"
    source: "threat_research"
  - indicator: "xxnfc.com"
    family: "GhostTapped"
    category: "MALWARE"
    severity: "CRITICAL"
    description: "Ghost Tapped NFC-relay C2 (Group-IB)"
    source: "threat_research"
  - indicator: "txnfc.com"
    family: "GhostTapped"
    category: "MALWARE"
    severity: "CRITICAL"
    description: "Ghost Tapped NFC-relay C2 (Group-IB)"
    source: "threat_research"
  - indicator: "api.kingcardnfc.com"
    family: "SuperCardX"
    category: "MALWARE"
    severity: "CRITICAL"
    description: "SuperCard X NFC-relay C2 (Cleafy)"
    source: "threat_research"
```

(`payforce-x.*` / `kingnfc.*` are wildcard families — add only exact hostnames the source documents; do NOT invent subdomains.)

- [ ] **Step 4: Validate**

```bash
python3 validation/validate-rule.py staging/app_scanner/androdr_087_nfc_relay.yml
python3 validation/validate-ioc-data.py ioc-data/c2-domains.yml
python3 validation/validate-ioc-complementarity.py --file ioc-data/c2-domains.yml --mode strict
python3 -m pytest validation/ -q
```
Expected: all PASS.

- [ ] **Step 5: Commit, push, PR**

```bash
git add staging/app_scanner/androdr_087_nfc_relay.yml ioc-data/c2-domains.yml
git commit -m "feat(rules+ioc): mirror androdr-087 NFC-relay rule + add NFC-relay C2 domains"
git push -u origin feat/androdr-087-nfc-relay
gh pr create --repo android-sigma-rules/rules --base main --title "feat: androdr-087 NFC-relay rule mirror + C2 IOCs" --body "Companion to the AndroDR NFC-relay PR. Staging mirror of androdr-087 + research-verified NFC-relay C2 domains (source: threat_research). Staging-only — not in rules.txt."
git checkout main && git submodule update --init   # restore AndroDR's pinned submodule
cd /home/yasir/AndroDR
```

---

### Task 6: 4-agent review, then AndroDR PR

- [ ] **Step 1: Run the 4-agent review ceremony**

Dispatch four parallel reviewers (correctness / code-quality / architect / code-security) per the saved ceremony policy, each pointed at the diff (rule, scanner line, fixtures, tests). Verify each finding before acting; fix blockers and re-verify.

- [ ] **Step 2: Open the AndroDR PR**

```bash
git push -u origin feat/nfc-relay-detection
gh pr create --repo yasirhamza/AndroDR --base main \
  --title "feat(scan): NFC-relay detection (androdr-087)" \
  --body "<root cause/threat, the composite rule, the 1-line scanner change, gate4 + adversary fixtures, emulator + real-device proof, 4-agent review summary, companion rules-repo PR link>"
```

---

## Self-Review

**Spec coverage:** §3 rule → Task 2; §4 scanner line → Task 1; §5 IOCs → Task 5; §6 tests/verification → Tasks 2/3/4; §7 severity convention → encoded in the rule (Task 2); §8 delivery → Tasks 5/6; §9 out-of-scope honored (no RoleManager field, domains-only IOCs, no broad-net medium rule). All covered.

**Placeholder scan:** Task 4 Step 3 leaves `<x> <y>` tap coordinates and the rules-repo PR/AndroDR PR bodies as fill-in — these are runtime-discovered (UI dump) / prose, not code placeholders. No "TBD/handle edge cases/similar to Task N" in code steps.

**Type consistency:** `highRiskPermissions` (Task 1) matches the existing set name; `service_permissions` FQN vs `permissions` short-name is consistent across the rule (Task 2), the gate4 fixture (Task 2), and the adversary manifest (Task 3); rule id `androdr-087` and resource `sigma_androdr_087_nfc_relay` consistent across Tasks 2, 5, 6.
