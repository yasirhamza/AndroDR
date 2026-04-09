# AndroDR Detection Rules Catalog

Every detection pattern — implemented, planned, and proposed — expressed as
a YAML rule. This catalog defines the initial rule set for the rule engine (#22).

Rules marked **[IMPLEMENTED]** are currently hardcoded in AppScanner/DeviceAuditor
and will be migrated to YAML when the rule engine ships.

Rules marked **[ROADMAP #N]** correspond to open GitHub issues and will be
implemented as rules from the start (no hardcoded phase).

Rules marked **[NEW]** were identified during adversary simulation, device testing,
and threat intel research but have no GitHub issue yet.

---

## Rule categories and severity caps

Every rule declares a required `category:` field. The category determines the maximum severity a finding from that rule can carry, enforced by `SigmaRuleEngine` at evaluation time. This is a load-bearing architectural decision — see refactor issue **#84** and spec `docs/superpowers/specs/2026-04-09-unified-telemetry-findings-refactor-design.md`.

**Two categories:**

- **`incident`** — evidence that *something happened* or is actively happening: an IOC matched, an app with surveillance permissions is installed, a spyware file artifact exists, an app is impersonating another. Attribution to a specific app/event/actor. **Uncapped** — may be LOW, MEDIUM, HIGH, or CRITICAL depending on rule-declared `severity:`.

- **`device_posture`** — a *condition* that enables future compromise but is not itself an incident: bootloader unlocked, no screen lock, ADB enabled, outdated security patch, exploitable CVE present. Not attributable to an active actor. **Capped at MEDIUM** regardless of declared severity. The engine clamps `finding.level = min(declared, MEDIUM)` for any rule in this category.

**Why the cap:** if every weak configuration is red, nothing is. Posture issues must not out-shout actual intrusions in the UI or report summary. A bootloader-unlocked device with no active threats is a MEDIUM risk. A bootloader-unlocked device *and* a Pegasus IOC match is CRITICAL — the incident leg promotes the combined finding via correlation rules (see below).

**Correlation rule propagation:** correlation rules inherit their category from their member rules. If *any* member is `incident`, the correlation is `incident` and uncapped. If *all* members are `device_posture`, the correlation is `device_posture` and capped. This means "bootloader unlocked + known-bad domain contacted within 24h" goes to HIGH/CRITICAL because the domain IOC leg is incident-category, even though the bootloader leg alone would be MEDIUM.

**Categorization principle:** category reflects the *nature* of the event (something happened vs. a condition exists), not the severity. A low-severity incident is still an incident. A CVE being exploitable is still posture even if the CVE is critical.

**Build-time enforcement:** a unit test enumerates all bundled rules, finds every `category: device_posture` rule, and asserts that even with worst-case evidence the rule cannot produce a finding above MEDIUM. Rule authors who try to ship a CRITICAL device_posture rule will fail CI.

---

## Category: IOC Matching

### ANDRODR-001: Package name IOC match [IMPLEMENTED]
```yaml
id: androdr-001
title: Package name matches known malware database
status: production
tags: [attack.t1418]
category: incident
severity: CRITICAL
type: ioc_lookup
detection:
  field: package_name
  lookup: package_ioc_db
remediation:
  - "Uninstall this app immediately — it matches a known malware or stalkerware database entry."
```

### ANDRODR-002: Signing certificate hash IOC match [IMPLEMENTED]
```yaml
id: androdr-002
title: APK signed with known malicious certificate
status: production
tags: [attack.t1628]
category: incident
severity: CRITICAL
type: ioc_lookup
detection:
  field: cert_hash
  lookup: cert_hash_ioc_db
remediation:
  - "This app is signed by a known malware developer. Uninstall it even if the app name looks legitimate."
```

### ANDRODR-003: DNS domain IOC match [IMPLEMENTED]
```yaml
id: androdr-003
title: DNS query to known C2 domain
status: production
tags: [attack.t1437]
category: incident
severity: CRITICAL
type: ioc_lookup
detection:
  field: dns_query_domain
  lookup: domain_ioc_db
action: block
remediation:
  - "A connection to a known command-and-control server was blocked."
```

### ANDRODR-004: IP address IOC match [ROADMAP #6]
```yaml
id: androdr-004
title: Outbound connection to known C2 IP address
status: experimental
tags: [attack.t1437.001]
category: incident
severity: CRITICAL
type: ioc_lookup
detection:
  field: destination_ip
  lookup: ip_ioc_db
action: block
remediation:
  - "A connection to a known malicious IP address was blocked."
```

### ANDRODR-005: Graphite/Paragon domain IOC match [ROADMAP #13]
```yaml
id: androdr-005
title: DNS query to known Graphite/Paragon C2 domain
status: experimental
tags: [attack.t1437]
category: incident
severity: CRITICAL
type: ioc_lookup
detection:
  field: dns_query_domain
  lookup: graphite_domain_ioc_db
remediation:
  - "A connection to infrastructure associated with Paragon's Graphite spyware was blocked."
```

---

## Category: Behavioral Heuristics — App Analysis

### ANDRODR-010: Sideloaded app detection [IMPLEMENTED]
```yaml
id: androdr-010
title: App installed from untrusted source
status: production
tags: [attack.t1476]
category: incident
severity: MEDIUM
detection:
  all:
    - field: is_system_app
      equals: false
    - field: from_trusted_store
      equals: false
    - field: is_known_oem_app
      equals: false
remediation:
  - "This app was not installed from a trusted app store. Verify you intended to install it."
```

### ANDRODR-011: Surveillance permission cluster [IMPLEMENTED]
```yaml
id: androdr-011
title: Sideloaded app with multiple surveillance permissions
status: production
tags: [attack.t1429, attack.t1430, attack.t1512, attack.t1636]
category: incident
severity: HIGH
severity_escalation:
  condition: permission_count >= 4
  severity: CRITICAL
detection:
  all:
    - field: is_system_app
      equals: false
    - field: from_trusted_store
      equals: false
    - field: surveillance_permission_count
      gte: 2
remediation:
  - "This app has extensive surveillance capabilities. If you did not install it intentionally, uninstall it."
```

### ANDRODR-012: Accessibility service abuse [IMPLEMENTED]
```yaml
id: androdr-012
title: Sideloaded app with accessibility service
status: production
tags: [attack.t1626]
category: incident
severity: HIGH
severity_escalation:
  condition: is_sideloaded == true
  severity: CRITICAL
detection:
  all:
    - field: is_system_app
      equals: false
    - field: from_trusted_store
      equals: false
    - field: has_accessibility_service
      equals: true
remediation:
  - "This app can read your screen content. Go to Settings > Accessibility and disable its service before uninstalling."
```

### ANDRODR-013: Device admin abuse [IMPLEMENTED]
```yaml
id: androdr-013
title: Sideloaded app with device administrator
status: production
tags: [attack.t1401]
category: incident
severity: HIGH
severity_escalation:
  condition: is_sideloaded == true
  severity: CRITICAL
detection:
  all:
    - field: is_system_app
      equals: false
    - field: from_trusted_store
      equals: false
    - field: has_device_admin
      equals: true
remediation:
  - "This app has prevented its own uninstallation. Go to Settings > Security > Device Admin Apps and remove it first."
```

### ANDRODR-014: App impersonating known legitimate app [IMPLEMENTED]
```yaml
id: androdr-014
title: Sideloaded app impersonating a well-known app
status: production
tags: [attack.t1036.005]
category: incident
severity: HIGH
detection:
  all:
    - field: is_system_app
      equals: false
    - field: from_trusted_store
      equals: false
    - field: known_app_category
      equals: USER_APP
remediation:
  - "This app's package name matches a well-known app but was not installed from a trusted store — possible impersonation."
```

### ANDRODR-015: Firmware implant detection [IMPLEMENTED]
```yaml
id: androdr-015
title: System app with unknown origin
status: production
tags: [attack.t1398]
category: incident
severity: HIGH
detection:
  all:
    - field: is_system_app
      equals: true
    - field: is_known_oem_app
      equals: false
remediation:
  - "This app has system-level privileges but does not match any known OEM or AOSP package — possible firmware implant."
```

### ANDRODR-016: System name impersonation [NEW]
```yaml
id: androdr-016
title: Sideloaded app with system-impersonating name
status: experimental
tags: [attack.t1036.005]
category: incident
severity: HIGH
severity_escalation:
  condition: has_surveillance_permissions == true
  severity: CRITICAL
detection:
  all:
    - field: is_system_app
      equals: false
    - field: from_trusted_store
      equals: false
    - field: app_name
      matches_any:
        - "System*"
        - "*Service*"
        - "Google*"
        - "Android*"
        - "Samsung*"
        - "*Update*"
        - "*Security*"
        - "*Settings*"
        - "*Phone*"
        - "*Messenger*"
remediation:
  - "This app's name impersonates a system component but was installed from an untrusted source."
  - "Uninstall it unless you specifically installed it."
```

### ANDRODR-017: Accessibility + surveillance permissions combo [NEW]
```yaml
id: androdr-017
title: Sideloaded app with accessibility service AND surveillance permissions
status: experimental
tags: [attack.t1626, attack.t1429, attack.t1430]
category: incident
severity: CRITICAL
detection:
  all:
    - field: is_system_app
      equals: false
    - field: from_trusted_store
      equals: false
    - field: has_accessibility_service
      equals: true
    - field: surveillance_permission_count
      gte: 2
remediation:
  - "This app combines screen reading capability with surveillance permissions — a hallmark of stalkerware."
  - "Disable its accessibility service in Settings, then uninstall."
```

### ANDRODR-018: Packer/obfuscator detection [NEW — from APKiD research]
```yaml
id: androdr-018
title: App uses known packing or obfuscation tool
status: experimental
tags: [attack.t1027]
category: incident
severity: MEDIUM
severity_escalation:
  condition: is_sideloaded == true
  severity: HIGH
detection:
  all:
    - field: is_packed_or_obfuscated
      equals: true
remediation:
  - "This app uses code obfuscation or packing techniques commonly seen in malware."
  - "Review whether this is a legitimate app that uses commercial protection (DexGuard, etc.) or a suspicious app."
```

---

## Category: File System Artifacts [ROADMAP #8]

### ANDRODR-020: Known spyware file artifact
```yaml
id: androdr-020
title: File artifact associated with known spyware
status: experimental
tags: [attack.t1533]
category: incident
severity: CRITICAL
type: ioc_lookup
detection:
  field: file_path
  lookup: file_artifact_ioc_db
  paths:
    - /data/local/tmp/.raptor
    - /data/local/tmp/.stat
    - /data/local/tmp/.mobilesoftwareupdate
remediation:
  - "Files associated with known spyware were found on this device."
  - "This may indicate a current or past compromise."
```

---

## Category: Process Monitoring [ROADMAP #9]

### ANDRODR-030: Known spyware process name
```yaml
id: androdr-030
title: Running process matches known spyware daemon
status: experimental
tags: [attack.t1629]
category: incident
severity: CRITICAL
type: ioc_lookup
detection:
  field: process_name
  lookup: process_name_ioc_db
remediation:
  - "A running process matches a known spyware daemon name."
  - "This indicates active spyware on the device."
```

---

## Category: Device Posture [IMPLEMENTED in DeviceAuditor]

### ANDRODR-040: USB debugging enabled
```yaml
id: androdr-040
title: USB Debugging enabled
status: production
tags: [attack.t1404]
category: device_posture
severity: MEDIUM
detection:
  field: adb_enabled
  equals: true
remediation:
  - "Disable USB Debugging in Developer Options when not actively developing."
```

### ANDRODR-041: Developer options enabled
```yaml
id: androdr-041
title: Developer Options enabled
status: production
category: device_posture
severity: MEDIUM
detection:
  field: dev_options_enabled
  equals: true
remediation:
  - "Disable Developer Options unless actively needed for development."
```

### ANDRODR-042: Unknown sources enabled
```yaml
id: androdr-042
title: Install from Unknown Sources allowed
status: production
tags: [attack.t1476]
category: device_posture
severity: MEDIUM
detection:
  field: unknown_sources_enabled
  equals: true
remediation:
  - "Disable installation from unknown sources to prevent sideloaded malware."
```

### ANDRODR-043: No screen lock
```yaml
id: androdr-043
title: No screen lock configured
status: production
category: device_posture
severity: MEDIUM
detection:
  field: screen_lock_enabled
  equals: false
remediation:
  - "Set a PIN, password, pattern, or biometric lock to protect your device."
```

### ANDRODR-044: Stale security patch
```yaml
id: androdr-044
title: Security patch more than 90 days old
status: production
category: device_posture
severity: MEDIUM
detection:
  field: patch_age_days
  gte: 90
remediation:
  - "Update your device to the latest security patch level."
```

### ANDRODR-045: Bootloader unlocked
```yaml
id: androdr-045
title: Bootloader unlocked
status: production
category: device_posture
severity: MEDIUM
detection:
  field: bootloader_unlocked
  equals: true
remediation:
  - "Re-lock the bootloader unless you need it unlocked for custom ROM development."
```

### ANDRODR-046: Wireless ADB enabled
```yaml
id: androdr-046
title: Wireless ADB enabled
status: production
category: device_posture
severity: MEDIUM
detection:
  field: wifi_adb_enabled
  equals: true
remediation:
  - "Disable Wireless ADB — any device on the same network can connect and issue debug commands."
```

### ANDRODR-047: CVE-based exploit vulnerability [ROADMAP #14]
```yaml
id: androdr-047
title: Device vulnerable to known spyware exploit
status: experimental
tags: [attack.t1404]
category: device_posture
severity: MEDIUM
detection:
  field: patch_level
  lookup: cve_exploit_db
  description: Maps patch level to known exploited CVEs used by mercenary spyware
remediation:
  - "Your device's security patch level is vulnerable to a known exploit used by spyware."
  - "Update your device immediately."
```

---

## Summary

| ID Range | Category | Count | Status |
|----------|----------|-------|--------|
| 001-005 | IOC matching | 5 | 3 implemented, 2 roadmap |
| 010-018 | App behavioral heuristics | 9 | 6 implemented, 3 new |
| 020 | File artifacts | 1 | Roadmap #8 |
| 030 | Process monitoring | 1 | Roadmap #9 |
| 040-047 | Device posture | 8 | 7 implemented, 1 roadmap |

**Total: 24 rules** — 16 implemented (to migrate), 5 roadmap (to implement as rules), 3 new (identified during testing/research).
