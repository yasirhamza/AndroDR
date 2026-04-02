# Changelog

## v0.9.0 (2026-04-02)

### Detection
- **APK SHA-256 hash matching** — every installed app's APK file is hashed and checked against MalwareBazaar threat intelligence feeds and a bundled malware hash database
- **Unified IOC architecture** — single indicators table replaces 3 separate IOC tables, supporting package names, domains, cert hashes, and APK hashes
- **STIX2 import/export** — export scan findings as STIX 2.1 JSON bundles for forensic handoff; import MVT-format indicator bundles
- **9 bugreport analysis modules** — accessibility services, broadcast receivers, AppOps permission usage, battery/install timeline, activity handlers, ADB trusted keys, platform compatibility, database operations, legacy pattern scan
- **Cellebrite UFED CVE detection** (staging) — 3 CVEs used in Serbian journalist attacks
- **BOOT_COMPLETED persistence detection** (staging) — apps that auto-start on boot
- **Dynamic DNS C2 detection** (staging) — 22 DDNS provider suffixes
- **Screen overlay detection** (staging) — SYSTEM_ALERT_WINDOW on sideloaded apps
- **Popular-app impersonation** (staging) — sideloaded apps mimicking WhatsApp, Snapchat, etc.

### Reports & Exports
- **APP HASH INVENTORY** in scan reports — SHA-256 for every installed app
- **Standalone hash export** — Settings > Export App Hashes (CSV) for VirusTotal bulk lookup
- **STIX2 findings export** — Settings > Export Findings (STIX2 JSON)
- **Campaign check section** — Pegasus/Predator/Graphite/Cellebrite detection status
- **Remediation steps** in all device posture findings
- **Spyware artifact paths** shown specifically (not generic titles)
- **Data provenance** — iocSource, campaignName, appName populated in timeline events
- **Bugreport findings grouped** by type with package names

### False Positive Reduction
- Known-good app filter covers all categories (USER_APP, OEM, GOOGLE, AOSP, POPULAR)
- OEM prefix matching via dynamic resolver (Samsung, Xiaomi, Huawei, etc.)
- Bitwarden, Perplexity, Google apps no longer flagged for accessibility/camera/mic

### Performance
- **15MB memory reduction** — domain IOC cache replaced with Room + LRU (was OOM-killing on low-RAM devices)
- **OSV ETag caching** — skips 7.3MB CVE database re-download when unchanged
- **APK hash computation** — ~5-10 seconds for 150 apps via streaming SHA-256

### Infrastructure
- **Bundled databases** — 86 CVEs, 9 APK hashes, package/cert IOCs available offline from first launch
- **SIGMA rules load at startup** — Settings shows correct counts immediately
- **Package lifecycle monitor** — records install/update/uninstall events in forensic timeline
- **Deep-links** — tap app finding to see filtered timeline
- **CI versioned releases** — each build creates a tagged release
- **Unified scan selection** — all screens show the same scan data

### IOC Updates (auto-deployed, no app update needed)
- NoviSpy (Serbia) — 4 packages, 3 cert hashes
- ResidentBat (Belarus) — 8 packages, 8 cert hashes
- Wintego Helios — 22 C2 domains
- Cellebrite UFED agent — 1 package
- EasyPhoneTrack Snapchat impersonation — 2 packages, 2 cert hashes
- MobileTrackerFree — 1 new cert hash

### Bug Fixes
- STIX2 export crash (was serializing 371K blocklist domains)
- STIX2 bundle missing `type` field (kotlinx.serialization encodeDefaults)
- False download error on scan (ETag cache hit mistaken for failure)
- Device screen showing different scan than Dashboard
- Timeline not persisting informational findings
- Template variables not resolving in spyware artifact rule titles
- History preview not matching export (missing hash inventory)
