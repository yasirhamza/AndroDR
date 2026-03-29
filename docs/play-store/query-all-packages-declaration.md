# QUERY_ALL_PACKAGES Permission Declaration

## For Google Play Console: Permission Declaration Form

### Why does your app need the QUERY_ALL_PACKAGES permission?

AndroDR is a security scanner and endpoint detection app that checks all installed applications against known malware, stalkerware, and spyware indicator databases. The app must enumerate the complete list of installed packages to:

1. **Match package names against known-malicious app databases** — including stalkerware indicators from AssoEchap, spyware IOCs from Amnesty International's MVT project, and abuse.ch ThreatFox
2. **Match APK signing certificate hashes** against known-bad certificate databases to detect repackaged malware
3. **Detect sideloaded apps** installed from untrusted sources (no installer package or installed via ADB)
4. **Identify suspicious permission combinations** — apps requesting surveillance permissions (camera, microphone, SMS, contacts, location) in combination with accessibility services or device admin
5. **Detect accessibility service abuse** — non-system apps with active accessibility services (a primary stalkerware persistence mechanism)

### Why can't you use a targeted `<queries>` declaration instead?

A `<queries>` filter requires knowing which packages to look for in advance. AndroDR's detection model is signature-based: it compares the **entire** installed app list against dynamically-updated threat intelligence databases. New threats are added to these databases daily. A static `<queries>` filter would:

- Miss zero-day threats not yet in any database
- Require an app update every time a new malware package name is discovered
- Defeat the purpose of a comprehensive security scan

### What category does your app fall under?

**Device search / antivirus / security management** — AndroDR is an open-source endpoint detection and response (EDR) tool comparable to commercial products like Certo AntiSpy and Lookout.

### Core functionality

The app's core functionality is scanning the device for security threats. Without QUERY_ALL_PACKAGES, the app cannot perform its primary function. It does not use package information for advertising, analytics, or any purpose other than security scanning.
