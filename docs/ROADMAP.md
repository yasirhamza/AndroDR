# AndroDR — Feature Roadmap

Items are listed in rough priority order within each section.
This file is updated as gaps are identified; it does not imply a delivery schedule.

---

## Detection Gaps (identified 2026-03-26)

These gaps were surfaced during adversary simulation design and represent
IOC/TTP categories that AndroDR does not currently detect.
Each item should be driven by a failing test before implementation (TDD).

| Gap | Description | ATT&CK ref |
|-----|-------------|------------|
| **IP address IOC detection** | Extend DnsVpnService to check TCP/UDP destination IPs against a known-bad IP list in addition to DNS domain matching | T1437 |
| **APK certificate hash IOCs** | Add cert-hash field to IOC database; AppScanner extracts APK signing cert SHA-256 and matches against IOC list | T1628 |
| **File artifact scanning** | Scan filesystem for known spyware artifact paths (e.g. Pegasus `/tmp/.raptor`, Predator `/.stat`) | T1533 |
| **Process name scanning** | Enumerate running processes via `/proc` and match against known spyware daemon names from MVT indicators | T1629 |
| **Accessibility / Device Admin abuse** | Flag apps that hold AccessibilityService registration or DeviceAdminReceiver — high-confidence persistence/surveillance TTPs | T1626, T1401 |

---

## Potential Future Work

- **Threat hunting / forensic analysis mode** — MVT-style deep device inspection: parse SMS/call/browser databases from device backups, extract filesystem artifacts, cross-reference against IOC lists. Targeted at trained analysts for post-compromise investigation. Requires backup access permissions and analyst-facing UI.
- iOS companion app (out of scope for Android-only release)
- Remote report upload / SIEM integration
- Real-time permission-use monitoring (camera/mic activation events)
