# AndroDR Privacy Policy

_Last updated: 2026-03-26_

## Our Philosophy

AndroDR is an open-source security tool built on a simple principle: **your data stays on your device**. The entire source code is publicly auditable — you don't have to trust our words, you can read the code.

We believe security tools should give users full visibility and control, not create new surveillance risks. AndroDR collects no accounts, no analytics, no telemetry, and phones home to no servers. Everything it does happens on your device, under your control.

---

## What AndroDR Does

AndroDR scans your device for security threats:
- Checks installed apps against known malware and stalkerware databases
- Matches app signing certificates against known malicious certificate hashes
- Detects apps with dangerous permission combinations
- Identifies sideloaded apps from untrusted sources
- Detects accessibility service and device admin abuse
- Monitors DNS queries for connections to known command-and-control servers
- Audits device security settings (screen lock, bootloader, debug mode, patch level)

---

## Data That Stays On Your Device

All scan data is stored locally in an on-device database. **None of it is ever transmitted to us or any third party.**

| Data | Purpose | Storage |
|------|---------|---------|
| Installed app list (names, permissions, signing certs) | Scanned for threat detection | On-device Room database |
| DNS queries | Checked against domain blocklist | On-device Room database |
| Device security flags | Posture assessment | On-device Room database |
| Scan results and history | Track security state over time | On-device Room database |
| Security reports | User-initiated export only | Device storage, shared via Android share sheet |

**We cannot see your scan results.** There is no cloud backend, no remote dashboard, no server-side processing.

---

## Network Requests AndroDR Makes

AndroDR fetches publicly available threat intelligence feeds to keep its detection databases current. These requests contain **no user data, no device identifiers, and no information about your installed apps**.

| Feed | URL | What's fetched | What's sent |
|------|-----|---------------|-------------|
| Stalkerware indicators | AssoEchap/stalkerware-indicators (GitHub) | Known stalkerware package names | Nothing (public HTTP GET) |
| Domain IOCs | mvt-project/mvt-indicators (GitHub) | Known spyware C2 domains | Nothing (public HTTP GET) |
| Known app database | Universal Android Debloater, Plexus | Legitimate app lists for false positive reduction | Nothing (public HTTP GET) |

No API keys, no authentication tokens, no cookies, and no tracking headers are sent with these requests. You can verify this in the source code.

---

## DNS Monitoring

AndroDR's DNS monitor uses a local VPN to intercept DNS queries **on your device only**. This is how it detects connections to known malicious domains.

- DNS queries are resolved locally — **no traffic is routed to external servers**
- DNS event logs are stored on-device only
- The VPN does not route, inspect, or modify your web traffic, app data, or any non-DNS network activity
- You can enable or disable DNS monitoring at any time

---

## What We Do NOT Collect

- No personal information (name, email, phone number)
- No device identifiers (IMEI, serial number, advertising ID)
- No location data
- No browsing history
- No message content
- No photos or files
- No usage analytics or telemetry
- No crash reports
- No data shared with third parties
- No advertising SDKs

---

## Data Sharing

AndroDR shares data **only when you explicitly choose to**:

- **Report export:** You can generate a security report and share it via the Android share sheet. You choose the recipient. We never see it.
- **No automatic sharing:** Nothing is sent anywhere without your action.

---

## Data Retention and Deletion

- Scan history and DNS events are stored on-device indefinitely until you clear them
- Uninstalling AndroDR deletes all stored data
- You can clear all app data at any time via Android Settings > Apps > AndroDR > Clear Data

---

## Open Source Transparency

AndroDR's source code is publicly available. Every detection heuristic, every network request, every data storage operation is visible in the code. This is intentional — security tools that operate as black boxes ask for trust they haven't earned.

- **Repository:** github.com/yasirhamza/AndroDR
- **Detection logic:** `app/src/main/java/com/androdr/scanner/`
- **Network requests:** `app/src/main/java/com/androdr/ioc/feeds/`
- **Data storage:** `app/src/main/java/com/androdr/data/`

If you find a privacy concern in the code, open an issue.

---

## Children's Privacy

AndroDR does not knowingly collect any data from children under 13. The app does not collect data from anyone — it operates entirely on-device.

---

## Changes to This Policy

If this policy changes, the updated version will be published in the repository and the "last updated" date will be revised. Since AndroDR collects no data, meaningful policy changes are unlikely.

---

## Contact

For privacy questions or concerns:
- Open an issue at github.com/yasirhamza/AndroDR/issues
