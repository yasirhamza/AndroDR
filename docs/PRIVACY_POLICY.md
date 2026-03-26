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
- Analyzes Android bug reports for spyware indicators (user-initiated only)

---

## Data That Stays On Your Device

All scan data is stored locally in an on-device database. **None of it is ever transmitted to us or any third party.**

| Data | Purpose | Storage |
|------|---------|---------|
| Installed app list (names, permissions, signing certs) | Scanned for threat detection | On-device Room database |
| DNS queries (domain names, timestamps) | Checked against domain blocklist | On-device Room database |
| Device security flags | Posture assessment | On-device Room database |
| Scan results and history | Track security state over time | On-device Room database |
| Security reports | User-initiated export only | Device storage, shared via Android share sheet |

**We cannot see your scan results.** There is no cloud backend, no remote dashboard, no server-side processing. Cloud backup is disabled (`android:allowBackup="false"`) — your scan data is never uploaded to Google's backup service.

---

## Permissions and Why We Need Them

| Permission | Why it's needed |
|-----------|----------------|
| `QUERY_ALL_PACKAGES` | To scan all installed apps for malware indicators. A security scanner cannot detect threats in apps it cannot see. Without this permission, Android limits package visibility and malware could hide from detection. |
| `INTERNET` | To fetch publicly available threat intelligence feeds (IOC lists). No user data is sent. |
| `FOREGROUND_SERVICE` | To run the DNS monitoring VPN service while the app is in the background. |
| `ACCESS_NETWORK_STATE` | To check network connectivity before fetching IOC feed updates. |
| `READ_LOGS` | To capture AndroDR's own process log for inclusion in user-initiated security reports. This permission reads only the app's own log output (`logcat --pid`), not system-wide logs. It is used exclusively when you manually export a report. |

---

## Network Requests AndroDR Makes

AndroDR fetches publicly available threat intelligence feeds to keep its detection databases current. These requests contain **no user data, no device identifiers, and no information about your installed apps**.

| Feed | Source | What's fetched | Requests per update |
|------|--------|---------------|-------------------|
| Stalkerware indicators | AssoEchap/stalkerware-indicators (GitHub) | Known stalkerware package names | 1 HTTP GET |
| Mercenary spyware domain IOCs | mvt-project/mvt-indicators (GitHub) | Known spyware C2 domains from multiple campaigns (Pegasus, Predator, RCS Lab, etc.) | 1 index fetch + 1 per campaign (~10-20 requests) |
| Known app database (UAD) | Universal Android Debloater (GitHub) | Legitimate app lists for false positive reduction | 1 HTTP GET |
| Known app database (Plexus) | Plexus (techlore.tech) | App compatibility data | ~19 paginated requests |
| Cert hash IOCs (planned) | MalwareBazaar (abuse.ch) | Known malicious signing certificate hashes. This feed is not yet active — currently returns no data. When activated, it will require an optional API key that you provide. | 0 (stub) |

All requests are unauthenticated public HTTP GET requests. No API keys, no authentication tokens, no cookies, and no tracking headers are sent. You can verify this in the source code at `app/src/main/java/com/androdr/ioc/feeds/`.

---

## DNS Monitoring

AndroDR's DNS monitor uses a local VPN to intercept DNS queries **on your device only**. This is how it detects connections to known malicious domains.

- DNS queries are resolved locally — **no traffic is routed to external servers**
- DNS event logs are stored on-device only
- The VPN does not route, inspect, or modify your web traffic, app data, or any non-DNS network activity
- You can enable or disable DNS monitoring at any time

---

## Bug Report Analysis

AndroDR can analyze Android bug report files (`.zip`) that you manually provide. This feature:

- Reads the bug report ZIP file you select — which may contain sensitive system logs, process lists, and device state
- Scans for spyware indicators: C2 beacon patterns, suspicious process names, base64 exfiltration blobs, abnormal wakelocks, and crash patterns
- Processes everything **entirely on-device** — no part of the bug report is transmitted anywhere
- Does not retain the original bug report file — only the analysis findings are stored in scan results

Bug report files are among the most sensitive files on an Android device. AndroDR reads them only when you explicitly choose to analyze one.

---

## What Exported Reports Contain

When you export a security report, it includes:

- **Device information:** manufacturer, model, Android version, API level, security patch date
- **Scan results:** flagged apps with package names, risk levels, and reasons
- **DNS event log:** recent DNS queries with domain names, timestamps, and blocked/allowed status
- **Application log:** up to 300 lines of AndroDR's own process log (not system-wide logs)

Reports are generated only when you tap the export button. You choose who to share them with via the Android share sheet. **We never see your reports.**

---

## What We Do NOT Collect

- No personal information (name, email, phone number)
- No device identifiers (IMEI, serial number, advertising ID)
- No location data
- No browsing history
- No message content
- No photos or files
- No usage analytics or telemetry
- No automatic crash reporting or analytics SDKs
- No data shared with third parties
- No advertising SDKs
- No cloud backup of app data

---

## Data Sharing

AndroDR shares data **only when you explicitly choose to**:

- **Report export:** You generate a security report and share it via the Android share sheet. You choose the recipient. We never see it. Review the "What Exported Reports Contain" section above to understand what is included.
- **No automatic sharing:** Nothing is sent anywhere without your explicit action.

---

## Data Retention and Deletion

- Scan history and DNS events are stored on-device indefinitely until you clear them
- Cloud backup is disabled — your data is not backed up to Google's servers
- Uninstalling AndroDR deletes all stored data from the device
- You can clear all app data at any time via Android Settings > Apps > AndroDR > Clear Data

---

## Open Source Transparency

AndroDR's source code is publicly available. Every detection heuristic, every network request, every data storage operation is visible in the code. This is intentional — security tools that operate as black boxes ask for trust they haven't earned.

- **Repository:** github.com/yasirhamza/AndroDR
- **Detection logic:** `app/src/main/java/com/androdr/scanner/`
- **Network requests:** `app/src/main/java/com/androdr/ioc/feeds/`
- **Data storage:** `app/src/main/java/com/androdr/data/`

If you find a privacy concern in the code, open an issue or contact us directly.

---

## Google Play Data Safety Alignment

For Google Play's Data Safety section, AndroDR declares:

- **Data collected:** Installed app list (on-device only, never transmitted), device info (included in user-initiated reports only)
- **Data shared:** None (user-initiated report sharing is under user control)
- **Data encrypted in transit:** N/A — no user data is transmitted
- **Data deletion:** Available via app uninstall or clearing app data

---

## Children's Privacy

AndroDR does not knowingly collect any data from children under 13. The app does not collect data from anyone — it operates entirely on-device.

---

## International Users (GDPR / CCPA)

AndroDR processes no personal data on any server. All processing occurs on your device. As a result:

- **EU users (GDPR):** No personal data is collected or processed by the developer. Your rights under GDPR (access, rectification, erasure, portability) are fulfilled by the fact that all data resides on your device under your control. Uninstalling the app erases all data. The data controller for on-device data is you.
- **California users (CCPA):** AndroDR does not sell, share, or disclose personal information to any third party. There is no personal information to sell because none is collected.

---

## Governing Law

This privacy policy is governed by the laws of the jurisdiction in which the developer resides. Disputes related to this policy shall be resolved in the courts of that jurisdiction.

---

## Changes to This Policy

If this policy changes, the updated version will be published in the repository and the "last updated" date will be revised. Since AndroDR collects no data, meaningful policy changes are unlikely.

---

## Contact

For privacy questions or concerns:
- Email: privacy@androdr.dev
- GitHub: github.com/yasirhamza/AndroDR/issues
