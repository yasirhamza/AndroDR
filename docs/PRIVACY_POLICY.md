# AndroDR Privacy Policy

_Last updated: 2026-04-25_

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
- Optionally monitors DNS queries for connections to known command-and-control servers (**optional** DNS monitoring — you must explicitly enable the local VPN)
- Audits device security settings (screen lock, bootloader, debug mode, patch level)
- Analyzes Android bug reports for spyware indicators (user-initiated only)
- Evaluates detection rules expressed as auditable YAML — detection logic is not hidden inside compiled code
- Imports and exports STIX2-compatible indicators for interoperability with other forensic tools

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
| Forensic timeline events (e.g., device admin grants) | Displayed in the timeline screen; included in exported reports | On-device Room database |
| Bug report analysis findings | Displayed with scan results; original bug report ZIP is discarded after analysis | On-device Room database |

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
| `MANAGE_EXTERNAL_STORAGE` | To scan external storage for known spyware file artifacts. On Android 11+, scoped storage prevents apps from checking arbitrary file paths without this permission. AndroDR checks a small set of known artifact paths documented in forensic research — it does not browse or index your files. |

---

## Network Requests AndroDR Makes

AndroDR fetches publicly available threat intelligence feeds to keep its detection databases current. These requests contain **no user data, no device identifiers, and no information about your installed apps**.

| Feed | Source | What's fetched | Requests per update |
|------|--------|---------------|-------------------|
| Stalkerware indicators | AssoEchap/stalkerware-indicators (GitHub) | Known stalkerware package names | 1 HTTP GET |
| Mercenary spyware domain IOCs | mvt-project/mvt-indicators (GitHub) | Known spyware C2 domains from multiple campaigns (Pegasus, Predator, RCS Lab, etc.) | 1 index fetch + 1 per campaign (~10-20 requests) |
| Known app database (UAD) | Universal Android Debloater (GitHub) | Legitimate app lists for false positive reduction | 1 HTTP GET |
| Known app database (Plexus) | Plexus (techlore.tech) | App compatibility data | ~19 paginated requests |
| MalwareBazaar APK + cert hashes | abuse.ch MalwareBazaar public API | Hashes of known malicious APKs and the cert hashes that signed them | 1 API request per refresh |
| ThreatFox indicators | abuse.ch ThreatFox public API | Command-and-control domain / IP indicators | 1 API request per refresh |
| Stalkerware cert-hash indicators | AssoEchap/stalkerware-indicators (GitHub) | Cert hashes of known stalkerware signers | 1 HTTP GET |
| SIGMA detection rules | android-sigma-rules/rules (GitHub) | Rule manifest (`rules.txt`), SHA-256 integrity manifest (`rules.sha256`), then one GET per rule YAML file listed in the manifest. Each downloaded rule is integrity-checked against the manifest before being loaded. | 2 manifests + 1 per rule |
| Centralized IOC data | android-sigma-rules/rules (GitHub) | Package names, C2 domains, signing-cert hashes, APK hashes, and known-good app lists from the repo's `ioc-data/` directory | 5 HTTP GETs |
| **Optional:** custom rule URLs | URLs you configure in Settings → Custom Rule Sources | Same SIGMA-rule-feed format as above. Disabled by default; only fetched if you add a URL. | Same as above per configured URL |

All requests are unauthenticated public HTTP GET requests. No API keys, no authentication tokens, no cookies, and no tracking headers are sent. You can verify this in the source code at `app/src/main/java/com/androdr/ioc/feeds/`.

All ingesters run inside a dispatcher that deduplicates indicators across feeds before writing to the on-device database. Each feed is independently auditable in `app/src/main/java/com/androdr/ioc/feeds/`.

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

AndroDR retains only the analysis findings — flagged app names, indicator matches, detected patterns — in the scan result. The original bug report ZIP is not stored on-device after analysis completes.

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

### Detection rules live in a separate, public repository

What the app looks for is not hidden inside compiled Kotlin. AndroDR's detection rules are authored as human-readable YAML in an independent public repository — [github.com/android-sigma-rules/rules](https://github.com/android-sigma-rules/rules) — and bundled into the app at build time via a pinned git submodule. The rule schema (`validation/rule-schema.json`) is published alongside the rules. This decoupling has two privacy consequences:

- **You can read every rule before installing.** Each rule names the indicator (package name, signing-cert hash, DNS domain, permission combination, etc.), the threat it models, and the public source it was derived from. No detection exists only inside the binary.
- **Rule changes are reviewable independently of the app.** New detections land in the rules repo through a public 5-gate validation pipeline (schema check, build, IOC sanity, semantic deduplication, and an independent review pass). You can audit the diff between any two rule-bundle versions without disassembling the APK.

The threat-intelligence feeds AndroDR ingests at runtime are listed in the "Network Requests" section above. The rules that decide what those indicators *mean* live in the rules repo. Both are public; neither is part of the compiled app's hidden state. Advanced users can also configure additional rule sources in Settings; those URLs are fetched in the same way as the default repo and are listed in the Network Requests table above.

---

## Google Play Data Safety Alignment

For Google Play's Data Safety section, AndroDR declares:

- **Data collected:** Installed app list (package names, permissions, signing certs — on-device only, never transmitted); device info (model, OS version, security patch level — included in user-initiated reports only); DNS query domain names (only when the optional DNS VPN is enabled — on-device only, auto-deleted after 30 days); diagnostic info (app-own logcat — included in user-initiated reports only)
- **Data shared:** None — user-initiated report sharing is under user control and not considered "sharing with third parties"
- **Data encrypted in transit:** N/A — no user data is transmitted; all outbound requests are inbound-only IOC feed downloads over HTTPS
- **Data encrypted at rest:** Yes — Room database is stored on Android's encrypted file system; cached reports reside in the app's private storage directory
- **Data deletion:** Users can clear all stored data at any time via Android Settings > Apps > AndroDR > Clear Data, or by uninstalling the app; DNS events are also automatically deleted after 30 days
- **Optional data collection:** DNS query monitoring is entirely optional — the local VPN must be explicitly enabled by the user

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
- Email: yhamad.dev@gmail.com
- GitHub: github.com/yasirhamza/AndroDR/issues
