# Play Store Listing

## App name
AndroDR

## Short description (80 chars max)
Detect spyware, stalkerware & malware on your phone. Open-source mobile EDR.

## Full description (4000 chars max)

AndroDR is a free, open-source security scanner that checks your Android phone for spyware, stalkerware, and malware. Built for anyone who wants to know if their device is compromised — from domestic violence survivors to journalists to IT security teams.

**What AndroDR checks:**

• Installed apps — scanned against threat intelligence databases for known malware package names, certificate hashes, and APK file hashes
• Device security — screen lock, USB debugging, developer options, bootloader status, security patch level
• Unpatched vulnerabilities — checks your patch level against the CISA Known Exploited Vulnerabilities catalog and OSV Android database
• Mercenary spyware — specific checks for Pegasus (NSO Group), Predator (Intellexa), and Graphite (Paragon) indicators
• DNS activity — optional network monitor detects connections to known command-and-control servers
• Surveillance permissions — identifies apps with camera, microphone, location, SMS, and contact access
• Accessibility abuse — detects apps misusing accessibility services for monitoring
• APK file hashes — SHA-256 hashes for every app, ready for VirusTotal lookup

**What makes AndroDR different:**

• Everything runs on your phone — no cloud, no accounts, no data leaves your device
• Open-source detection rules (SIGMA format) — transparent, auditable, community-updatable
• Bugreport analysis — import Android system diagnostics for deep forensic analysis
• Forensic timeline — correlates events across app installs, permission use, DNS activity, and device changes
• STIX2 export — share findings with forensic analysts in the industry-standard format
• CSV export — import into spreadsheets, SIEM tools, or analysis platforms

**Who AndroDR is for:**

• People concerned about stalkerware or monitoring by a partner
• Journalists and activists at risk of state-sponsored surveillance
• IT security teams doing device health checks
• Privacy-conscious individuals who want a clean bill of health
• Anyone who wants to verify their phone hasn't been compromised

**Detection sources:**

• CISA Known Exploited Vulnerabilities catalog
• OSV Android vulnerability database
• MalwareBazaar threat intelligence (abuse.ch)
• MVT indicators (Amnesty Tech)
• ThreatFox domain IOCs
• HaGeZi Threat Intelligence Feeds
• Stalkerware Indicators (Coalition Against Stalkerware)
• Community-maintained SIGMA detection rules

**Privacy:**

AndroDR does not collect, transmit, or share any personal data. All scanning and analysis happens entirely on your device. Threat intelligence databases are downloaded to your phone — your data never goes the other way. See our full privacy policy for details.

## Category
Tools

## Tags
security, antivirus, malware scanner, stalkerware detector, spyware, privacy, EDR, endpoint detection, mobile security, phone security

## Contact email
(your email)

## Privacy policy URL
https://yasirhamza.github.io/AndroDR/privacy

## Screenshots needed (take from S25 Ultra)
1. Dashboard — clean scan showing LOW risk with green indicators
2. Dashboard — scan with findings showing risk level and guidance
3. Device audit — checks passed/failed with remediation steps
4. Apps screen — flagged apps with severity and details
5. Network monitor — DNS filtering active with events
6. Timeline — forensic timeline with event correlation
7. Settings — threat database stats and export options
8. Bugreport analysis — deep device scan results

## Feature graphic (1024x500)
Design needed — suggest: dark background with AndroDR logo, shield icon, tagline "Know if your phone is compromised"

## App icon (512x512)
Use existing ic_launcher at higher resolution
