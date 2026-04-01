# Data Safety Form Answers

## Does your app collect or share any of the required user data types?
Yes — the app collects device and app information for on-device security analysis.

---

## Data types collected

### App info and performance
- **Installed apps**: Package names, version codes, installer source, permissions
  - Purpose: App functionality (security scanning)
  - Required: Yes
  - Shared: No
  - Processed on-device: Yes
  - User can request deletion: Yes (clear app data)

### Device or other IDs
- **Device model, OS version, security patch level**: Used in security reports
  - Purpose: App functionality (device security assessment)
  - Required: Yes
  - Shared: No — only included in user-exported reports
  - Processed on-device: Yes
  - User can request deletion: Yes

### App activity
- **DNS queries** (domain names only, when VPN enabled): Monitored for threat detection
  - Purpose: App functionality (network threat detection)
  - Required: No (VPN is optional)
  - Shared: No
  - Processed on-device: Yes
  - Encrypted: Yes (Room database on encrypted storage)
  - User can request deletion: Yes
  - Automatically deleted after 30 days

---

## Data types NOT collected
- Personal info (name, email, phone number)
- Financial info
- Health and fitness
- Messages
- Photos and videos
- Audio files
- Files and docs (except user-selected bugreport .zip files for analysis)
- Calendar
- Contacts
- Location (not collected by AndroDR itself — only detects if OTHER apps use location)
- Web browsing history
- Search history
- Advertising ID

---

## Data sharing
**AndroDR does not share any data with third parties.**

- No analytics SDKs
- No advertising SDKs
- No crash reporting services (crashes logged locally only)
- No cloud backend
- No user accounts
- No telemetry transmission

All threat intelligence data flows **inbound** (downloaded IOC databases). No user data flows **outbound**.

---

## Security practices

### Is data encrypted in transit?
Yes — all threat intelligence feed downloads use HTTPS. No user data is transmitted.

### Is data encrypted at rest?
Yes — Room database is stored on Android's encrypted file system. Reports are cached in the app's private storage directory.

### Can users request data deletion?
Yes — clearing the app's data (Settings > Apps > AndroDR > Clear Data) removes all stored scan results, DNS logs, timeline events, and cached reports.

### Does the app follow Google's Families policy?
Not applicable — AndroDR is not designed for children.
