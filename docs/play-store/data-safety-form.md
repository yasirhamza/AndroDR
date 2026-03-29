# Data Safety Form Answers

## For Google Play Console: Data Safety Section

### Does your app collect or share any of the required user data types?

**No.** AndroDR does not collect, share, or transmit any user data to the developer or third parties.

---

### Data Types — Detailed Answers

| Data Type | Collected? | Shared? | Notes |
|-----------|-----------|---------|-------|
| **Location** | No | No | |
| **Personal info** (name, email, IDs) | No | No | |
| **Financial info** | No | No | |
| **Health and fitness** | No | No | |
| **Messages** | No | No | |
| **Photos and videos** | No | No | |
| **Audio files** | No | No | |
| **Files and docs** | No | No | Bug reports are user-selected and processed on-device only |
| **Calendar** | No | No | |
| **Contacts** | No | No | |
| **App activity** | No | No | Installed app list is scanned on-device only, never transmitted |
| **Web browsing** | No | No | |
| **App info and performance** | No | No | No crash reporting, no analytics |
| **Device or other IDs** | No | No | No IMEI, serial, advertising ID collection |

### Data handling practices

| Practice | Answer |
|----------|--------|
| Is data encrypted in transit? | N/A — no user data is transmitted |
| Can users request data deletion? | Yes — uninstall the app or clear app data via Android Settings |
| Is data processing optional? | All processing is on-device; no remote processing occurs |
| Does the app follow the Families policy? | Not applicable (not a children's app) |

### Network requests

AndroDR makes unauthenticated HTTP GET requests to publicly available threat intelligence repositories (GitHub) to update its detection databases. These requests contain:
- No user data
- No device identifiers
- No installed app information
- No cookies or tracking headers

### Third-party SDKs

AndroDR contains **no** third-party analytics, advertising, or tracking SDKs.

### Security practices

| Practice | Answer |
|----------|--------|
| App data encrypted at rest? | Android's default encryption applies; cloud backup is disabled |
| Follows responsible disclosure? | Yes — via GitHub issues |
| Security review conducted? | Open source — code publicly auditable |
