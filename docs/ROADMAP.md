# AndroDR — Feature Roadmap

Items are listed in rough priority order within each section.
This file is updated as gaps are identified; it does not imply a delivery schedule.

---

## Completed

| Feature | Issue | Date |
|---------|-------|------|
| IP address IOC detection | #6 | 2026-03-27 |
| APK certificate hash IOC matching | #7 | 2026-03-26 |
| File system artifact scanning | #8 | 2026-03-27 |
| Running process name scanning | #9 | 2026-03-27 |
| Accessibility / Device Admin abuse detection | #10 | 2026-03-26 |
| Threat remediation guidance | #12 | 2026-03-26 |
| Graphite/Paragon spyware IOC coverage | #13 | 2026-03-27 |
| CVE-based exploit detection | #14 | 2026-03-27 |
| YAML-based detection rule engine (SIGMA) | #22 | 2026-03-27 |
| Enhanced CVE display + SIGMA engine revision | #25 | 2026-03-27 |
| ReDoS mitigation for regex rules | #26 | 2026-03-27 |
| TLS certificate pinning on security feeds | #27 | 2026-03-28 |
| Release build verification | #21 | 2026-03-27 |

---

## Open — Performance & Security Hardening

| Priority | Issue | Description |
|----------|-------|-------------|
| 1 | #28 | OSV ETag caching — avoid 7.3MB re-download on every refresh |
| 2 | — | RE2j adoption for linear-time regex (follow-up to #26) |
| 3 | — | TLS pin rotation monitoring script (follow-up to #27) |

---

## Open — Play Store Publishability

| Priority | Issue | Description |
|----------|-------|-------------|
| 1 | #15 | Write privacy policy |
| 2 | #16 | QUERY_ALL_PACKAGES declaration justification |
| 3 | #17 | VPN permission declaration |
| 4 | #18 | Data safety form |
| 5 | #19 | Content rating (IARC) |
| 6 | #20 | Store listing assets (screenshots, description) |

---

## Future Work

| Feature | Issue | Notes |
|---------|-------|-------|
| Threat hunting / forensic analysis mode | #11 | MVT-style deep device inspection from backups |
| Public SIGMA rule repository | — | Community-contributed detection rules (separate repo) |
| iOS companion app | — | Out of scope for Android-only release |
| Remote report upload / SIEM integration | — | Enterprise feature |
| Real-time permission-use monitoring | — | Camera/mic activation events |

---

## Architecture Notes

All detection logic is rule-driven via YAML SIGMA rules. New detection patterns
are added as rule files, not Kotlin code. The rule engine supports:
- Field matching with modifiers (contains, startswith, regex, numeric comparisons)
- IOC lookups (package, cert hash, domain databases)
- Evidence providers (CVE lists with campaign attribution)
- Display metadata (titles, icons, severity, evidence type) embedded in rules
- Remote rule feeds from configurable URLs
