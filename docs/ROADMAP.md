# AndroDR — Feature Roadmap

The canonical source of truth for open work is the
[GitHub issue tracker](https://github.com/yasirhamza/AndroDR/issues).
This file is a human-readable snapshot refreshed at milestones.

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

## Open — MVT-Parity Forensic Analysis (#11)

Kotlin port of MVT's detection logic — bugreport parsing + runtime API equivalents.
Prioritized by: detection value × user impact × publishability.

### Tier 1 — Foundation

| Priority | Issue | Description |
|----------|-------|-------------|
| 1 | #31 | Expose Bug Report Analysis in Dashboard UI |
| 2 | #32 | Dumpsys section parser for structured bugreport analysis |

### Tier 2 — High-Value Detection

| Priority | Issue | Description |
|----------|-------|-------------|
| 3 | #33 | AppOps permission usage analysis (bugreport + runtime) |
| 4 | #34 | Broadcast receiver audit — SMS/call interception (bugreport + runtime) |
| 5 | #35 | Enabled accessibility services audit (bugreport + runtime) |

### Tier 3 — Moderate Value

| Priority | Issue | Description |
|----------|-------|-------------|
| 6 | #36 | Battery daily install/uninstall timeline (bugreport) |
| 7 | #37 | Full STIX2 indicator pattern support |
| 8 | #38 | Activity/intent handler audit (bugreport) |

### Tier 4 — Specialist / Forensic

| Priority | Issue | Description |
|----------|-------|-------------|
| 9 | #39 | Database operations audit (bugreport) |
| 10 | #40 | ADB trusted keys + PlatformCompat audit (bugreport) |
| 11 | #41 | Cross-module forensic timeline view |

---

## Future Work

| Feature | Issue | Notes |
|---------|-------|-------|
| Public SIGMA rule repository | — | Community-contributed detection rules (separate repo) |
| iOS companion app | — | Out of scope for Android-only release |
| Remote report upload / SIEM integration | — | Enterprise feature |

---

## Architecture Notes

All detection logic is rule-driven via YAML SIGMA rules. New detection patterns
are added as rule files, not Kotlin code. The rule engine supports:
- Field matching with modifiers (contains, startswith, regex, numeric comparisons)
- IOC lookups (package, cert hash, domain databases)
- Evidence providers (CVE lists with campaign attribution)
- Display metadata (titles, icons, severity, evidence type) embedded in rules
- Remote rule feeds from configurable URLs
