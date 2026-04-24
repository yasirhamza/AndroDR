# Play Store Listing

## Short Description (80 chars max)

Open-source Android security scanner — detect spyware, stalkerware, and threats

## Full Description (4000 chars max)

AndroDR is a free, open-source security scanner that checks your Android device for spyware, stalkerware, and security threats. Everything runs on your device — no accounts, no cloud, no tracking.

WHAT ANDRODR DETECTS

• Known malware and stalkerware (Pegasus, FlexiSpy, mSpy, Cerberus, and more)
• Sideloaded apps from untrusted sources
• Apps abusing accessibility services or device admin
• Dangerous permission combinations (camera + microphone + location)
• Connections to known command-and-control servers (DNS monitoring)
• Outdated security patches with known exploited vulnerabilities
• Unlocked bootloader, USB debugging, and other device posture issues

HOW IT WORKS

AndroDR uses SIGMA-compatible detection rules — the same standard used by enterprise security tools. Detection patterns are updated independently of the app through public threat intelligence feeds.

• Scan installed apps against IOC databases (stalkerware indicators, abuse.ch ThreatFox, Amnesty Tech, Citizen Lab)
• Match APK signing certificates against known-bad hashes
• Monitor DNS queries for C2 server connections (local VPN, no traffic leaves device)
• Audit device security settings (screen lock, patch level, ADB, bootloader)
• Analyze Android bug reports for forensic indicators

FORENSIC TIMELINE

AndroDR builds a forensic timeline of security events — permission usage, app installs, DNS matches, and scan findings — with severity filtering and export. Export as plaintext or MVT-compatible CSV for law enforcement or advocacy organizations.

PRIVACY BY DESIGN

• No accounts, no registration, no sign-up
• No analytics, no telemetry, no crash reporting
• No data transmitted to developers or third parties
• No advertising SDKs
• Cloud backup disabled
• Full source code publicly auditable on GitHub

AndroDR is built for journalists, activists, domestic violence survivors, and anyone who wants to know if their phone is compromised. It complements Amnesty International's MVT (Mobile Verification Toolkit) by providing on-device detection without requiring a computer.

Source code: github.com/yasirhamza/AndroDR

## Category

Tools

## Tags

security, antivirus, spyware, stalkerware, malware, scanner, privacy, EDR, forensics, threat detection

## Contact Email

yhamad.dev@gmail.com

## Privacy Policy URL

https://yasirhamza.github.io/androdr-site/#privacy

---

## Release Notes — v0.9.0 (Closed Testing)

AndroDR v0.9.0 — First closed testing release.

What's included:
• Full device security scan — checks installed apps, device settings, and security patches
• 29 detection rules covering stalkerware, banking trojans, and nation-state spyware (Pegasus, Predator, Graphite)
• Forensic Timeline — chronological view of all security events with severity filtering, correlation clustering, and export
• Deep Device Scan — analyze Android system diagnostics for hidden spyware indicators
• DNS monitoring — detect connections to known command-and-control servers via local VPN
• Runtime monitoring for accessibility service abuse, broadcast receiver interception, and permission usage
• App install/uninstall tracking in real-time
• Post-scan guidance with clear, risk-appropriate messaging
• Export reports as plaintext or MVT-compatible CSV
• Dynamic threat intelligence — detection databases update automatically from public feeds
• Zero data collection — no accounts, no analytics, no cloud, fully on-device

Known limitations:
• DNS monitoring requires manual VPN permission grant
• Some well-known apps may appear in informational-level findings
• Deep Device Scan requires Developer Options enabled to generate a system diagnostic
• Timeline correlation patterns may produce false clusters on devices with many apps

We welcome feedback from testers — please report issues at:
github.com/yasirhamza/AndroDR/issues
