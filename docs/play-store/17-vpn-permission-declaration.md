# VPN Service Permission Declaration

> **Version gating:** the text below describes app versions **0.9.0.615+**
> (configured-resolver upstream, #303). The console declaration submitted
> 2026-08-17 used the 8.8.8.8 wording, which stays accurate for builds <=614.
> Re-paste the updated blocks below once a build 0.9.0.615 or later is live on Play (the 0.9.0.616 upload qualifies).

## Permission requested
`android.permission.BIND_VPN_SERVICE`

## How the VPN is used
AndroDR uses Android's VpnService API to create a **local-only DNS monitor** that intercepts DNS queries on the device. This is used to detect connections to known command-and-control (C2) servers, malware domains, and threat intelligence indicators.

## Key technical details
- **Only DNS packets pass through the VPN.** DNS queries are inspected locally for threat domains, then forwarded to the device's own configured DNS resolvers (the same servers Android itself uses) for resolution.
- **No proxy or remote server is involved for user traffic.** Only DNS resolution traffic is forwarded; all other network traffic bypasses the VPN entirely.
- **No user data is added to DNS queries.** Only the standard DNS query payload (domain name) is forwarded — no device identifiers, app information, or tracking data.
- **The VPN is optional.** Users must explicitly enable it and accept the Android VPN permission prompt. The app functions fully without the VPN enabled (app scanning, device audit, bugreport analysis all work without it).

## What the DNS monitor does
1. Inspects the domain name in each DNS query
2. Compares against threat intelligence domain databases (CISA, MVT indicators, ThreatFox, HaGeZi TIF)
3. Optionally blocks queries to known malicious domains (returns NXDOMAIN)
4. Logs matched domains to the forensic timeline for security analysis
5. Forwards all other DNS queries unchanged to the device's configured DNS
   resolvers, discovered via ConnectivityManager (`UnderlyingDnsTracker`);
   there is no hardcoded fallback resolver

## Why a VPN is necessary
Android does not provide a public API for monitoring DNS queries at the application level. The VpnService API is the only mechanism available to non-root apps for inspecting network-layer DNS traffic. This is the same approach used by DNS-based security apps (NextDNS, Blokada, AdGuard) and recommended by Android security documentation for on-device network monitoring.

## Data handling
- DNS query logs are stored locally in an encrypted Room database
- Logs are automatically pruned after 30 days
- No DNS data is transmitted to external servers
- Users can export DNS logs for their own analysis

## Play Console "VPN service" declaration — paste-ready answers (2026-08)

Rejection 2026-08-17 ("Missing or Incomplete Declaration") — the form must be
completed in FULL at Play Console → Policy → App content → VPN service, and the
store listing must document the VPN (done: Privacy section of the full
description, see `20-store-listing.md`).

**Use case / exception category:** Device security app (VpnService is required
for one security feature — on-device DNS threat monitoring — not for tunneling
user traffic).

**Description of VpnService use (free-text field):**

> AndroDR is an open-source device-security (mobile EDR) app. It uses
> VpnService solely to implement an optional, local-only DNS security monitor.
> The VPN routes ONLY DNS traffic (a single /32 route to an on-device virtual
> resolver); no other traffic enters the VPN. Each DNS query is inspected
> on-device against threat-intelligence databases (command-and-control servers,
> stalkerware and malware domains); matches can be blocked by returning
> NXDOMAIN, and all other queries are forwarded unchanged to the device's own configured DNS resolvers (no hardcoded resolver anywhere). There is no remote VPN server: the tunnel terminates inside the
> app on the device. No user data, identifiers, or browsing traffic is
> collected, transmitted, or monetized; DNS logs are stored locally (encrypted
> database, 30-day retention) and never leave the device. The VPN is opt-in via
> the Android system consent dialog, and the app is fully functional without
> it. This use matches the policy's device-security exception. VPN use is
> documented in the store listing (Privacy section) and the privacy policy.

**Encryption question ("data encrypted from device to VPN tunnel endpoint"):**

> The VPN tunnel terminates on the device inside the app — there is no remote
> tunnel endpoint and no data is transmitted from the device to any VPN
> server, so there is no device-to-endpoint link to encrypt. DNS queries are
> forwarded to the device's own configured resolvers exactly as the operating
> system would send them without the VPN — with one exception: if the user has
> enabled Android's Private DNS (DNS-over-TLS), queries are sent in plaintext
> UDP/53 to those configured resolvers while the monitor is on, rather than
> encrypted to the Private DNS server; users who need strict Private DNS
> transport should leave the optional monitor off.

**Store-listing sentence (Arabic listing — add to the privacy section):**

> حول خدمة VPN الاختيارية: تستخدم أداة مراقبة الشبكة خدمة VpnService في
> أندرويد لفحص استعلامات DNS على جهازك. تعمل هذه الخدمة محليًا بالكامل: فهي لا
> تنشئ أي نفق إلى خادم خارجي، ولا تمرر سوى حركة DNS، ولا تنقل بيانات تصفحك
> أبدًا. تُفحص استعلامات DNS على الجهاز مقابل قواعد بيانات التهديدات، ثم
> تُمرَّر إلى خوادم DNS المهيأة على جهازك نفسه للاستجابة المعتادة، وتُسجَّل
> النطاقات الخبيثة المحظورة في الخط الزمني الجنائي على هاتفك. خدمة VPN
> اختيارية — وتعمل بقية الميزات كلها بدونها.

And the DNS-activity bullet (Arabic):

> • نشاط DNS — أداة مراقبة اختيارية للشبكة تستخدم خدمة VPN في أندرويد لإنشاء
> مرشّح DNS محلي يكتشف الاتصالات بخوادم القيادة والتحكم المعروفة ويحظرها
