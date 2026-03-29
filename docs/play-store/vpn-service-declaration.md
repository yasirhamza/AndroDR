# VPN Service Permission Declaration

## For Google Play Console: VPN Permission Declaration Form

### How does your app use VpnService?

AndroDR uses Android's VpnService API to create a **local-only DNS monitor** that intercepts DNS queries on the device. This is used to detect connections to known command-and-control (C2) servers associated with spyware, stalkerware, and malware.

### Technical implementation

- The VPN creates a TUN interface that routes **only DNS traffic** (port 53 to a local address 10.0.0.1)
- **No user traffic is routed through the VPN** — web browsing, app data, and all non-DNS traffic flows normally through the device's standard network path
- DNS queries are checked against a blocklist of known malicious domains (C2 servers, spyware infrastructure)
- Matching queries can be blocked (NXDOMAIN response) or logged (detect-only mode) based on user preference
- All processing happens **entirely on-device** — no DNS queries are forwarded to external servers controlled by the developer
- The upstream DNS resolver is the device's configured DNS (or 8.8.8.8 as fallback)

### What the VPN does NOT do

- Does NOT route, inspect, modify, or log non-DNS traffic
- Does NOT tunnel traffic to any remote server
- Does NOT collect browsing history, URLs, or web content
- Does NOT transmit any network data to the developer or third parties
- Does NOT function as a traditional VPN (no remote endpoint)

### Why VpnService instead of alternative approaches?

Android does not provide a public API for monitoring DNS queries at the application level. VpnService is the only mechanism available to unprivileged (non-root) apps for DNS interception. This approach is used by other security and privacy apps on Google Play (e.g., DNS-based ad blockers, parental controls).

### User control

- DNS monitoring is **opt-in** — it requires the user to explicitly accept the VPN permission prompt
- The user can enable/disable DNS monitoring at any time via a toggle in the app
- The VPN can be stopped at any time from Android's system settings
- The VPN status is clearly indicated in the Android notification bar

### Category

**Security / threat detection** — the VPN is used exclusively for on-device DNS-based threat detection, not for tunneling, privacy, or network modification purposes.
