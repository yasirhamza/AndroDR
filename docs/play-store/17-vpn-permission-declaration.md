# VPN Service Permission Declaration

## Permission requested
`android.permission.BIND_VPN_SERVICE`

## How the VPN is used
AndroDR uses Android's VpnService API to create a **local-only DNS monitor** that intercepts DNS queries on the device. This is used to detect connections to known command-and-control (C2) servers, malware domains, and threat intelligence indicators.

## Key technical details
- **No traffic leaves the device through AndroDR's VPN tunnel.** All DNS queries are resolved using the device's original DNS servers.
- **No proxy or remote server is involved.** The VPN runs entirely on-device.
- **No user traffic is modified, stored, or forwarded.** Only DNS query domain names are inspected.
- **The VPN is optional.** Users must explicitly enable it and accept the Android VPN permission prompt. The app functions fully without the VPN enabled (app scanning, device audit, bugreport analysis all work without it).

## What the DNS monitor does
1. Inspects the domain name in each DNS query
2. Compares against threat intelligence domain databases (CISA, MVT indicators, ThreatFox, HaGeZi TIF)
3. Optionally blocks queries to known malicious domains (returns NXDOMAIN)
4. Logs matched domains to the forensic timeline for security analysis
5. Forwards all other DNS queries to the device's configured DNS servers unchanged

## Why a VPN is necessary
Android does not provide a public API for monitoring DNS queries at the application level. The VpnService API is the only mechanism available to non-root apps for inspecting network-layer DNS traffic. This is the same approach used by DNS-based security apps (NextDNS, Blokada, AdGuard) and recommended by Android security documentation for on-device network monitoring.

## Data handling
- DNS query logs are stored locally in an encrypted Room database
- Logs are automatically pruned after 30 days
- No DNS data is transmitted to external servers
- Users can export DNS logs for their own analysis
