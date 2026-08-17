# #303 — DNS monitor: forward to the device's configured resolvers

**Date:** 2026-08-17
**Issue:** #303 — replace `DnsVpnService`'s hardcoded 8.8.8.8 upstream
**Status:** Approved design, pre-implementation

## Problem

`DnsVpnService` intercepts all device DNS via a local VPN and forwards every
query to a hardcoded Google Public DNS upstream
(`UPSTREAM_DNS_HOST = "8.8.8.8"`). Two problems:

1. **Privacy coherence.** The listing says "no data leaves your device," yet
   the monitor reroutes every DNS query on the device to a third-party
   resolver the user did not choose. Surfaced during the Play VpnService
   declaration work (2026-08-17 rejection remediation).
2. **Behavior change under the monitor.** With the VPN on, the device stops
   using its own resolvers (carrier, router, Private-DNS-adjacent setups) —
   split-horizon names served by local resolvers break.

Also in scope, because it lives in the exact code being changed: the
`UpstreamResolver.handleResponse` comment claims a "connect()'d upstream
socket" rules out spoofed responses, but `start()` never calls `connect()` —
the socket is open to off-path traffic filtered only by the 16-bit txId.

## Decisions (user-approved)

- **Never contact Google.** No 8.8.8.8 fallback anywhere; the constant is
  deleted. If resolvers cannot be determined, the monitor degrades toward
  "monitor off" or "queries drop," never "queries rerouted to a third party."
- **Play sequencing:** the console resubmission (VpnService declaration +
  listing) proceeds NOW with the 8.8.8.8 text — it accurately describes every
  build users can currently install. The listing/declaration copy updates to
  "your device's configured DNS servers" with the release that ships this
  change (612+). EN + AR snippets are prepared with that release.

## Design

### New unit: `UnderlyingDnsTracker`
`app/src/main/java/com/androdr/network/UnderlyingDnsTracker.kt`

One responsibility: answer "what are the device's real (non-VPN) DNS
resolvers right now?"

- **API:** `start()`, `stop()`, and an observable current resolver list
  (`StateFlow<List<InetAddress>>`, ordered).
- **Initial snapshot (synchronous, at VPN start):**
  `ConnectivityManager.getAllNetworks()` → keep networks whose capabilities
  include `NET_CAPABILITY_INTERNET` and `NET_CAPABILITY_NOT_VPN` → read
  `LinkProperties.dnsServers`. Snapshot rule: among matching networks,
  prefer one with `NET_CAPABILITY_VALIDATED` (first such wins); with none
  validated, first match wins. The callback supersedes the snapshot within
  milliseconds, so this choice only covers the start instant. No waiting on
  callbacks — there is no startup blind window.
- **Tracking:** `registerNetworkCallback` with a
  `NetworkRequest{INTERNET, NOT_VPN}`; `onLinkPropertiesChanged` and
  `onLost` update the list.
- **Selection rule (deterministic, documented):** among live matching
  networks, the most recently reported wins; within a network's resolver
  list, IPv4 entries order before IPv6; the head of the list is the active
  upstream. Multi-network edge cases are rare and self-heal on the next
  callback.
- Depends only on `ConnectivityManager` (`ACCESS_NETWORK_STATE` is already
  held). The selection logic is a pure function over snapshot data so it is
  unit-testable without Android.

### `UpstreamResolver` changes (inner class of `DnsVpnService`)

- Consumes the tracker instead of `UPSTREAM_DNS_HOST` (constant deleted).
- The shared upstream socket is **`connect()`ed** to the chosen resolver:
  off-path/spoofed responses are kernel-rejected, making the existing
  anti-spoof comment true instead of aspirational; unreachable resolvers
  fail fast with ICMP errors instead of silent timeouts.
- **On resolver change** (network switch): open + `protect()` + `connect()`
  a new socket, atomically swap, close the old one. In-flight queries on the
  old socket age out via the existing sweep — indistinguishable from a
  normal timeout. A new receive loop accompanies the new socket.
- `send()` with no usable socket (no known resolvers) **drops the query**
  with a rate-limited log — never a fallback resolver.

### Start and failure semantics

- `startVpn()` starts the tracker **before** `Builder().establish()`. If the
  initial snapshot yields no resolvers, startup **aborts** via the existing
  "upstream resolver failed to start" path (monitor off + log). Rationale:
  capturing device-wide DNS and black-holing it is strictly worse than the
  monitor not running.
- Mid-session transient loss of resolvers (network switch gap): queries drop
  for the callback-latency window (milliseconds) and recover automatically.
- Resolver unreachable: queries time out exactly as today with a dead
  upstream — the device's DNS is equally dead without the monitor.
- Every failure direction ends at "DNS behaves as if the resolver is down,"
  never "queries silently sent to a party the user didn't configure."

### Explicitly unchanged

Tun packet handling, DNS txId rewrite/demux, blocklist and detection logic,
DNS event logging, `UPSTREAM_PENDING_CAP`/sweep, VPN Builder routes
(`addRoute(DNS_SERVER_IP, 32)`, `addDisallowedApplication(packageName)`),
and the transport: plaintext UDP/53, exactly as today — but now to the same
resolver the OS itself would use. DoT/DoH support is out of scope (future
issue if wanted).

## Testing

- **Unit:** resolver-selection pure function — multi-network snapshots,
  IPv6-only network, empty snapshot, ordering (IPv4 first), network-lost
  transitions.
- **Unit (JVM-feasible parts):** socket-swap sequencing hooks where the
  harness allows without Android framework classes.
- **On-device (Fold 2, authoritative):**
  1. Monitor on → browse on Wi-Fi → resolution works, DNS events log, and
     logcat shows the chosen upstream equals the Wi-Fi network's resolver.
  2. Switch Wi-Fi → mobile data mid-session → resolution continues after the
     swap; upstream follows the new network.
  3. Airplane mode → attempt monitor start → clean abort (monitor off), not
     dead DNS.
  4. Spoof-comment verification: confirm the socket is connected
     (`ss`/logcat evidence or code inspection in review).

## Rollout

Ships in the next app release (612+). No rules-repo/feed involvement. With
that release: update `docs/play-store/20-store-listing.md` ("About the
optional VPN" paragraph) and `docs/play-store/17-vpn-permission-declaration.md`
to say queries are forwarded to the device's own configured DNS servers
(EN + AR), and the user pastes the updated copy into the console with the
release rollout. `docs/PRIVACY_POLICY.md` is checked for 8.8.8.8 mentions and
updated in the same PR if any exist.

## Process

Implementation via subagent-driven execution from a written plan; full
4-agent review ceremony (correctness, code-quality, architect,
code-security — the security reviewer prompted at the connect()/spoof
surface and the no-fallback guarantee). PR targets `main` with
`Closes #303`.
