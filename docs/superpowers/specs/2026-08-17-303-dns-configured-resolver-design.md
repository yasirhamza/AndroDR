# #303 — DNS monitor: forward to the device's configured resolvers

**Date:** 2026-08-17
**Issue:** #303 — replace `DnsVpnService`'s hardcoded 8.8.8.8 upstream
**Status:** Implemented. Amended 2026-08-17 to as-built after the 4-agent
review ceremony — amendments are marked **[as-built]** inline; everything
unmarked is the originally approved design and was implemented as written.

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

- **API:** `start()`, `stop()`, and an observable current selection.
  **[as-built]** the flow is `StateFlow<UpstreamSelection?>`, not
  `StateFlow<List<InetAddress>>`: it carries the **winning network** together
  with its ordered resolvers, because the consumer's channel identity is
  `(network, address)` (see the `UpstreamResolver` amendment below). `null`
  replaces "empty list" as the "nothing known" signal.
- **Initial snapshot (synchronous, at VPN start):**
  `ConnectivityManager.getAllNetworks()` → keep networks whose capabilities
  include `NET_CAPABILITY_INTERNET` and `NET_CAPABILITY_NOT_VPN` → read
  `LinkProperties.dnsServers`. Snapshot rule: among matching networks,
  prefer one with `NET_CAPABILITY_VALIDATED` (first such wins); with none
  validated, first match wins. The callback supersedes the snapshot within
  milliseconds, so this choice only covers the start instant. No waiting on
  callbacks — there is no startup blind window. **[as-built]** the snapshot
  additionally skips networks whose `dnsServers` is empty, and it stays
  deliberately **lenient** (it accepts an unvalidated network when no
  validated one exists) so a monitor start during the brief pre-validation
  window after a network comes up is not blocked. An unvalidated network can
  therefore be the upstream only while no validated network exists at all,
  and only until the tracking callback fires.
- **Tracking:** `registerNetworkCallback` with a
  `NetworkRequest{INTERNET, NOT_VPN}`; `onLinkPropertiesChanged` and
  `onLost` update the list. **[as-built]** the request also requires
  `NET_CAPABILITY_VALIDATED`. `INTERNET` is a *declared* capability;
  `VALIDATED` is the one the OS sets after its own connectivity check and
  uses to choose the default network. Without it, a network Android had
  refused to use (captive portal, no-internet AP, an evil twin whose
  validation probe fails) still matched the callback and — being the most
  recent report — became the device's sole DNS upstream while the OS routed
  nothing over it. That is an interception capability the attacker does not
  have with the monitor off, so tracking is now validated-gated.
- **Selection rule (deterministic, documented):** among live matching
  networks, the most recently reported wins; within a network's resolver
  list, IPv4 entries order before IPv6; the head of the list is the active
  upstream. Multi-network edge cases are rare and self-heal on the next
  callback.
- **[as-built] IPv4-first is a deliberate override of the operator's order.**
  `orderResolvers` sorts IPv4 ahead of IPv6 regardless of the order the
  network advertised, so with head-only selection (below) AndroDR can pin the
  resolver the OS would have used *second*. Kept for v4 reachability and a
  simpler single-socket story; recorded here because it is a real deviation
  from "the same server Android would use", not an accident.
- Depends only on `ConnectivityManager` (`ACCESS_NETWORK_STATE` is already
  held). The selection logic is a pure function over snapshot data so it is
  unit-testable without Android.

### `UpstreamResolver` changes (inner class of `DnsVpnService`)

- Consumes the tracker instead of `UPSTREAM_DNS_HOST` (constant deleted).
- The shared upstream socket is **`connect()`ed** to the chosen resolver:
  off-path/spoofed responses are kernel-rejected, making the existing
  anti-spoof comment true instead of aspirational; unreachable resolvers
  fail fast with ICMP errors instead of silent timeouts.
- **[as-built] Honest anti-spoof posture.** `connect()` makes the kernel drop
  datagrams whose *source address/port* is not the resolver's — it filters
  off-path traffic; it does **not** stop an attacker who forges the
  resolver's source address. The residual guess is therefore the 16-bit
  transaction id, and that id is now drawn per query from `SecureRandom`
  (the previous scheme was a sequential counter, so one observed query
  revealed the whole future sequence on a single fixed source port). The
  code comments state exactly this instead of claiming spoof-proofing.
- **[as-built] Channel identity is `(network, address)`, and the socket is
  bound to that network.** `openChannel` checks `protect()`'s return value
  (fails closed on `false`) and calls `Network.bindSocket()` before
  `connect()`, so a resolver learned from network A can never be reached
  over network B — a wrong pairing errors instead of silently succeeding.
  The swap triggers on a change of **either** component: a connected UDP
  socket has its source address fixed at `connect()` time, so an AP roam or
  a new DHCP lease that keeps the same resolver address (`192.168.1.1` is
  near-universal) would otherwise leave the socket pinned to a source
  address that no longer exists — a silent device-wide DNS blackhole for the
  rest of the session.
- **On resolver change** (network switch): open + `protect()` + `connect()`
  a new socket, atomically swap, close the old one. In-flight queries on the
  old socket age out via the existing sweep — indistinguishable from a
  normal timeout. A new receive loop accompanies the new socket.
- **[as-built] Failed swaps retry with backoff.** The watcher uses
  `collectLatest` and retries a failed open at 1s → 2s → 4s (cap 5s) while
  the selection is still current; a newer selection cancels the loop. A
  `StateFlow` does not re-emit an equal value, so without this a single
  transient failure (common during a network transition) pinned the monitor
  to the previous — possibly hostile — resolver for the rest of the session.
- **[as-built] Lifecycle:** a `@Volatile stopped` flag is set before teardown
  and re-checked after swap-in, so an open that completes after `stop()`
  removes and closes the channel it just installed instead of leaking a
  socket and receive loop past teardown.
- `send()` with no usable socket (no known resolvers) **drops the query**
  with a rate-limited log — never a fallback resolver.

### Start and failure semantics

- `startVpn()` starts the tracker **before** `Builder().establish()`. If the
  initial snapshot yields no resolvers, startup **aborts** via the existing
  "upstream resolver failed to start" path (monitor off + log). Rationale:
  capturing device-wide DNS and black-holing it is strictly worse than the
  monitor not running. **[as-built]** the abort happens *before*
  `establish()`, so the tunnel is never created at all — stronger than the
  spec asked for.
- **[as-built] The first channel opens off the main thread, bounded.**
  `start()` is called from `onStartCommand` → `startVpn()` on the main
  thread, where `DatagramSocket`/`protect()`/`connect()` throw
  `NetworkOnMainThreadException`. The open runs on `Dispatchers.IO` and the
  main thread waits for it under a 3s cap (`CHANNEL_OPEN_TIMEOUT_MS`) so a
  contended `system_server` cannot hang the UI. The timeout frees the waiter
  but cannot cancel a blocking `protect()`/`connect()` already in flight —
  a late success is disarmed by the `stopped` flag above. Moving the whole
  start sequence onto `serviceScope` is deferred to a follow-up.
- Mid-session transient loss of resolvers (network switch gap): queries drop
  for the callback-latency window (milliseconds) and recover automatically.
- Resolver unreachable: queries time out exactly as today with a dead
  upstream. **[as-built] correction —** the original text here said "the
  device's DNS is equally dead without the monitor". That is **false**:
  Android's own resolver rotates across every server in
  `LinkProperties.dnsServers` with retry, so a network whose first resolver
  is down resolves fine with the monitor off. AndroDR v1 uses the **head of
  the list only**, so `resolvers[0]` being down means DNS is down while the
  monitor is on — the monitor becomes the visible cause of an outage it did
  not create. This is an accepted v1 simplification (one connected socket,
  and every failure direction still ends at "resolver down" rather than
  "queries sent somewhere the user didn't choose"); failover across the
  ordered list is deferred to a follow-up issue, naturally sequenced after
  the channel-health work.
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

**[as-built] The doc list above was incomplete.** Also updated in this PR:
`docs/ARCHITECTURE.md` (§7.1 + the module map — the repo's designated
architecture source of truth still described the 8.8.8.8 upstream), and
`cloudflare-worker.js`, which is the generated render of the privacy policy
(`python3 scripts/render_privacy.py docs/PRIVACY_POLICY.md
cloudflare-worker.js`) and is CI-gated by `check-privacy-sync`. The privacy
policy and the VpnService declaration additionally carry a **Private DNS**
qualification: the pre-existing claim that queries go "exactly as the OS would
send them without the VPN" is false for a user with Private DNS (DoT) enabled —
inside the monitor those queries are plaintext UDP/53 to the network's
configured resolvers. The downgrade is pre-existing (it was equally true of the
8.8.8.8 upstream) and is not addressed in code here; it is now stated honestly,
with the advice to leave the monitor off if strict Private DNS transport is
required.

## Process

Implementation via subagent-driven execution from a written plan; full
4-agent review ceremony (correctness, code-quality, architect,
code-security — the security reviewer prompted at the connect()/spoof
surface and the no-fallback guarantee). PR targets `main` with
`Closes #303`.
