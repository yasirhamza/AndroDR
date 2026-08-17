# #303 Configured-Resolver DNS Upstream Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** DnsVpnService forwards intercepted DNS queries to the device's own configured resolvers instead of hardcoded Google DNS (8.8.8.8), with no third-party fallback anywhere.

**Architecture:** A new `UnderlyingDnsTracker` answers "what are the device's real (non-VPN) resolvers right now" via a synchronous ConnectivityManager snapshot at VPN start plus a NetworkCallback for changes; its Android-free inner state machine (`ResolverState`) is JVM-unit-tested. `UpstreamResolver` consumes the tracker's StateFlow and keeps its single shared socket `connect()`ed to the current resolver (kernel-level anti-spoof, fast-fail on unreachable), swapping sockets on network change. No resolvers at start → the monitor aborts startup; transient loss mid-session → queries drop until the callback recovers.

**Tech Stack:** Kotlin, Android VpnService/ConnectivityManager, kotlinx.coroutines StateFlow, JUnit4 (plain JVM — the project has NO Robolectric, so anything unit-tested must not touch Android classes).

## Global Constraints

- Working directory for ALL commands: `/home/yasir/AndroDR/.claude/worktrees/phase2-from-trusted-store` (a git worktree — never cd to `/home/yasir/AndroDR`). Branch: `feat/303-dns-configured-resolver` (already created, tracks origin/main, spec committed at c83b9a3).
- Env block before any gradle/adb command:
  ```bash
  export JAVA_HOME=/home/yasir/Applications/android-studio/jbr
  export ANDROID_HOME=/home/yasir/Android/Sdk
  export PATH="$JAVA_HOME/bin:$ANDROID_HOME/platform-tools:$HOME/.local/bin:$PATH"
  ```
- Session sandbox rejects multiline `git commit -m` and compound/looped shell commands: write commit messages to a file under `.superpowers/sdd/` and use `git commit -F <file>`; run commands one at a time.
- **No Google fallback anywhere** (user decision): after Task 2 the strings `8.8.8.8` and `UPSTREAM_DNS_HOST` must not appear in `app/src/main/` at all. Failure directions are "monitor doesn't start" or "queries drop/time out" — never "queries rerouted to a resolver the user didn't configure".
- The listing/declaration/privacy-policy text updated in Task 3 describes app versions 0.9.0.612+; each edit carries a version-gating note because fielded builds (≤611) still use 8.8.8.8 and the user is resubmitting the Play console TODAY with the old (accurate) text.
- Spec: `docs/superpowers/specs/2026-08-17-303-dns-configured-resolver-design.md`. PR must close #303.
- Verification device: Samsung Fold 2 (SM-F916B) attached via USB; debug package `com.androdr.debug`.

---

### Task 1: `UnderlyingDnsTracker` with JVM-tested state machine

**Files:**
- Create: `app/src/main/java/com/androdr/network/UnderlyingDnsTracker.kt`
- Test: `app/src/test/java/com/androdr/network/UnderlyingDnsTrackerTest.kt`

**Interfaces:**
- Consumes: nothing (first task).
- Produces (Task 2 relies on these exact signatures):
  - `class UnderlyingDnsTracker(context: android.content.Context)` with `fun start()`, `fun stop()`, `val resolvers: kotlinx.coroutines.flow.StateFlow<List<java.net.InetAddress>>`
  - `internal class ResolverState` with `fun update(key: Any, dns: List<InetAddress>): List<InetAddress>`, `fun remove(key: Any): List<InetAddress>`, `fun current(): List<InetAddress>`
  - `internal fun orderResolvers(list: List<InetAddress>): List<InetAddress>` (top-level in the same file)

- [ ] **Step 1: Write the failing tests**

Create `app/src/test/java/com/androdr/network/UnderlyingDnsTrackerTest.kt`:

```kotlin
package com.androdr.network

import org.junit.Assert.assertEquals
import org.junit.Test
import java.net.InetAddress

/**
 * JVM tests for the Android-free core of UnderlyingDnsTracker (#303):
 * the ResolverState recency machine and orderResolvers. The Android wiring
 * (ConnectivityManager snapshot + NetworkCallback) is exercised on-device —
 * this project has no Robolectric, so nothing here may touch Android classes.
 */
class UnderlyingDnsTrackerTest {

    private val v4a: InetAddress = InetAddress.getByName("192.168.1.1")
    private val v4b: InetAddress = InetAddress.getByName("10.20.30.40")
    private val v6a: InetAddress = InetAddress.getByName("2001:4860:4860::8888")
    private val v6b: InetAddress = InetAddress.getByName("fd00::1")

    @Test
    fun `orderResolvers puts IPv4 first and is stable within family`() {
        assertEquals(
            listOf(v4a, v4b, v6a, v6b),
            orderResolvers(listOf(v6a, v4a, v6b, v4b))
        )
    }

    @Test
    fun `orderResolvers keeps IPv6-only list intact`() {
        assertEquals(listOf(v6a, v6b), orderResolvers(listOf(v6a, v6b)))
    }

    @Test
    fun `orderResolvers of empty is empty`() {
        assertEquals(emptyList<InetAddress>(), orderResolvers(emptyList()))
    }

    @Test
    fun `update publishes that network's resolvers ordered`() {
        val s = ResolverState()
        assertEquals(listOf(v4a, v6a), s.update("wifi", listOf(v6a, v4a)))
    }

    @Test
    fun `most recently updated live network wins`() {
        val s = ResolverState()
        s.update("wifi", listOf(v4a))
        assertEquals(listOf(v4b), s.update("cell", listOf(v4b)))
        // Re-reporting wifi makes it most recent again.
        assertEquals(listOf(v4a), s.update("wifi", listOf(v4a)))
    }

    @Test
    fun `losing the current network falls back to the remaining one`() {
        val s = ResolverState()
        s.update("wifi", listOf(v4a))
        s.update("cell", listOf(v4b))
        assertEquals(listOf(v4a), s.remove("cell"))
    }

    @Test
    fun `losing the last network yields empty`() {
        val s = ResolverState()
        s.update("wifi", listOf(v4a))
        assertEquals(emptyList<InetAddress>(), s.remove("wifi"))
    }

    @Test
    fun `update with empty dns list drops the key`() {
        val s = ResolverState()
        s.update("wifi", listOf(v4a))
        s.update("cell", listOf(v4b))
        // cell reports no resolvers anymore -> falls back to wifi
        assertEquals(listOf(v4a), s.update("cell", emptyList()))
    }
}
```

- [ ] **Step 2: Run the tests — verify they fail to compile (class doesn't exist)**

```bash
./gradlew testDebugUnitTest --tests 'com.androdr.network.UnderlyingDnsTrackerTest' 2>&1 | tail -8
```
Expected: compilation FAILURE (`unresolved reference: ResolverState` / `orderResolvers`).

- [ ] **Step 3: Write the implementation**

Create `app/src/main/java/com/androdr/network/UnderlyingDnsTracker.kt`:

```kotlin
package com.androdr.network

import android.content.Context
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.util.Log
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import java.net.Inet4Address
import java.net.InetAddress

/**
 * Orders a resolver list IPv4-first (stable within each family). The head of
 * the ordered list is the upstream [DnsVpnService.UpstreamResolver] connects to.
 */
internal fun orderResolvers(list: List<InetAddress>): List<InetAddress> =
    list.sortedBy { if (it is Inet4Address) 0 else 1 }

/**
 * Android-free recency machine behind [UnderlyingDnsTracker] (#303).
 *
 * Tracks the DNS server list of each live network (keyed by the [Network]
 * object at runtime; by any stable key in JVM tests). The MOST RECENTLY
 * updated live network wins — a deterministic rule that self-heals on the
 * next ConnectivityManager callback in the rare multi-network edge cases.
 */
internal class ResolverState {
    private val networks = LinkedHashMap<Any, List<InetAddress>>()

    @Synchronized
    fun update(key: Any, dns: List<InetAddress>): List<InetAddress> {
        networks.remove(key) // re-insert => most recent
        if (dns.isNotEmpty()) networks[key] = dns
        return current()
    }

    @Synchronized
    fun remove(key: Any): List<InetAddress> {
        networks.remove(key)
        return current()
    }

    @Synchronized
    fun current(): List<InetAddress> =
        orderResolvers(networks.entries.lastOrNull()?.value.orEmpty())
}

/**
 * Tracks the device's real (non-VPN) DNS resolvers for the DNS monitor (#303).
 *
 * [start] takes a synchronous snapshot of all networks with INTERNET+NOT_VPN
 * capabilities (preferring a VALIDATED one) so there is no startup blind
 * window, then registers a NetworkCallback to follow network changes.
 * [resolvers] is the ordered live list (IPv4 first); empty means "no known
 * non-VPN resolvers" — consumers must drop/abort rather than fall back to any
 * hardcoded resolver (no-Google-fallback guarantee).
 */
class UnderlyingDnsTracker(private val context: Context) {

    private val state = ResolverState()
    private val _resolvers = MutableStateFlow<List<InetAddress>>(emptyList())
    val resolvers: StateFlow<List<InetAddress>> = _resolvers

    private val cm: ConnectivityManager
        get() = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager

    private val callback = object : ConnectivityManager.NetworkCallback() {
        override fun onLinkPropertiesChanged(network: Network, linkProperties: LinkProperties) {
            _resolvers.value = state.update(network, linkProperties.dnsServers)
        }

        override fun onLost(network: Network) {
            _resolvers.value = state.remove(network)
        }
    }

    @Suppress("TooGenericExceptionCaught", "DEPRECATION")
    fun start() {
        // Synchronous snapshot first — no startup blind window. Snapshot rule
        // (spec): among INTERNET+NOT_VPN networks with resolvers, first
        // VALIDATED wins; with none validated, first match wins. The callback
        // supersedes this within milliseconds.
        try {
            var chosen: Pair<Network, List<InetAddress>>? = null
            var chosenValidated = false
            for (network in cm.allNetworks) {
                val caps = cm.getNetworkCapabilities(network) ?: continue
                if (!caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) continue
                if (!caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)) continue
                val dns = cm.getLinkProperties(network)?.dnsServers.orEmpty()
                if (dns.isEmpty()) continue
                val validated = caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)
                if (chosen == null || (validated && !chosenValidated)) {
                    chosen = network to dns
                    chosenValidated = validated
                }
                if (chosenValidated) break
            }
            chosen?.let { _resolvers.value = state.update(it.first, it.second) }
        } catch (e: Exception) {
            Log.w(TAG, "snapshot failed: ${e.message}")
        }

        val request = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
            .build()
        @Suppress("SwallowedException")
        try {
            cm.registerNetworkCallback(request, callback)
        } catch (e: Exception) {
            // Snapshot still stands; tracking just won't follow network changes.
            Log.w(TAG, "registerNetworkCallback failed: ${e.message}")
        }
    }

    fun stop() {
        @Suppress("TooGenericExceptionCaught", "SwallowedException")
        try {
            cm.unregisterNetworkCallback(callback)
        } catch (e: Exception) {
            // Not registered / already unregistered — nothing to do.
        }
        _resolvers.value = emptyList()
    }

    private companion object {
        const val TAG = "UnderlyingDnsTracker"
    }
}
```

- [ ] **Step 4: Run the tests — verify all 8 pass**

```bash
./gradlew testDebugUnitTest --tests 'com.androdr.network.UnderlyingDnsTrackerTest' 2>&1 | tail -5
```
Expected: BUILD SUCCESSFUL, 8/8 pass.

- [ ] **Step 5: Commit**

```bash
git add app/src/main/java/com/androdr/network/UnderlyingDnsTracker.kt app/src/test/java/com/androdr/network/UnderlyingDnsTrackerTest.kt
git commit -F <msgfile>   # "feat(dns): UnderlyingDnsTracker — non-VPN resolver tracking (#303)" + trailers
```

---

### Task 2: Rework `UpstreamResolver` + service wiring (no 8.8.8.8 anywhere)

**Files:**
- Modify: `app/src/main/java/com/androdr/network/DnsVpnService.kt` (companion constants ~84-85; fields ~131-132; `startVpn()` ~161-206; `stopVpn()` ~208-233; inner `UpstreamResolver` ~540-685)

**Interfaces:**
- Consumes: `UnderlyingDnsTracker(context)`, `.start()`, `.stop()`, `.resolvers: StateFlow<List<InetAddress>>` from Task 1.
- Produces: the final service behavior Tasks 4-5 verify. No API surface consumed by later code tasks.

- [ ] **Step 1: Delete the Google constant; add the tracker field**

In the companion object, DELETE both lines:

```kotlin
        // Upstream DNS resolver
        private const val UPSTREAM_DNS_HOST = "8.8.8.8"
        private const val UPSTREAM_DNS_PORT = 53
```

and add where they were:

```kotlin
        // Upstream DNS port (the resolver ADDRESS comes from UnderlyingDnsTracker — #303)
        private const val UPSTREAM_DNS_PORT = 53
```

Next to the `private var resolver: UpstreamResolver?` field (~line 132) add:

```kotlin
    private var dnsTracker: UnderlyingDnsTracker? = null
```

- [ ] **Step 2: Wire the tracker into `startVpn()`**

At the TOP of `startVpn()`, immediately after `if (isRunning.value) return`, insert:

```kotlin
        // #303: resolve the device's real DNS servers BEFORE establishing the
        // tunnel. No resolvers -> do not capture device DNS at all (a captured
        // tunnel with nowhere to forward would black-hole the whole device;
        // monitor-off is strictly better). There is NO hardcoded fallback.
        val tracker = UnderlyingDnsTracker(this).also { it.start() }
        if (tracker.resolvers.value.isEmpty()) {
            Log.w(TAG, "DnsVpnService: no non-VPN DNS resolvers available; not starting monitor")
            tracker.stop()
            stopSelf()
            return
        }
        dnsTracker = tracker
```

Then change the `UpstreamResolver` construction (currently `resolver = UpstreamResolver(serviceScope, this, outputStream, outputLock).also {`) to pass the flow:

```kotlin
        resolver = UpstreamResolver(serviceScope, this, outputStream, outputLock, tracker.resolvers).also {
            if (!it.start()) {
                Log.w(TAG, "DnsVpnService: upstream resolver failed to start; aborting")
                stopVpn()
                return
            }
        }
```

- [ ] **Step 3: Wire the tracker into `stopVpn()`**

Update the early-return guard (first line of `stopVpn()`) from

```kotlin
        if (!isRunning.value && tunFd == null && resolver == null && logBuffer == null) {
```

to

```kotlin
        if (!isRunning.value && tunFd == null && resolver == null &&
            logBuffer == null && dnsTracker == null
        ) {
```

and immediately after the `resolver?.stop(); resolver = null` pair add:

```kotlin
        dnsTracker?.stop()
        dnsTracker = null
```

- [ ] **Step 4: Rework the inner `UpstreamResolver`**

Replace the class header, state fields, `start()`, and `stop()` (keep `pending`, `txIdSeq`, the `Pending` class, `sweepLoop`, and `handleResponse` logic as-is except where shown):

```kotlin
    /**
     * Owns a single `protect()`'d, **`connect()`'d** [DatagramSocket] that all DNS
     * forwards share. Outgoing queries have their 16-bit DNS transaction id rewritten
     * to a unique value so the single receive loop can demux upstream replies and
     * route them back to the correct tun source.
     *
     * #303: the upstream address comes from [UnderlyingDnsTracker] (the device's own
     * configured resolvers) — never a hardcoded host. On resolver change the socket
     * is swapped atomically; in-flight queries on the old socket age out via the
     * sweep, indistinguishable from a normal timeout. If the resolver list goes
     * empty mid-session the last socket is kept (its sends fail like any dead
     * upstream) and recovery is automatic on the next tracker update. connect()
     * makes the kernel reject off-path datagrams, so spoofed responses never reach
     * [handleResponse].
     */
    private inner class UpstreamResolver(
        private val scope: CoroutineScope,
        private val vpnService: VpnService,
        private val outputStream: FileOutputStream,
        private val outputLock: Any,
        private val upstreams: kotlinx.coroutines.flow.StateFlow<List<InetAddress>>,
    ) {
        private inner class Channel(
            val socket: DatagramSocket,
            val addr: InetAddress,
            val receiveJob: Job,
        )

        private val channelRef = java.util.concurrent.atomic.AtomicReference<Channel?>(null)
        private val pending = ConcurrentHashMap<Int, Pending>()
        private val txIdSeq = AtomicInteger(1)
        private var sweepJob: Job? = null
        private var watchJob: Job? = null

        fun start(): Boolean {
            val initial = upstreams.value.firstOrNull()
            if (initial == null) {
                Log.w(TAG, "UpstreamResolver: no configured resolvers at start")
                return false
            }
            if (!openChannel(initial)) return false
            sweepJob = scope.launch { sweepLoop() }
            watchJob = scope.launch {
                upstreams.collect { list -> onUpstreamsChanged(list) }
            }
            return true
        }

        fun stop() {
            watchJob?.cancel(); watchJob = null
            sweepJob?.cancel();  sweepJob  = null
            channelRef.getAndSet(null)?.let { ch ->
                ch.receiveJob.cancel()
                try { ch.socket.close() } catch (_: Exception) {}
            }
            pending.clear()
        }

        private fun onUpstreamsChanged(list: List<InetAddress>) {
            val target = list.firstOrNull()
            val current = channelRef.get()
            when {
                // Empty list: keep the current channel — its sends fail like any
                // dead upstream and the next update heals it. NEVER a fallback host.
                target == null -> Log.w(TAG, "UpstreamResolver: resolver list empty; keeping last channel")
                current?.addr == target -> Unit
                else -> {
                    Log.i(TAG, "UpstreamResolver: switching upstream to $target")
                    openChannel(target)
                }
            }
        }

        /** Opens+protects+connects a socket to [addr], swaps it in, closes the old one. */
        @Suppress("TooGenericExceptionCaught")
        private fun openChannel(addr: InetAddress): Boolean {
            return try {
                val s = DatagramSocket()
                vpnService.protect(s)
                s.connect(addr, UPSTREAM_DNS_PORT)
                s.soTimeout = 0   // blocking; the receive loop runs on its own coroutine
                val job = scope.launch { receiveLoop(s) }
                channelRef.getAndSet(Channel(s, addr, job))?.let { old ->
                    old.receiveJob.cancel()
                    try { old.socket.close() } catch (_: Exception) {}
                }
                true
            } catch (e: Exception) {
                Log.w(TAG, "UpstreamResolver: channel open failed for $addr: ${e.message}")
                false
            }
        }
```

In `send(...)`, replace the socket/address usage. The first line `val s = socket ?: return` becomes:

```kotlin
            val ch = channelRef.get() ?: return
```

and the send block at the end (`val addr = upstreamAddr ?: return; try { s.send(DatagramPacket(rewritten, rewritten.size, addr, UPSTREAM_DNS_PORT)) }`) becomes (connected socket — no explicit address):

```kotlin
            try {
                ch.socket.send(DatagramPacket(rewritten, rewritten.size))
            } catch (e: Exception) {
                pending.remove(ourTxId)
                Log.w(TAG, "UpstreamResolver: send failed: ${e.message}")
            }
```

`receiveLoop` becomes parameterized on its socket (it must die with ITS socket, not a shared field):

```kotlin
        private suspend fun receiveLoop(s: DatagramSocket) {
            val recvBuf = ByteArray(MAX_DNS_PACKET_SIZE)
            while (scope.isActive && !s.isClosed) {
                @Suppress("TooGenericExceptionCaught", "SwallowedException")
                try {
                    val pkt = DatagramPacket(recvBuf, recvBuf.size)
                    s.receive(pkt)
                    handleResponse(recvBuf.copyOf(pkt.length))
                } catch (e: Exception) {
                    if (!scope.isActive || s.isClosed) break
                    Log.w(TAG, "UpstreamResolver: receive failed: ${e.message}")
                }
            }
        }
```

In `handleResponse`, the comment "Combined with the connect()'d upstream socket this rules out garbage / spoofs" is NOW TRUE — leave it, but only after confirming the connect() call above landed (this was aspirational before #303).

- [ ] **Step 5: Prove no Google remains, run the full gate**

```bash
grep -rn "8.8.8.8" app/src/main/ ; grep -rn "UPSTREAM_DNS_HOST" app/src/
```
Expected: both greps EMPTY (exit 1).

```bash
./gradlew testDebugUnitTest lintDebug 2>&1 | tail -8
```
Expected: BUILD SUCCESSFUL, full suite + lint green (including the 8 Task-1 tests).

- [ ] **Step 6: Commit**

```bash
git add app/src/main/java/com/androdr/network/DnsVpnService.kt
git commit -F <msgfile>   # "feat(dns): forward to configured resolvers via connected socket (#303)" + trailers
```

---

### Task 3: Documentation — privacy policy, listing copy, declaration doc

**Files:**
- Modify: `docs/PRIVACY_POLICY.md:94`
- Modify: `docs/play-store/20-store-listing.md` ("About the optional VPN" paragraph)
- Modify: `docs/play-store/17-vpn-permission-declaration.md` (technical details + form answers + AR snippet)

**Interfaces:**
- Consumes: nothing from code tasks (text-only).
- Produces: the copy the user pastes into the Play console when 0.9.0.612 rolls out.

- [ ] **Step 1: Privacy policy**

Replace the sentence at `docs/PRIVACY_POLICY.md:94` beginning "- Allowed queries are forwarded to a public DNS resolver (Google Public DNS, 8.8.8.8)..." with:

```markdown
- Allowed queries are forwarded to your device's own configured DNS resolvers — the same servers Android itself uses (app versions 0.9.0.612 and later; earlier versions forwarded to Google Public DNS, 8.8.8.8) — over standard DNS (UDP port 53) and the answers are returned to your apps. This is the same unencrypted DNS protocol Android uses by default when Private DNS is off: your resolver sees the domain names your apps look up, exactly as it would without AndroDR. AndroDR attaches no device identifiers or app information to these queries
```

- [ ] **Step 2: Listing copy**

In `docs/play-store/20-store-listing.md`, in the "About the optional VPN" paragraph, replace the sentence

> DNS queries are checked against threat databases on your device and forwarded to Google Public DNS (8.8.8.8) for normal resolution; blocked malicious domains are logged to the forensic timeline on your phone.

with

> DNS queries are checked against threat databases on your device and forwarded to your device's own configured DNS servers for normal resolution; blocked malicious domains are logged to the forensic timeline on your phone.

and add directly under the paragraph an HTML comment:

```markdown
<!-- Console note: paste this version only when 0.9.0.612+ is the live build.
     Versions <=611 use Google Public DNS (8.8.8.8) — the currently-submitted
     console text describes those accurately. -->
```

- [ ] **Step 3: Declaration doc**

In `docs/play-store/17-vpn-permission-declaration.md`:

1. Add at the very top, under the H1:

```markdown
> **Version gating:** the text below describes app versions **0.9.0.612+**
> (configured-resolver upstream, #303). The console declaration submitted
> 2026-08-17 used the 8.8.8.8 wording, which stays accurate for builds <=611.
> Re-paste the updated blocks below on the first console touch after 612 is live.
```

2. Replace `Key technical details` bullet 1 ("**Only DNS packets pass through the VPN.** ... forwarded to an upstream DNS resolver (Google Public DNS, 8.8.8.8) for resolution.") with:

```markdown
- **Only DNS packets pass through the VPN.** DNS queries are inspected locally for threat domains, then forwarded to the device's own configured DNS resolvers (the same servers Android itself uses) for resolution.
```

3. Replace `What the DNS monitor does` item 5 (the 8.8.8.8/`UPSTREAM_DNS_HOST` bullet) with:

```markdown
5. Forwards all other DNS queries unchanged to the device's configured DNS
   resolvers, discovered via ConnectivityManager (`UnderlyingDnsTracker`);
   there is no hardcoded fallback resolver
```

4. In the paste-ready console answers section, replace in the free-text block "and all other queries are forwarded unchanged to Google Public DNS (8.8.8.8)." with "and all other queries are forwarded unchanged to the device's own configured DNS resolvers (no hardcoded resolver anywhere)." and in the encryption answer replace "DNS queries are forwarded to a public resolver (8.8.8.8) exactly as the operating system would send them without the VPN." with "DNS queries are forwarded to the device's own configured resolvers exactly as the operating system would send them without the VPN."

5. In the Arabic snippet, replace "ثم تُمرَّر إلى خادم Google Public DNS ‏(8.8.8.8) للاستجابة المعتادة" with "ثم تُمرَّر إلى خوادم DNS المهيأة على جهازك نفسه للاستجابة المعتادة".

- [ ] **Step 4: Verify no stray 8.8.8.8 remains outside version-gated context, commit**

```bash
grep -rn "8.8.8.8" docs/ | grep -v "earlier versions" | grep -v "<=611" | grep -v "Versions <=611"
```
Expected: no hits outside historical/spec/plan context (spec + plans may mention it historically — those are fine; the three live-copy docs must only carry it in the version-gated notes).

```bash
git add docs/PRIVACY_POLICY.md docs/play-store/20-store-listing.md docs/play-store/17-vpn-permission-declaration.md
git commit -F <msgfile>   # "docs(dns): resolver copy for privacy policy + Play listing/declaration, 612-gated (#303)" + trailers
```

---

### Task 4: On-device verification — Fold 2

**Files:** none modified; produces evidence only.

**Interfaces:**
- Consumes: the built app from Tasks 1-2.
- Produces: pass/fail evidence for spec scenarios 1-4 — gate for Tasks 5-6.

- [ ] **Step 1: Install and start the monitor on Wi-Fi**

```bash
./gradlew installDebug
```

Launch AndroDR debug on the Fold 2 (screenshot-guided: `adb exec-out screencap -p > <scratchpad>/shot.png`, Read the PNG, `adb shell input tap X Y`; coordinates from your own screenshot). Navigate to the **Network** tab → enable the DNS monitor (accept the system VPN consent dialog if it appears — tap OK). Confirm the key notification: `adb shell dumpsys notification | grep -i androdr | head -5` shows the VPN foreground notification.

- [ ] **Step 2: Scenario 1 — resolution works on Wi-Fi, upstream = Wi-Fi resolver**

```bash
adb shell dumpsys connectivity | grep -i "dns" | head -8    # note the Wi-Fi network's DNS servers
adb logcat -d -s DnsVpnService UnderlyingDnsTracker | tail -20
```

Open Chrome on the device, load any site (e.g. example.com). PASS when: pages resolve/load with the monitor ON, and logcat shows no "channel open failed"; the switching/initial upstream (if logged) equals one of the Wi-Fi network's DNS servers from dumpsys — NOT 8.8.8.8 (unless the Wi-Fi actually uses it).

- [ ] **Step 3: Scenario 2 — mid-session Wi-Fi → mobile data switch**

```bash
adb shell svc wifi disable
```
Wait ~5s, reload a page in Chrome (new domain, e.g. wikipedia.org). Then:
```bash
adb logcat -d -s DnsVpnService | grep -i "switching upstream" | tail -3
adb shell svc wifi enable
```
PASS when: the page resolves on mobile data, and logcat shows `switching upstream to <mobile resolver>` after the switch (and back after re-enable).

- [ ] **Step 4: Scenario 3 — airplane-mode start aborts cleanly**

Stop the monitor in the app UI. Then:
```bash
adb shell cmd connectivity airplane-mode enable
```
Try to start the monitor from the app UI. PASS when: the monitor does NOT enter the running state (UI toggle returns to off / no VPN key icon), and `adb logcat -d -s DnsVpnService | tail -5` shows "no non-VPN DNS resolvers available; not starting monitor". Then:
```bash
adb shell cmd connectivity airplane-mode disable
```
Re-start the monitor once network is back — it must start normally (recovery check). Leave the device with the monitor OFF and airplane mode OFF at the end.

- [ ] **Step 5: Scenario 4 — connected socket evidence**

```bash
adb shell ss -u -n -p | grep -i androdr | head -5
```
PASS when: the app's UDP socket shows a CONNECTED peer `<resolver>:53` (ss shows a peer address for connected UDP sockets; an unconnected socket shows `*:*`). Alternative evidence if `ss` output is unhelpful on this build: `adb shell dumpsys netstats detail | grep -A2 androdr` or accept code-review confirmation of the `connect()` call plus Scenario-2 behavior.

Write all command outputs into the task report. DNS events sanity: pull the debug Room DB (with `-wal`) or check the app's Network tab shows fresh DNS events during the scenarios.

---

### Task 5: 4-agent review ceremony

**Files:** none unless findings require fixes.

**Interfaces:**
- Consumes: branch diff (merge-base origin/main..HEAD) + spec + Task 4 evidence.
- Produces: consolidated verdict; fixes committed + re-gated. Gate for Task 6.

- [ ] **Step 1: Dispatch four parallel reviewers** (single message), each with the spec path, the branch diff file, the Task-4 report path, and one mandate:

1. **Correctness:** tracker state machine vs its tests; socket-swap lifecycle (receive loop bound to ITS socket; no leaked sockets/jobs; pending entries across swaps); startVpn ordering (tracker before establish; abort path leaves no foreground service/fd); stopVpn symmetry.
2. **Code quality:** file organization, naming, comment accuracy (especially the now-true connect() anti-spoof comment), test quality, no dead code (UPSTREAM_DNS_HOST fully gone).
3. **Architect:** boundary of UnderlyingDnsTracker (Android-free core honored), spec conformance section by section, doc version-gating coherence with the Play resubmission timeline, no scope creep.
4. **Code security (attack it):** can any path still leak queries to a non-configured resolver? Race between establish() and tracker where VPN's own virtual DNS (10.0.0.1) or the VPN network's LinkProperties could enter the tracker (NOT_VPN capability must exclude it — verify); connect()-swap races (datagrams to a closed socket, responses routed after swap); spoofing with the connected socket; whether the empty-list-keep-last-channel rule can be abused; airplane-abort DoS surface (can a hostile network make the monitor unstartable?).

- [ ] **Step 2: Consolidate; fix Critical/Important via the fix loop; re-run `./gradlew testDebugUnitTest lintDebug`; if the FIX changed runtime behavior, repeat the affected Task-4 scenario before proceeding.**

---

### Task 6: PR and merge

**Files:** none.

- [ ] **Step 1: Push and open the PR**

```bash
git push -u origin feat/303-dns-configured-resolver
gh pr create --base main --head feat/303-dns-configured-resolver \
  --title "feat(dns): forward DNS to the device's configured resolvers (#303)" \
  --body-file <bodyfile>
```

Body file content:

```markdown
The DNS monitor now forwards intercepted queries to the device's own configured resolvers instead of hardcoded Google DNS (8.8.8.8) — with NO third-party fallback anywhere: no resolvers at start aborts monitor startup (never black-holing device DNS), transient loss mid-session drops queries for the callback-latency window.

- New `UnderlyingDnsTracker`: synchronous non-VPN network snapshot + NetworkCallback tracking; Android-free `ResolverState` core is JVM-unit-tested (8 tests).
- `UpstreamResolver`: single shared socket now `connect()`ed to the current resolver (kernel-level off-path rejection — the anti-spoof comment is finally true), atomic socket swap on network change; in-flight queries age out via the existing sweep.
- Docs: privacy policy, listing copy, and declaration doc updated to the configured-resolver wording, version-gated to 0.9.0.612+ (the console keeps the 8.8.8.8 text until 612 is live — it accurately describes fielded builds).

Verified on-device (SM-F916B): resolution on Wi-Fi with upstream = Wi-Fi resolver; mid-session Wi-Fi→mobile-data switch with logged upstream swap; airplane-mode start aborts cleanly and recovers; connected-socket evidence. Full 4-agent ceremony passed.

Ships in 0.9.0.612+.

Closes #303

🤖 Generated with [Claude Code](https://claude.com/claude-code)

https://claude.ai/code/session_01NahFvjzP3RaHfJAYhbWMDa
```

(Adjust the body's verification/ceremony sentences to match what Tasks 4-5 actually produced — never claim an unrun check.)

- [ ] **Step 2: Wait for CI, merge**

```bash
gh pr checks --watch      # build-and-test must be green; submodule-check unaffected (no submodule change)
gh pr merge --squash --delete-branch=false
```

- [ ] **Step 3: Report** — fix is in main; ships with the next release cut (612+). Remind the user: the Play console copy update (listing + declaration) is a user-side paste that happens when 612 rolls out, per the version-gating notes in the docs.

---

## Self-review notes (completed)

- Spec coverage: tracker+snapshot rule (T1), connect()ed socket+swap+no-fallback (T2), abort-at-start & drop-mid-session (T2 steps 2/4), docs incl. privacy policy (T3), all four on-device scenarios (T4), ceremony w/ security mandates from spec (T5), rollout/Closes #303 (T6). Gap check: none found.
- Placeholders: `<msgfile>`/`<bodyfile>` are commit-message/body files the executor writes with the quoted content + standard trailers (sandbox requires -F); the body content is given verbatim. No TBDs.
- Type consistency: `UnderlyingDnsTracker(context: Context)/start()/stop()/resolvers: StateFlow<List<InetAddress>>` and `ResolverState.update/remove/current`, `orderResolvers` used identically in T1 code, T1 tests, and T2 wiring. `UpstreamResolver` ctor arity matches its T2 construction site.
