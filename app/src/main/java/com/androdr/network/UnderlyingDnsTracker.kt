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
 * The winning network **and** its ordered resolvers (#303).
 *
 * The upstream channel's identity is `(network, resolver address)`, not the
 * address alone: the same address (`192.168.1.1` is near-universal) on a
 * different network is a different upstream, and a connected UDP socket pins
 * its source address at `connect()` time, so a network change with an
 * unchanged resolver address must still force a reopen.
 *
 * [networkKey] is the `android.net.Network` at runtime (value-based
 * equals/hashCode on netId); any stable key in JVM tests.
 */
data class UpstreamSelection(val networkKey: Any, val resolvers: List<InetAddress>)

/**
 * Android-free recency machine behind [UnderlyingDnsTracker] (#303).
 *
 * Tracks the DNS server list of each live network (keyed by the [Network]
 * object at runtime; by any stable key in JVM tests). The MOST RECENTLY
 * updated live network wins — a deterministic rule that self-heals on the
 * next ConnectivityManager callback in the rare multi-network edge cases.
 * Only networks the OS has VALIDATED ever reach this machine via the tracking
 * callback (see [UnderlyingDnsTracker.start]).
 */
internal class ResolverState {
    private val networks = LinkedHashMap<Any, List<InetAddress>>()

    @Synchronized
    fun update(key: Any, dns: List<InetAddress>): UpstreamSelection? {
        networks.remove(key) // re-insert => most recent
        if (dns.isNotEmpty()) networks[key] = dns
        return current()
    }

    @Synchronized
    fun remove(key: Any): UpstreamSelection? {
        networks.remove(key)
        return current()
    }

    /** The winning `(network, ordered resolvers)`, or null when nothing is tracked. */
    @Synchronized
    fun current(): UpstreamSelection? =
        networks.entries.lastOrNull()?.let { UpstreamSelection(it.key, orderResolvers(it.value)) }
}

/**
 * Tracks the device's real (non-VPN) DNS resolvers for the DNS monitor (#303).
 *
 * [start] takes a synchronous snapshot of all networks with INTERNET+NOT_VPN
 * capabilities (preferring a VALIDATED one) so there is no startup blind
 * window, then registers a NetworkCallback — restricted to **VALIDATED**
 * networks — to follow network changes.
 * [selection] is the winning `(network, ordered resolvers)` pair; null means
 * "no known non-VPN resolvers" — consumers must drop/abort rather than fall
 * back to any hardcoded resolver (no-Google-fallback guarantee).
 */
class UnderlyingDnsTracker(private val context: Context) {

    private val state = ResolverState()
    private val _selection = MutableStateFlow<UpstreamSelection?>(null)
    val selection: StateFlow<UpstreamSelection?> = _selection

    private val cm: ConnectivityManager
        get() = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager

    private val callback = object : ConnectivityManager.NetworkCallback() {
        override fun onLinkPropertiesChanged(network: Network, linkProperties: LinkProperties) {
            _selection.value = state.update(network, linkProperties.dnsServers)
        }

        override fun onLost(network: Network) {
            _selection.value = state.remove(network)
        }
    }

    @Suppress("TooGenericExceptionCaught", "DEPRECATION", "LoopWithTooManyJumpStatements")
    fun start() {
        // Synchronous snapshot first — no startup blind window. Snapshot rule
        // (spec): among INTERNET+NOT_VPN networks with resolvers, first
        // VALIDATED wins; with none validated, first match wins. The snapshot
        // stays deliberately lenient (accept an unvalidated network when NO
        // validated one exists) so monitor start is not blocked during the
        // brief pre-validation window right after a network comes up; the
        // VALIDATED-only tracking callback below supersedes an unvalidated
        // snapshot choice within seconds. An unvalidated network can therefore
        // be the upstream only while no validated network exists at all.
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
            chosen?.let { _selection.value = state.update(it.first, it.second) }
        } catch (e: Exception) {
            Log.w(TAG, "snapshot failed: ${e.message}")
        }

        // VALIDATED is the capability the OS sets after its own connectivity
        // check and the one ConnectivityService uses to pick the default
        // network; INTERNET is merely *declared*. Requiring VALIDATED here
        // keeps a network the OS has rejected (captive portal, no-internet AP,
        // evil twin failing validation) out of tracking entirely — it can
        // never become the device's sole DNS upstream (#303 security C1).
        val request = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
            .addCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)
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
        _selection.value = null
    }

    private companion object {
        const val TAG = "UnderlyingDnsTracker"
    }
}
