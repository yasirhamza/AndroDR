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
