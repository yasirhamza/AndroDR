package com.androdr.network

import java.net.InetAddress
import java.net.InetSocketAddress

/**
 * From the raw packet the VPN read off the tunnel to the app that sent it, and
 * from a (uid, package) pair to the words a person sees.
 *
 * The app's side of the socket is the packet's SOURCE address and port; the
 * resolver's side is its DESTINATION. Only IPv4/UDP is attributed, which is all
 * the tunnel carries (it routes the DNS server alone).
 */
object DnsQueryAttribution {

    private const val IPV4 = 4
    private const val IPV4_HEADER_MIN = 20
    private const val UDP_HEADER = 8
    private const val PROTOCOL_OFFSET = 9
    private const val SRC_ADDR_OFFSET = 12
    private const val DST_ADDR_OFFSET = 16
    private const val ROOT_UID = 0
    private const val SYSTEM_UID = 1000

    fun ownerOf(packet: ByteArray, resolver: ConnectionOwnerResolver): ConnectionOwnerResolver.Owner {
        val tuple = udpTuple(packet)
        return if (tuple == null) {
            ConnectionOwnerResolver.Owner.UNKNOWN
        } else {
            resolver.resolve(ConnectionOwnerResolver.IPPROTO_UDP, tuple.first, tuple.second)
        }
    }

    /** (app side, resolver side) of an IPv4/UDP packet, or null if it is not one. */
    private fun udpTuple(packet: ByteArray): Pair<InetSocketAddress, InetSocketAddress>? {
        val versionAndIhl = if (packet.size >= IPV4_HEADER_MIN) packet[0].toInt() and 0xFF else 0
        val ihl = (versionAndIhl and 0x0F) * 4
        val isIpv4Udp = versionAndIhl shr 4 == IPV4 &&
            packet.size >= ihl + UDP_HEADER &&
            (packet[PROTOCOL_OFFSET].toInt() and 0xFF) == ConnectionOwnerResolver.IPPROTO_UDP
        return if (!isIpv4Udp) {
            null
        } else {
            Pair(
                InetSocketAddress(address(packet, SRC_ADDR_OFFSET), port(packet, ihl)),
                InetSocketAddress(address(packet, DST_ADDR_OFFSET), port(packet, ihl + 2)),
            )
        }
    }

    private fun address(packet: ByteArray, at: Int): InetAddress =
        InetAddress.getByAddress(packet.copyOfRange(at, at + 4))

    private fun port(packet: ByteArray, at: Int): Int =
        ((packet[at].toInt() and 0xFF) shl 8) or (packet[at + 1].toInt() and 0xFF)

    /**
     * What the report and the Network Monitor screen print after `<-`. A known
     * package is shown by its display name when one is available; the uids that
     * have no package are named for what they are, never "unknown".
     */
    fun label(uid: Int, packageName: String?, displayNames: Map<String, String> = emptyMap()): String {
        if (packageName != null) {
            return displayNames[packageName]?.let { "$it ($packageName)" } ?: packageName
        }
        return when (uid) {
            ConnectionOwnerResolver.UNKNOWN_UID -> "unknown"
            ConnectionOwnerResolver.DNS_RESOLVER_UID -> "system resolver"
            ROOT_UID -> "root"
            SYSTEM_UID -> "system"
            else -> "uid:$uid"
        }
    }
}
