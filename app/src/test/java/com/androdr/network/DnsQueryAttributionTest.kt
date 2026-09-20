package com.androdr.network

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test
import java.net.InetSocketAddress

/**
 * From the raw packet the VPN reads off the tunnel to the socket tuple Android
 * needs: the app's side is the packet's SOURCE address and port, the resolver's
 * side is its DESTINATION. Getting either end backwards makes every lookup miss
 * silently, so the exact tuple is pinned. Also pins the user-facing label for
 * the uids that have no package.
 */
class DnsQueryAttributionTest {

    /** A minimal IPv4 + UDP packet: 20-byte IP header, 8-byte UDP header, DNS payload. */
    private fun ipv4Udp(src: String, srcPort: Int, dst: String, dstPort: Int, protocol: Int = 17): ByteArray {
        val ip = ByteArray(20)
        ip[0] = 0x45.toByte()                       // version 4, IHL 5
        ip[9] = protocol.toByte()
        src.split('.').map { it.toInt().toByte() }.forEachIndexed { i, b -> ip[12 + i] = b }
        dst.split('.').map { it.toInt().toByte() }.forEachIndexed { i, b -> ip[16 + i] = b }
        val udp = ByteArray(8)
        udp[0] = (srcPort shr 8).toByte(); udp[1] = srcPort.toByte()
        udp[2] = (dstPort shr 8).toByte(); udp[3] = dstPort.toByte()
        val dns = ByteArray(16)                      // header + a little; content irrelevant here
        return ip + udp + dns
    }

    private class RecordingResolver(private val answer: ConnectionOwnerResolver.Owner) :
        ConnectionOwnerResolver(sockets = null, packages = { emptyList() }) {
        var seen: Triple<Int, InetSocketAddress, InetSocketAddress>? = null
        override fun resolve(protocol: Int, local: InetSocketAddress, remote: InetSocketAddress): Owner {
            seen = Triple(protocol, local, remote)
            return answer
        }
    }

    @Test
    fun `asks who owns the app-side socket of the query`() {
        val resolver = RecordingResolver(ConnectionOwnerResolver.Owner(10042, "com.instagram.android"))
        val packet = ipv4Udp(src = "10.0.0.2", srcPort = 41234, dst = "10.0.0.1", dstPort = 53)

        val owner = DnsQueryAttribution.ownerOf(packet, resolver)

        assertEquals(
            Triple(
                ConnectionOwnerResolver.IPPROTO_UDP,
                InetSocketAddress("10.0.0.2", 41234),
                InetSocketAddress("10.0.0.1", 53),
            ),
            resolver.seen,
        )
        assertEquals("com.instagram.android", owner.packageName)
    }

    @Test
    fun `a non-UDP packet is not looked up`() {
        val resolver = RecordingResolver(ConnectionOwnerResolver.Owner(10042, "com.example"))
        val packet = ipv4Udp(src = "10.0.0.2", srcPort = 41234, dst = "10.0.0.1", dstPort = 53, protocol = 6)

        val owner = DnsQueryAttribution.ownerOf(packet, resolver)

        assertNull(resolver.seen)
        assertEquals(ConnectionOwnerResolver.UNKNOWN_UID, owner.uid)
    }

    @Test
    fun `a non-IPv4 packet is not looked up`() {
        val resolver = RecordingResolver(ConnectionOwnerResolver.Owner(10042, "com.example"))
        val packet = ipv4Udp("10.0.0.2", 41234, "10.0.0.1", 53).also { it[0] = 0x60.toByte() }

        val owner = DnsQueryAttribution.ownerOf(packet, resolver)

        assertNull(resolver.seen)
        assertEquals(ConnectionOwnerResolver.UNKNOWN_UID, owner.uid)
    }

    @Test
    fun `labels name the app when known, the system resolver when it is netd, and unknown otherwise`() {
        val names = mapOf("com.instagram.android" to "Instagram")

        assertEquals(
            "Instagram (com.instagram.android)",
            DnsQueryAttribution.label(10042, "com.instagram.android", names),
        )
        assertEquals("com.instagram.android", DnsQueryAttribution.label(10042, "com.instagram.android"))
        assertEquals("system resolver", DnsQueryAttribution.label(ConnectionOwnerResolver.DNS_RESOLVER_UID, null))
        assertEquals("system", DnsQueryAttribution.label(1000, null))
        assertEquals("root", DnsQueryAttribution.label(0, null))
        assertEquals("unknown", DnsQueryAttribution.label(ConnectionOwnerResolver.UNKNOWN_UID, null))
        assertEquals("uid:10555", DnsQueryAttribution.label(10555, null))
    }
}
