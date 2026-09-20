package com.androdr.network

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test
import java.net.InetSocketAddress

/**
 * Who is behind a socket. The VPN sees a DNS query as an IPv4/UDP packet with a
 * source port; Android (API 29+) will tell the active VPN which uid owns that
 * socket, and the package manager maps the uid to a package. Everything the
 * resolver decides -- caching, unknowns, system uids, shared uids, failures -- is
 * pinned here against fakes of those two system services.
 */
class ConnectionOwnerResolverTest {

    private val local = InetSocketAddress("10.0.0.2", 41234)
    private val remote = InetSocketAddress("10.0.0.1", 53)

    private class FakePackages(private val table: Map<Int, List<String>>) : UidPackageLookup {
        var calls = 0
        override fun packagesForUid(uid: Int): List<String> {
            calls++
            return table[uid].orEmpty()
        }
    }

    @Test
    fun `resolves the owning package of a socket`() {
        val resolver = ConnectionOwnerResolver(
            sockets = { _, _, _ -> 10042 },
            packages = FakePackages(mapOf(10042 to listOf("com.instagram.android"))),
        )

        val owner = resolver.resolve(ConnectionOwnerResolver.IPPROTO_UDP, local, remote)

        assertEquals(10042, owner.uid)
        assertEquals("com.instagram.android", owner.packageName)
    }

    @Test
    fun `an unknown socket is unknown, not a guess`() {
        val packages = FakePackages(emptyMap())
        val resolver = ConnectionOwnerResolver(
            sockets = { _, _, _ -> ConnectionOwnerResolver.UNKNOWN_UID },
            packages = packages,
        )

        val owner = resolver.resolve(ConnectionOwnerResolver.IPPROTO_UDP, local, remote)

        assertEquals(ConnectionOwnerResolver.UNKNOWN_UID, owner.uid)
        assertNull(owner.packageName)
        assertEquals("no package lookup for an unknown uid", 0, packages.calls)
    }

    @Test
    fun `the system resolver daemon keeps its uid and has no package`() {
        // netd performs DNS on apps' behalf; when the kernel reports its uid the
        // event must say so, not "unknown" and not some app.
        val resolver = ConnectionOwnerResolver(
            sockets = { _, _, _ -> ConnectionOwnerResolver.DNS_RESOLVER_UID },
            packages = FakePackages(emptyMap()),
        )

        val owner = resolver.resolve(ConnectionOwnerResolver.IPPROTO_UDP, local, remote)

        assertEquals(ConnectionOwnerResolver.DNS_RESOLVER_UID, owner.uid)
        assertNull(owner.packageName)
    }

    @Test
    fun `a shared uid resolves to its first package in sorted order, deterministically`() {
        val resolver = ConnectionOwnerResolver(
            sockets = { _, _, _ -> 10099 },
            packages = FakePackages(mapOf(10099 to listOf("com.samsung.android.b", "com.samsung.android.a"))),
        )

        val owner = resolver.resolve(ConnectionOwnerResolver.IPPROTO_UDP, local, remote)

        assertEquals("com.samsung.android.a", owner.packageName)
    }

    @Test
    fun `uid to package is cached so the package manager is asked once per uid`() {
        val packages = FakePackages(mapOf(10042 to listOf("com.instagram.android")))
        val resolver = ConnectionOwnerResolver(sockets = { _, _, _ -> 10042 }, packages = packages)

        repeat(5) { resolver.resolve(ConnectionOwnerResolver.IPPROTO_UDP, local, remote) }

        assertEquals(1, packages.calls)
    }

    @Test
    fun `a failing socket lookup degrades to unknown instead of crashing the VPN`() {
        val resolver = ConnectionOwnerResolver(
            sockets = { _, _, _ -> throw SecurityException("not the active VPN") },
            packages = FakePackages(emptyMap()),
        )

        val owner = resolver.resolve(ConnectionOwnerResolver.IPPROTO_UDP, local, remote)

        assertEquals(ConnectionOwnerResolver.UNKNOWN_UID, owner.uid)
        assertNull(owner.packageName)
    }

    @Test
    fun `no socket lookup available means unknown`() {
        // Below API 29 the platform offers nothing; the resolver is built without one.
        val resolver = ConnectionOwnerResolver(sockets = null, packages = FakePackages(emptyMap()))

        val owner = resolver.resolve(ConnectionOwnerResolver.IPPROTO_UDP, local, remote)

        assertEquals(ConnectionOwnerResolver.UNKNOWN_UID, owner.uid)
    }

    @Test
    fun `the lookup receives exactly the tuple it was given`() {
        var seen: Triple<Int, InetSocketAddress, InetSocketAddress>? = null
        val resolver = ConnectionOwnerResolver(
            sockets = { p, l, r -> seen = Triple(p, l, r); 10042 },
            packages = FakePackages(mapOf(10042 to listOf("com.example"))),
        )

        resolver.resolve(ConnectionOwnerResolver.IPPROTO_UDP, local, remote)

        assertEquals(Triple(ConnectionOwnerResolver.IPPROTO_UDP, local, remote), seen)
    }
}
