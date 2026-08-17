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
