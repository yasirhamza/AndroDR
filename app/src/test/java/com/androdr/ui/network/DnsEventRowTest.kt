package com.androdr.ui.network

import com.androdr.data.model.DnsEvent
import com.androdr.network.ConnectionOwnerResolver
import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * What the Network Monitor prints under each domain.
 *
 * The screen used to call the label helper with no display names, so a row
 * read `com.android.chrome` while the report for the same event read
 * `Chrome (com.android.chrome)`. Two surfaces, one event, two answers. The
 * row text is built here, outside the composable, so that disagreement is a
 * failing test rather than something only a person looking at the screen
 * would catch.
 */
class DnsEventRowTest {

    private fun event(domain: String, uid: Int, pkg: String?, at: Long = 1_000L) =
        DnsEvent(timestamp = at, domain = domain, appUid = uid, appName = pkg, isBlocked = false, reason = null)

    @Test
    fun `a named app reads as its name with the package, exactly as the report writes it`() {
        val rows = dnsEventRows(
            listOf(event("www.google.com", 10162, "com.android.chrome")),
            mapOf("com.android.chrome" to "Chrome"),
        )

        assertEquals("Chrome (com.android.chrome)", rows.single().appLabel)
    }

    @Test
    fun `an app with no known name keeps its package`() {
        val rows = dnsEventRows(listOf(event("a.example", 10042, "com.obscure.app")), emptyMap())

        assertEquals("com.obscure.app", rows.single().appLabel)
    }

    @Test
    fun `an event the platform would not attribute reads unknown, not a raw uid`() {
        val rows = dnsEventRows(
            listOf(event("a.example", ConnectionOwnerResolver.UNKNOWN_UID, null)),
            emptyMap(),
        )

        assertEquals("unknown", rows.single().appLabel)
    }

    @Test
    fun `the system resolver is named for what it is`() {
        val rows = dnsEventRows(
            listOf(event("a.example", ConnectionOwnerResolver.DNS_RESOLVER_UID, null)),
            emptyMap(),
        )

        assertEquals("system resolver", rows.single().appLabel)
    }

    @Test
    fun `rows keep their events and their order`() {
        val first = event("first.example", 10001, "com.a", at = 3_000L)
        val second = event("second.example", 10002, "com.b", at = 2_000L)

        val rows = dnsEventRows(listOf(first, second), mapOf("com.a" to "A", "com.b" to "B"))

        assertEquals(listOf(first, second), rows.map { it.event })
    }

    @Test
    fun `the packages needing a name are collected without duplicates`() {
        val events = listOf(
            event("a.example", 10001, "com.a"),
            event("b.example", 10001, "com.a"),
            event("c.example", ConnectionOwnerResolver.UNKNOWN_UID, null),
            event("d.example", 10002, "com.b"),
        )

        assertEquals(setOf("com.a", "com.b"), packagesNeedingLabels(events))
    }
}
