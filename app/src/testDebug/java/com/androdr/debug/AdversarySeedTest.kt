package com.androdr.debug

import com.androdr.ioc.IndicatorResolver
import com.androdr.ioc.IocSanitizer
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The debug build's seed row for the adversary harness (`mercenary_cert_hash`, #424). The harness used to
 * write this row with `sqlite3` on the device, which retail-style images do not have; the debug receiver
 * now builds it here, so the row is type-checked against the entity and looks like a real feed row.
 */
class AdversarySeedTest {
    private val hash = "ab".repeat(32)

    @Test fun `a signing cert hash becomes a feed-like cert_hash indicator`() {
        val row = requireNotNull(AdversarySeed.certIndicator(hash, now = 42L))
        assertEquals(IndicatorResolver.TYPE_CERT_HASH, row.type)
        assertEquals(hash, row.value)
        assertEquals(AdversarySeed.SOURCE, row.source)
        assertEquals(42L, row.fetchedAt)
        assertEquals("CRITICAL", row.severity)
        assertTrue("a category the sanitizer keeps", row.category in IocSanitizer.CATEGORIES)
        assertEquals(row, IocSanitizer.sanitize(row))
    }

    @Test fun `upper case and colons from keytool are accepted and normalised`() {
        val keytool = hash.uppercase().chunked(2).joinToString(":")
        assertEquals(hash, AdversarySeed.certIndicator(keytool, now = 1L)?.value)
    }

    @Test fun `anything that is not a SHA-256 hash seeds nothing`() {
        for (bad in listOf(null, "", "abc", hash + "00", "zz".repeat(32), "$hash'; DROP TABLE indicators;--")) {
            assertNull(bad, AdversarySeed.certIndicator(bad, now = 1L))
        }
    }
}
