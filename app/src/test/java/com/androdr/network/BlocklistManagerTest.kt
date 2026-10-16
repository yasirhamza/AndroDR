package com.androdr.network

import com.androdr.ioc.BundledDomainDatabase
import io.mockk.every
import io.mockk.mockk
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class BlocklistManagerTest {
    private val db = mockk<BundledDomainDatabase> {
        every { blockedDomains() } returns setOf("evil.example")
    }
    private val manager = BlocklistManager(db)

    @Test
    fun `blocks only the default-blocked set and its subdomains`() {
        assertTrue(manager.isBlocked("evil.example"))
        assertTrue(manager.isBlocked("c2.Evil.Example."))
        assertFalse("attribution-only domain blocked", manager.isBlocked("attribution-only.example"))
        assertEquals(1, manager.blockedCount())
    }
}
