package com.androdr.scanner.bugreport

import com.androdr.data.model.PackageHistoryEventType
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class InstallTimeModuleTest {

    private val sample = """
        Package [com.example.foo] (ab12cd):
          versionName=1.0
          firstInstallTime=2024-03-15 14:23:01
          lastUpdateTime=2024-03-20 09:11:45
        Package [com.example.bar] (ef34gh):
          firstInstallTime=2025-01-02 08:00:00
          lastUpdateTime=2025-01-02 08:00:00
    """.trimIndent()

    /** The INSTALL records (the retired `package_install` rows' successors, C3). */
    private fun installs(text: String) = InstallTimeModule().parseHistory(text, capturedAt = 1L)
        .filter { it.eventType == PackageHistoryEventType.INSTALL }

    @Test
    fun `parses both packages with first and last install times`() {
        val events = installs(sample)
        assertEquals(2, events.size)
        assertEquals("com.example.foo", events[0].packageName)
        assertTrue(events[0].timestamp > 0)
        val update = InstallTimeModule().parseHistory(sample, 1L)
            .single { it.eventType == PackageHistoryEventType.UPDATE }
        assertEquals("only foo was updated after its install", "com.example.foo", update.packageName)
    }

    @Test
    fun `package with only firstInstallTime still emits a record`() {
        val text = """
            Package [com.x] (z):
              firstInstallTime=2024-01-01 00:00:00
        """.trimIndent()
        assertEquals(1, installs(text).size)
    }

    @Test
    fun `malformed timestamp is skipped, not exception`() {
        val text = """
            Package [com.x] (z):
              firstInstallTime=GARBAGE
              lastUpdateTime=ALSO BROKEN
        """.trimIndent()
        assertTrue(InstallTimeModule().parseHistory(text, 1L).isEmpty())
    }

    @Test
    fun `package missing both times produces no record`() {
        val text = """
            Package [com.empty] (a):
              versionName=1
        """.trimIndent()
        assertTrue(InstallTimeModule().parseHistory(text, 1L).isEmpty())
    }
}
