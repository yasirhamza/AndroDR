package com.androdr.scanner.bugreport

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

    @Test
    fun `parses both packages with first and last install times`() {
        val mod = InstallTimeModule()
        val events = mod.parseSection(sample)
        assertEquals(2, events.size)
        assertEquals("com.example.foo", events[0].packageName)
        assertEquals("package_install", events[0].category)
        assertTrue(events[0].startTimestamp > 0)
    }

    @Test
    fun `package with only firstInstallTime still emits a row`() {
        val text = """
            Package [com.x] (z):
              firstInstallTime=2024-01-01 00:00:00
        """.trimIndent()
        val events = InstallTimeModule().parseSection(text)
        assertEquals(1, events.size)
    }

    @Test
    fun `malformed timestamp is skipped, not exception`() {
        val text = """
            Package [com.x] (z):
              firstInstallTime=GARBAGE
              lastUpdateTime=ALSO BROKEN
        """.trimIndent()
        val events = InstallTimeModule().parseSection(text)
        assertTrue(events.isEmpty())
    }

    @Test
    fun `package missing both times produces no row`() {
        val text = """
            Package [com.empty] (a):
              versionName=1
        """.trimIndent()
        assertTrue(InstallTimeModule().parseSection(text).isEmpty())
    }
}
