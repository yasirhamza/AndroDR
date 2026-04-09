package com.androdr.scanner.bugreport

import com.androdr.ioc.IndicatorResolver
import io.mockk.every
import io.mockk.mockk
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

class DbInfoModuleTest {

    private val mockIndicatorResolver: IndicatorResolver = mockk()
    private lateinit var module: DbInfoModule

    @Before
    fun setUp() {
        every { mockIndicatorResolver.isKnownBadPackage(any()) } returns null
        module = DbInfoModule()
    }

    @Test
    fun `targetSections is dbinfo`() {
        assertEquals(listOf("dbinfo"), module.targetSections)
    }

    @Test
    fun `detects database connection pool`() = runBlocking {
        val section = """
            Connection pool for /data/user/0/com.evil.spy/databases/data.db:
              Pool size: 1
              Most recently executed SQL:
                0: SELECT * FROM contacts
                1: SELECT * FROM sms
        """.trimIndent()

        val result = module.analyze(section, mockIndicatorResolver, com.androdr.ioc.DeviceIdentity.UNKNOWN)
        assertTrue(result.telemetry.any {
            it["package_name"] == "com.evil.spy" &&
                it["recent_query_count"] == 2
        })
    }

    @Test
    fun `emits telemetry for sensitive db path without hardcoded filter`() = runBlocking {
        // is_sensitive_db field removed — hardcoded path list deleted. SIGMA
        // rules (plan 6) match on db_path themselves.
        val section = """
            Connection pool for /data/user/0/com.android.providers.contacts/databases/contacts2.db:
              Pool size: 1
        """.trimIndent()

        val result = module.analyze(section, mockIndicatorResolver, com.androdr.ioc.DeviceIdentity.UNKNOWN)
        assertTrue(result.telemetry.any {
            (it["db_path"] as String).endsWith("contacts2.db")
        })
    }

    @Test
    fun `empty section produces no telemetry`() = runBlocking {
        val result = module.analyze("", mockIndicatorResolver, com.androdr.ioc.DeviceIdentity.UNKNOWN)
        assertTrue(result.telemetry.isEmpty())
    }
}
