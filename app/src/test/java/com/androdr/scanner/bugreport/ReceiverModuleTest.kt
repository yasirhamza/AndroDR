package com.androdr.scanner.bugreport

import com.androdr.ioc.IocResolver
import io.mockk.every
import io.mockk.mockk
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

class ReceiverModuleTest {

    private val mockIocResolver: IocResolver = mockk()
    private lateinit var module: ReceiverModule

    @Before
    fun setUp() {
        every { mockIocResolver.isKnownBadPackage(any()) } returns null
        module = ReceiverModule()
    }

    @Test
    fun `targetSections is package`() {
        assertEquals(listOf("package"), module.targetSections)
    }

    @Test
    fun `detects non-system SMS_RECEIVED receiver`() = runBlocking {
        val section = """
            Receiver Resolver Table:
              Non-Data Actions:
                  android.provider.Telephony.SMS_RECEIVED:
                    12345 com.evil.sms/.SmsReceiver filter abcdef
                      Action: "android.provider.Telephony.SMS_RECEIVED"
        """.trimIndent()

        val result = module.analyze(section, mockIocResolver)
        assertTrue(result.findings.any {
            it.category == "ReceiverAbuse" &&
                it.description.contains("com.evil.sms") &&
                it.description.contains("SMS_RECEIVED")
        })
    }

    @Test
    fun `detects PHONE_STATE receiver`() = runBlocking {
        val section = """
            Receiver Resolver Table:
              Non-Data Actions:
                  android.intent.action.PHONE_STATE:
                    12345 com.spy.calls/.CallReceiver filter abcdef
                      Action: "android.intent.action.PHONE_STATE"
        """.trimIndent()

        val result = module.analyze(section, mockIocResolver)
        assertTrue(result.findings.any {
            it.category == "ReceiverAbuse" &&
                it.description.contains("com.spy.calls")
        })
    }

    @Test
    fun `ignores system package receivers`() = runBlocking {
        val section = """
            Receiver Resolver Table:
              Non-Data Actions:
                  android.provider.Telephony.SMS_RECEIVED:
                    1000 com.android.phone/.SmsReceiver filter abcdef
                      Action: "android.provider.Telephony.SMS_RECEIVED"
                    1000 com.google.android.gms/.SmsReceiver filter abcdef
                      Action: "android.provider.Telephony.SMS_RECEIVED"
        """.trimIndent()

        val result = module.analyze(section, mockIocResolver)
        assertTrue(result.findings.isEmpty())
    }

    @Test
    fun `flags IOC-matched receiver as CRITICAL`() = runBlocking {
        val iocInfo = com.androdr.ioc.BadPackageInfo(
            packageName = "com.stalker.app",
            name = "StalkerApp",
            category = "STALKERWARE",
            severity = "CRITICAL",
            description = "Known stalkerware"
        )
        every { mockIocResolver.isKnownBadPackage("com.stalker.app") } returns iocInfo

        val section = """
            Receiver Resolver Table:
              Non-Data Actions:
                  android.provider.Telephony.SMS_RECEIVED:
                    12345 com.stalker.app/.SmsInterceptor filter abcdef
                      Action: "android.provider.Telephony.SMS_RECEIVED"
        """.trimIndent()

        val result = module.analyze(section, mockIocResolver)
        assertTrue(result.findings.any {
            it.severity == "CRITICAL" && it.description.contains("StalkerApp")
        })
    }

    @Test
    fun `detects all 5 sensitive intents`() = runBlocking {
        val intents = listOf(
            "android.provider.Telephony.SMS_RECEIVED",
            "android.provider.Telephony.NEW_OUTGOING_SMS",
            "android.intent.action.DATA_SMS_RECEIVED",
            "android.intent.action.PHONE_STATE",
            "android.intent.action.NEW_OUTGOING_CALL"
        )
        for (intent in intents) {
            val section = """
                Receiver Resolver Table:
                  Non-Data Actions:
                      $intent:
                        12345 com.evil.app/.Receiver filter abcdef
                          Action: "$intent"
            """.trimIndent()

            val result = module.analyze(section, mockIocResolver)
            assertTrue("Expected detection for $intent",
                result.findings.any { it.category == "ReceiverAbuse" })
        }
    }

    @Test
    fun `empty section produces no findings`() = runBlocking {
        val result = module.analyze("", mockIocResolver)
        assertTrue(result.findings.isEmpty())
    }
}
