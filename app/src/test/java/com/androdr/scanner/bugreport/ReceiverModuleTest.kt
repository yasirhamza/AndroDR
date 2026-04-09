package com.androdr.scanner.bugreport

import com.androdr.ioc.IndicatorResolver
import com.androdr.ioc.OemPrefixResolver
import io.mockk.every
import io.mockk.mockk
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

class ReceiverModuleTest {

    private val mockIndicatorResolver: IndicatorResolver = mockk()
    private lateinit var module: ReceiverModule

    @Before
    fun setUp() {
        every { mockIndicatorResolver.isKnownBadPackage(any()) } returns null
        val oemPrefixResolver: OemPrefixResolver = mockk()
        every { oemPrefixResolver.isOemPrefix(any()) } answers {
            val pkg = firstArg<String>()
            pkg.startsWith("com.android.") ||
                pkg.startsWith("com.google.android.") ||
                pkg.startsWith("com.samsung.android.") ||
                pkg.startsWith("com.sec.android.") ||
                pkg.startsWith("com.qualcomm.") ||
                pkg.startsWith("com.mediatek.")
        }
        module = ReceiverModule(oemPrefixResolver)
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

        val result = module.analyze(section, mockIndicatorResolver)
        assertTrue(result.telemetry.any {
            it["package_name"] == "com.evil.sms" &&
                it["intent_action"] == "android.provider.Telephony.SMS_RECEIVED" &&
                it["is_system_app"] == false
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

        val result = module.analyze(section, mockIndicatorResolver)
        assertTrue(result.telemetry.any {
            it["package_name"] == "com.spy.calls" &&
                it["intent_action"] == "android.intent.action.PHONE_STATE"
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

        val result = module.analyze(section, mockIndicatorResolver)
        assertTrue(result.telemetry.all { it["is_system_app"] == true })
    }

    @Test
    fun `flags IOC-matched receiver in telemetry`() = runBlocking {
        val iocInfo = com.androdr.ioc.BadPackageInfo(
            packageName = "com.stalker.app",
            name = "StalkerApp",
            category = "STALKERWARE",
            severity = "CRITICAL",
            description = "Known stalkerware"
        )
        every { mockIndicatorResolver.isKnownBadPackage("com.stalker.app") } returns iocInfo

        val section = """
            Receiver Resolver Table:
              Non-Data Actions:
                  android.provider.Telephony.SMS_RECEIVED:
                    12345 com.stalker.app/.SmsInterceptor filter abcdef
                      Action: "android.provider.Telephony.SMS_RECEIVED"
        """.trimIndent()

        val result = module.analyze(section, mockIndicatorResolver)
        assertTrue(result.telemetry.any {
            it["package_name"] == "com.stalker.app" &&
                it["is_system_app"] == false
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

            val result = module.analyze(section, mockIndicatorResolver)
            assertTrue("Expected detection for $intent",
                result.telemetry.any { it["intent_action"] == intent })
        }
    }

    @Test
    fun `empty section produces no telemetry`() = runBlocking {
        val result = module.analyze("", mockIndicatorResolver)
        assertTrue(result.telemetry.isEmpty())
    }
}
