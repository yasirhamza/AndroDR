package com.androdr.scanner.bugreport

import com.androdr.ioc.DeviceIdentity
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
        every { oemPrefixResolver.isOemPrefix(any(), any()) } answers {
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

        val result = module.analyze(section, mockIndicatorResolver, DeviceIdentity.UNKNOWN)
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

        val result = module.analyze(section, mockIndicatorResolver, DeviceIdentity.UNKNOWN)
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

        val result = module.analyze(section, mockIndicatorResolver, DeviceIdentity.UNKNOWN)
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

        val result = module.analyze(section, mockIndicatorResolver, DeviceIdentity.UNKNOWN)
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

            val result = module.analyze(section, mockIndicatorResolver, DeviceIdentity.UNKNOWN)
            assertTrue("Expected detection for $intent",
                result.telemetry.any { it["intent_action"] == intent })
        }
    }

    @Test
    fun `does not attribute receivers from a following non-enumerated intent`() = runBlocking {
        // SMS_RECEIVED sorts last among the enumerated actions, so its block
        // previously ran to the safety cap and swept in receivers belonging to
        // later, non-enumerated intent groups (e.g. androidx.work's
        // DiagnosticsReceiver under androidx.work.diagnostics.*).
        val section = """
            Receiver Resolver Table:
              Non-Data Actions:
                  android.provider.Telephony.SMS_RECEIVED:
                    12345 com.evil.sms/.SmsReceiver filter abcdef
                      Action: "android.provider.Telephony.SMS_RECEIVED"
                  androidx.work.impl.diagnostics.REQUEST_DIAGNOSTICS:
                    67890 com.benign.app/androidx.work.impl.diagnostics.DiagnosticsReceiver filter beef
                      Action: "androidx.work.impl.diagnostics.REQUEST_DIAGNOSTICS"
        """.trimIndent()

        val result = module.analyze(section, mockIndicatorResolver, DeviceIdentity.UNKNOWN)

        // The real SMS receiver is still detected...
        assertTrue(
            "expected the genuine SMS receiver to be detected",
            result.telemetry.any { it["package_name"] == "com.evil.sms" },
        )
        // ...but the WorkManager diagnostics receiver must NOT be mislabelled as
        // an SMS receiver (nor appear at all — its intent is not enumerated).
        assertTrue(
            "WorkManager DiagnosticsReceiver must not be attributed to SMS_RECEIVED",
            result.telemetry.none { it["package_name"] == "com.benign.app" },
        )
    }

    @Test
    fun `non-enumerated group between two enumerated intents is excluded from both`() = runBlocking {
        // A non-enumerated intent group sits BETWEEN two enumerated ones. This
        // is the case only `truncateAtNextHeader` handles: BOOT_COMPLETED's
        // blockEnd is the SMS header, so without header-level truncation the
        // in-between receiver would be swept into BOOT_COMPLETED.
        val section = """
            Receiver Resolver Table:
              Non-Data Actions:
                  android.intent.action.BOOT_COMPLETED:
                    11111 com.app.boot/.BootReceiver filter aaaa
                      Action: "android.intent.action.BOOT_COMPLETED"
                  com.example.custom.MIDDLE_ACTION:
                    33333 com.middle.app/.MiddleReceiver filter cccc
                      Action: "com.example.custom.MIDDLE_ACTION"
                  android.provider.Telephony.SMS_RECEIVED:
                    22222 com.app.sms/.SmsReceiver filter bbbb
                      Action: "android.provider.Telephony.SMS_RECEIVED"
        """.trimIndent()

        val result = module.analyze(section, mockIndicatorResolver, DeviceIdentity.UNKNOWN)

        assertTrue(
            "boot receiver must map to BOOT_COMPLETED only",
            result.telemetry.any {
                it["package_name"] == "com.app.boot" &&
                    it["intent_action"] == "android.intent.action.BOOT_COMPLETED"
            },
        )
        assertTrue(
            "sms receiver must map to SMS_RECEIVED only",
            result.telemetry.any {
                it["package_name"] == "com.app.sms" &&
                    it["intent_action"] == "android.provider.Telephony.SMS_RECEIVED"
            },
        )
        // The in-between non-enumerated receiver must not be attributed to the
        // preceding enumerated intent (nor appear at all — its action is not
        // enumerated). This is what fails if truncateAtNextHeader is a no-op.
        assertTrue(
            "middle receiver must not be swept into BOOT_COMPLETED",
            result.telemetry.none { it["package_name"] == "com.middle.app" },
        )
    }

    @Test
    fun `empty section produces no telemetry`() = runBlocking {
        val result = module.analyze("", mockIndicatorResolver, com.androdr.ioc.DeviceIdentity.UNKNOWN)
        assertTrue(result.telemetry.isEmpty())
    }
}
