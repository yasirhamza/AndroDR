package com.androdr.ui.security

import android.app.KeyguardManager
import android.content.Intent
import io.mockk.every
import io.mockk.mockk
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Test

class ConfirmCredentialTest {

    private class FakeUi(
        var biometricResult: Boolean = true,
        var intentResult: Boolean = true,
        var failWith: Throwable? = null,
    ) : CredentialUi {
        var biometricCalls = 0
        var intentCalls = 0
        override suspend fun authenticateWithDeviceCredential(title: String, description: String): Boolean {
            biometricCalls++
            failWith?.let { throw it }
            return biometricResult
        }
        override suspend fun launchConfirmIntent(intent: Intent): Boolean {
            intentCalls++
            failWith?.let { throw it }
            return intentResult
        }
    }

    private fun keyguard(secure: Boolean, intent: Intent? = mockk()): KeyguardManager =
        mockk {
            every { isDeviceSecure } returns secure
            every { createConfirmDeviceCredentialIntent(any(), any()) } returns intent
        }

    @Test fun `api 30 routes to BiometricPrompt path only`() = runTest {
        val ui = FakeUi()
        val r = ConfirmCredential(30, keyguard(true), ui).confirm("t", "d")
        assertEquals(ConfirmResult.Confirmed, r)
        assertEquals(1, ui.biometricCalls)
        assertEquals(0, ui.intentCalls)
    }

    @Test fun `api 28 routes to Keyguard intent path only`() = runTest {
        val ui = FakeUi()
        val r = ConfirmCredential(28, keyguard(true), ui).confirm("t", "d")
        assertEquals(ConfirmResult.Confirmed, r)
        assertEquals(0, ui.biometricCalls)
        assertEquals(1, ui.intentCalls)
    }

    @Test fun `api 26 lower bound and api 29 upper bound use Keyguard path`() = runTest {
        for (sdk in listOf(26, 29)) {
            val ui = FakeUi()
            ConfirmCredential(sdk, keyguard(true), ui).confirm("t", "d")
            assertEquals("sdk $sdk", 1, ui.intentCalls)
            assertEquals("sdk $sdk", 0, ui.biometricCalls)
        }
    }

    @Test fun `insecure device returns NoSecureLock on both paths without prompting`() = runTest {
        for (sdk in listOf(28, 30)) {
            val ui = FakeUi()
            val r = ConfirmCredential(sdk, keyguard(false), ui).confirm("t", "d")
            assertEquals("sdk $sdk", ConfirmResult.NoSecureLock, r)
            assertEquals(0, ui.biometricCalls + ui.intentCalls)
        }
    }

    @Test fun `user cancel returns Cancelled on both paths`() = runTest {
        for (sdk in listOf(28, 30)) {
            val ui = FakeUi(biometricResult = false, intentResult = false)
            assertEquals(ConfirmResult.Cancelled, ConfirmCredential(sdk, keyguard(true), ui).confirm("t", "d"))
        }
    }

    @Test fun `thrown error returns Cancelled never NoSecureLock or Confirmed`() = runTest {
        for (sdk in listOf(28, 30)) {
            val ui = FakeUi(failWith = IllegalStateException("boom"))
            assertEquals(ConfirmResult.Cancelled, ConfirmCredential(sdk, keyguard(true), ui).confirm("t", "d"))
        }
    }

    @Test fun `null keyguard intent returns Cancelled not NoSecureLock`() = runTest {
        val ui = FakeUi()
        val r = ConfirmCredential(28, keyguard(true, intent = null), ui).confirm("t", "d")
        assertEquals(ConfirmResult.Cancelled, r)
        assertEquals(0, ui.intentCalls)
    }

    @Test fun `isDeviceSecure throwing returns Cancelled`() = runTest {
        val kg = mockk<KeyguardManager> { every { isDeviceSecure } throws SecurityException("x") }
        assertEquals(ConfirmResult.Cancelled, ConfirmCredential(30, kg, FakeUi()).confirm("t", "d"))
    }
}
