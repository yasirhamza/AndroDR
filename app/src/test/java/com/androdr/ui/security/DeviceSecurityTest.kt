package com.androdr.ui.security

import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * One rule for honouring a [ConfirmResult], shared by alert close and history
 * deletion (spec §5.4): `Confirmed` is honoured; `NoSecureLock` only when the lock
 * screen really is insecure, otherwise refused (a forged or stale result cannot
 * skip the credential); `Cancelled` is refused. Null means refuse.
 */
class DeviceSecurityTest {

    private val secure = DeviceSecurity { true }
    private val insecure = DeviceSecurity { false }

    @Test
    fun `Confirmed is honoured and recorded as credential-backed`() {
        assertEquals(true, secure.credentialOf(ConfirmResult.Confirmed))
        assertEquals(true, insecure.credentialOf(ConfirmResult.Confirmed))
    }

    @Test
    fun `NoSecureLock is honoured only when the device really has no secure lock`() {
        assertEquals(false, insecure.credentialOf(ConfirmResult.NoSecureLock))
        assertEquals(null, secure.credentialOf(ConfirmResult.NoSecureLock))
    }

    @Test
    fun `Cancelled is always refused`() {
        assertEquals(null, secure.credentialOf(ConfirmResult.Cancelled))
        assertEquals(null, insecure.credentialOf(ConfirmResult.Cancelled))
    }
}
