package com.androdr.ui.security

import android.app.KeyguardManager

/**
 * Whether the device has a secure lock screen ([KeyguardManager.isDeviceSecure]). Closing alerts
 * re-checks it before honouring [ConfirmResult.NoSecureLock] (spec §5.4): `NoSecureLock` on a device
 * that is secure is refused, so a forged or stale result cannot skip the credential.
 */
fun interface DeviceSecurity {
    fun isDeviceSecure(): Boolean

    companion object {
        fun of(keyguardManager: KeyguardManager) = DeviceSecurity { keyguardManager.isDeviceSecure }
    }
}

/**
 * Whether a protected action may proceed on [result], and if so whether it was
 * credential-backed (`true`) or allowed because the device has no secure lock
 * (`false`); null means refuse. One rule for every credential-gated action —
 * alert close and history deletion — so none of them honours a `NoSecureLock`
 * result on a device whose lock screen is in fact secure.
 */
fun DeviceSecurity.credentialOf(result: ConfirmResult): Boolean? = when (result) {
    ConfirmResult.Confirmed -> true
    // Honoured only when the lock screen really is insecure; otherwise refused (fails closed).
    ConfirmResult.NoSecureLock -> if (isDeviceSecure()) null else false
    ConfirmResult.Cancelled -> null
}
