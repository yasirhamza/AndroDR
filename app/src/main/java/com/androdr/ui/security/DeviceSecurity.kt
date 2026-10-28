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
