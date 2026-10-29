package com.androdr.ui.security

import android.app.KeyguardManager
import android.content.Intent
import kotlin.coroutines.cancellation.CancellationException

/** Outcome of a device-credential confirmation. */
enum class ConfirmResult {
    Confirmed,

    /** Returned only when [KeyguardManager.isDeviceSecure] is false. */
    NoSecureLock,

    /** The person dismissed the prompt, or anything at all went wrong. Fails closed. */
    Cancelled,
}

/**
 * The platform surface that actually shows a credential prompt. Separated so the routing and the
 * fail-closed mapping in [ConfirmCredential] are testable without a device.
 */
interface CredentialUi {
    /** API 30+: platform BiometricPrompt, `DEVICE_CREDENTIAL` authenticator only. True on success. */
    suspend fun authenticateWithDeviceCredential(title: String, description: String): Boolean

    /** API 26-29: runs the Keyguard confirm-credential intent. True when it returned RESULT_OK. */
    suspend fun launchConfirmIntent(intent: Intent): Boolean
}

/**
 * Requires the device credential (PIN, pattern or password) before a protected action.
 *
 * Residual risk: someone who knows the PIN, or spyware that has logged it, passes this check.
 */
class ConfirmCredential(
    private val sdkInt: Int,
    private val keyguardManager: KeyguardManager,
    private val ui: CredentialUi,
) {
    @Suppress("TooGenericExceptionCaught") // every failure must collapse to Cancelled (fail closed)
    suspend fun confirm(title: String, description: String): ConfirmResult =
        try {
            when {
                !keyguardManager.isDeviceSecure -> ConfirmResult.NoSecureLock
                sdkInt >= BIOMETRIC_DEVICE_CREDENTIAL_API ->
                    ui.authenticateWithDeviceCredential(title, description).toResult()
                else -> {
                    val intent = keyguardManager.createConfirmDeviceCredentialIntent(title, description)
                    if (intent == null) ConfirmResult.Cancelled else ui.launchConfirmIntent(intent).toResult()
                }
            }
        } catch (e: CancellationException) {
            throw e
        } catch (ignored: Exception) {
            ConfirmResult.Cancelled
        }

    private fun Boolean.toResult() = if (this) ConfirmResult.Confirmed else ConfirmResult.Cancelled

    private companion object {
        /** `setAllowedAuthenticators` on the platform BiometricPrompt exists from API 30. */
        const val BIOMETRIC_DEVICE_CREDENTIAL_API = 30
    }
}
