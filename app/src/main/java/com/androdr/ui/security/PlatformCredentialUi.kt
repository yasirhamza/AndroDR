package com.androdr.ui.security

import android.app.Activity
import android.content.Intent
import android.hardware.biometrics.BiometricManager
import android.hardware.biometrics.BiometricPrompt
import android.os.Build
import android.os.CancellationSignal
import androidx.activity.ComponentActivity
import androidx.activity.result.contract.ActivityResultContracts
import androidx.annotation.RequiresApi
import androidx.core.content.ContextCompat
import java.util.UUID
import kotlin.coroutines.resume
import kotlinx.coroutines.suspendCancellableCoroutine

/** Real [CredentialUi] bound to a foreground activity. Needs a device; covered by on-device checks. */
class PlatformCredentialUi(private val activity: ComponentActivity) : CredentialUi {

    override suspend fun authenticateWithDeviceCredential(title: String, description: String): Boolean {
        // ConfirmCredential routes here only on API 30+; fail closed (it maps the throw to Cancelled).
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.R) {
            error("device-credential BiometricPrompt needs API 30")
        }
        return promptApi30(title, description)
    }

    @RequiresApi(Build.VERSION_CODES.R)
    private suspend fun promptApi30(title: String, description: String): Boolean =
        suspendCancellableCoroutine { cont ->
            val signal = CancellationSignal()
            cont.invokeOnCancellation { signal.cancel() }
            val prompt = BiometricPrompt.Builder(activity)
                .setTitle(title)
                .setDescription(description)
                .setAllowedAuthenticators(BiometricManager.Authenticators.DEVICE_CREDENTIAL)
                .build()
            prompt.authenticate(
                signal,
                ContextCompat.getMainExecutor(activity),
                object : BiometricPrompt.AuthenticationCallback() {
                    override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult?) {
                        if (cont.isActive) cont.resume(true)
                    }

                    override fun onAuthenticationError(errorCode: Int, errString: CharSequence?) {
                        if (cont.isActive) cont.resume(false)
                    }
                },
            )
        }

    override suspend fun launchConfirmIntent(intent: Intent): Boolean =
        suspendCancellableCoroutine { cont ->
            val launcher = activity.activityResultRegistry.register(
                "confirm-credential-${UUID.randomUUID()}",
                ActivityResultContracts.StartActivityForResult(),
            ) { result -> if (cont.isActive) cont.resume(result.resultCode == Activity.RESULT_OK) }
            cont.invokeOnCancellation { launcher.unregister() }
            launcher.launch(intent)
        }
}
