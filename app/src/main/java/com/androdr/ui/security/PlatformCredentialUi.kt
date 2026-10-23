package com.androdr.ui.security

import android.app.Activity
import android.content.Intent
import android.hardware.biometrics.BiometricManager
import android.hardware.biometrics.BiometricPrompt
import android.os.Build
import android.os.CancellationSignal
import androidx.activity.ComponentActivity
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.result.ActivityResultLauncher
import androidx.annotation.RequiresApi
import androidx.core.content.ContextCompat
import androidx.lifecycle.DefaultLifecycleObserver
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleOwner
import java.util.UUID
import kotlin.coroutines.resume
import kotlinx.coroutines.suspendCancellableCoroutine

/**
 * Real [CredentialUi] bound to a foreground activity. The BiometricPrompt path needs a device (D3
 * on-device checklist). Holds the activity strongly: create it per composition (`remember` keyed
 * by the activity), never in a ViewModel or singleton.
 */
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

    /**
     * API 26-29 path. Fail closed: the result is delivered once; if the host activity is destroyed
     * first (rotation, process pressure) the lost result resolves to `false` (Cancelled), never
     * true. A unique key per launch means a stale OK from an earlier launch can never be replayed
     * into a later confirmation. The launcher is always unregistered (completion, cancellation,
     * destruction, or a throwing `launch`).
     */
    override suspend fun launchConfirmIntent(intent: Intent): Boolean =
        suspendCancellableCoroutine { cont ->
            if (activity.lifecycle.currentState == Lifecycle.State.DESTROYED) {
                cont.resume(false) // no onDestroy will ever fire; fail closed
                return@suspendCancellableCoroutine
            }
            var launcher: ActivityResultLauncher<Intent>? = null
            var observer: DefaultLifecycleObserver? = null

            fun cleanup() {
                launcher?.unregister()
                observer?.let { activity.lifecycle.removeObserver(it) }
            }

            fun finish(confirmed: Boolean) {
                cleanup()
                if (cont.isActive) cont.resume(confirmed)
            }

            val destroyObserver = object : DefaultLifecycleObserver {
                override fun onDestroy(owner: LifecycleOwner) = finish(false)
            }
            observer = destroyObserver
            // Lifecycle observers are main-thread only; a cancel from another dispatcher hops to the UI thread.
            cont.invokeOnCancellation { activity.runOnUiThread { cleanup() } }
            // Registration sits inside the try: from a non-main thread addObserver throws after
            // register, and the launcher key must still be released (the call fails closed).
            try {
                val registered = activity.activityResultRegistry.register(
                    "confirm-credential-${UUID.randomUUID()}",
                    ActivityResultContracts.StartActivityForResult(),
                ) { result -> finish(result.resultCode == Activity.RESULT_OK) }
                launcher = registered
                activity.lifecycle.addObserver(destroyObserver)
                registered.launch(intent)
            } catch (@Suppress("TooGenericExceptionCaught") t: Throwable) {
                launcher?.unregister()
                // removeObserver is main-thread only; off main it throws, and addObserver never ran.
                runCatching { activity.lifecycle.removeObserver(destroyObserver) }
                throw t
            }
        }
}
