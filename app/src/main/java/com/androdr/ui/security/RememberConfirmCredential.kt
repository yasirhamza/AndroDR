package com.androdr.ui.security

import android.app.KeyguardManager
import android.content.Context
import android.content.ContextWrapper
import android.os.Build
import androidx.activity.ComponentActivity
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.platform.LocalContext

/**
 * A device-credential prompt bound to the hosting activity, for a protected action (closing alerts):
 * `confirm(title, description)` shows the platform prompt ([ConfirmCredential]). Created per
 * composition (it holds the activity), never stored in a ViewModel. Without an activity — or a
 * keyguard service — every confirmation is [ConfirmResult.Cancelled] (fails closed).
 */
@Composable
fun rememberConfirmCredential(): suspend (title: String, description: String) -> ConfirmResult {
    val activity = LocalContext.current.findComponentActivity()
    return remember(activity) {
        val keyguard = activity?.getSystemService(KeyguardManager::class.java)
        if (activity == null || keyguard == null) {
            { _, _ -> ConfirmResult.Cancelled }
        } else {
            val credential = ConfirmCredential(Build.VERSION.SDK_INT, keyguard, PlatformCredentialUi(activity))
            credential::confirm
        }
    }
}

private tailrec fun Context.findComponentActivity(): ComponentActivity? = when (this) {
    is ComponentActivity -> this
    is ContextWrapper -> baseContext.findComponentActivity()
    else -> null
}
