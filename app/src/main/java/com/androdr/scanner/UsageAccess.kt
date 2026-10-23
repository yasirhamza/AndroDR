package com.androdr.scanner

import android.app.AppOpsManager
import android.content.Context
import android.os.Build
import android.os.Process
import com.androdr.data.model.UsageEvent
import dagger.hilt.android.qualifiers.ApplicationContext
import javax.inject.Inject
import javax.inject.Singleton

/**
 * One usage-stats collection (spec §5.2 Watermarks): the events read, or why none could be. Only
 * [Ok] advances the usage watermark; [NoAccess] (Usage Access not granted) and [Failed] keep it.
 */
sealed interface UsageCollection {
    data class Ok(val events: List<UsageEvent>) : UsageCollection
    data object NoAccess : UsageCollection
    data class Failed(val e: Throwable) : UsageCollection
}

/**
 * Usage Access (`PACKAGE_USAGE_STATS`), checked explicitly through [AppOpsManager] (spec §5.2:
 * no access means the collection failed, never an empty, clean-looking one).
 */
@Singleton
class UsageAccess @Inject constructor(@ApplicationContext private val context: Context) {
    fun granted(): Boolean = isGranted(context)

    companion object {
        /**
         * [AppOpsManager.unsafeCheckOpNoThrow] on API 29+ (the older [AppOpsManager.checkOpNoThrow]
         * was deprecated in Q); on API 26–28 the deprecated overload is still the correct choice.
         */
        fun isGranted(context: Context): Boolean {
            val appOps = context.getSystemService(Context.APP_OPS_SERVICE) as? AppOpsManager ?: return false
            val mode = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                appOps.unsafeCheckOpNoThrow(AppOpsManager.OPSTR_GET_USAGE_STATS, Process.myUid(), context.packageName)
            } else {
                @Suppress("DEPRECATION")
                appOps.checkOpNoThrow(AppOpsManager.OPSTR_GET_USAGE_STATS, Process.myUid(), context.packageName)
            }
            return mode == AppOpsManager.MODE_ALLOWED
        }
    }
}
