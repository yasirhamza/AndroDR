package com.androdr.scanner

import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.util.Log
import com.androdr.data.model.ReceiverTelemetry
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class ReceiverAuditScanner @Inject constructor(
    @ApplicationContext private val context: Context
) {

    private val sensitiveIntents = listOf(
        "android.provider.Telephony.SMS_RECEIVED",
        "android.provider.Telephony.NEW_OUTGOING_SMS",
        "android.intent.action.DATA_SMS_RECEIVED",
        "android.intent.action.PHONE_STATE",
        "android.intent.action.NEW_OUTGOING_CALL"
    )

    // The loop uses `continue` for dedup (seen set) and processes receivers — the two
    // jump points are necessary and the logic is clear without further decomposition.
    @Suppress("LoopWithTooManyJumpStatements")
    suspend fun collectTelemetry(): List<ReceiverTelemetry> = withContext(Dispatchers.IO) {
        val pm = context.packageManager
        val results = mutableListOf<ReceiverTelemetry>()
        val seen = mutableSetOf<Pair<String, String>>()

        for (action in sensitiveIntents) {
            val intent = Intent(action)
            @Suppress("QueryPermissionsNeeded")
            val receivers = pm.queryBroadcastReceivers(intent, PackageManager.GET_META_DATA)
            for (ri in receivers) {
                val ai = ri.activityInfo ?: continue
                val key = ai.packageName to action
                if (!seen.add(key)) continue
                val isSystem = OemPackageHelper.isSystemOrOem(ai.packageName, ai.applicationInfo)
                results.add(ReceiverTelemetry(
                    packageName = ai.packageName,
                    intentAction = action,
                    componentName = ai.name,
                    isSystemApp = isSystem
                ))
            }
        }

        Log.d(TAG, "Collected ${results.size} broadcast receiver records")
        results
    }

    companion object {
        private const val TAG = "ReceiverAuditScanner"
    }
}
