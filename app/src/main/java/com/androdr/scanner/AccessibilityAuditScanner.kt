package com.androdr.scanner

import android.accessibilityservice.AccessibilityServiceInfo
import android.content.Context
import android.content.pm.ApplicationInfo
import android.util.Log
import android.view.accessibility.AccessibilityManager
import com.androdr.data.model.AccessibilityTelemetry
import com.androdr.data.model.TelemetrySource
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class AccessibilityAuditScanner @Inject constructor(
    @ApplicationContext private val context: Context
) {
    suspend fun collectTelemetry(): List<AccessibilityTelemetry> = withContext(Dispatchers.IO) {
        val am = context.getSystemService(Context.ACCESSIBILITY_SERVICE) as? AccessibilityManager
            ?: return@withContext emptyList()

        val services = am.getEnabledAccessibilityServiceList(
            AccessibilityServiceInfo.FEEDBACK_ALL_MASK
        ) ?: return@withContext emptyList()

        services.mapNotNull { info ->
            val serviceInfo = info.resolveInfo?.serviceInfo ?: return@mapNotNull null
            val isSystem = serviceInfo.applicationInfo?.flags?.and(ApplicationInfo.FLAG_SYSTEM) != 0
            AccessibilityTelemetry(
                packageName = serviceInfo.packageName,
                serviceName = serviceInfo.name,
                isSystemApp = isSystem,
                isEnabled = true,
                source = TelemetrySource.LIVE_SCAN,
            )
        }.also {
            Log.d(TAG, "Collected ${it.size} enabled accessibility services")
        }
    }

    companion object {
        private const val TAG = "AccessibilityAuditScanner"
    }
}
