// app/src/main/java/com/androdr/sigma/SigmaRuleEngine.kt
package com.androdr.sigma

import android.content.Context
import android.util.Log
import com.androdr.data.model.AppTelemetry
import com.androdr.data.model.DeviceTelemetry
import dagger.hilt.android.qualifiers.ApplicationContext
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class SigmaRuleEngine @Inject constructor(
    @ApplicationContext private val context: Context
) {
    private var rules: List<SigmaRule> = emptyList()
    private var iocLookups: Map<String, (Any) -> Boolean> = emptyMap()

    @Suppress("TooGenericExceptionCaught")
    fun loadBundledRules() {
        val loaded = mutableListOf<SigmaRule>()
        try {
            val fields = com.androdr.R.raw::class.java.fields
            for (field in fields) {
                if (field.name.startsWith("sigma_")) {
                    val resId = field.getInt(null)
                    val yaml = context.resources.openRawResource(resId)
                        .bufferedReader().use { it.readText() }
                    SigmaRuleParser.parse(yaml)?.let { loaded.add(it) }
                }
            }
        } catch (e: Exception) {
            Log.w(TAG, "Failed to load bundled SIGMA rules: ${e.message}")
        }
        rules = loaded
        Log.i(TAG, "Loaded ${rules.size} bundled SIGMA rules")
    }

    fun setRemoteRules(remoteRules: List<SigmaRule>) {
        val bundledIds = rules.filter { it.id.startsWith("androdr-") }.map { it.id }.toSet()
        val merged = rules.toMutableList()
        for (rule in remoteRules) {
            if (rule.id !in bundledIds) {
                merged.add(rule)
            }
        }
        rules = merged
        Log.i(TAG, "Total rules after merge: ${rules.size}")
    }

    fun setIocLookups(lookups: Map<String, (Any) -> Boolean>) {
        iocLookups = lookups
    }

    fun evaluateApps(telemetry: List<AppTelemetry>): List<Finding> {
        val records = telemetry.map { it.toFieldMap() }
        return SigmaRuleEvaluator.evaluate(rules, records, "app_scanner", iocLookups)
    }

    fun evaluateDevice(telemetry: List<DeviceTelemetry>): List<Finding> {
        val records = telemetry.map { it.toFieldMap() }
        return SigmaRuleEvaluator.evaluate(rules, records, "device_auditor", iocLookups)
    }

    fun ruleCount(): Int = rules.size

    companion object {
        private const val TAG = "SigmaRuleEngine"
    }
}
