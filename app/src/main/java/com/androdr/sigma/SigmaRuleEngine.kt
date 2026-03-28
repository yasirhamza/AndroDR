// app/src/main/java/com/androdr/sigma/SigmaRuleEngine.kt
package com.androdr.sigma

import android.content.Context
import android.util.Log
import com.androdr.data.model.AccessibilityTelemetry
import com.androdr.data.model.AppOpsTelemetry
import com.androdr.data.model.AppTelemetry
import com.androdr.data.model.DeviceTelemetry
import com.androdr.data.model.DnsEvent
import com.androdr.data.model.FileArtifactTelemetry
import com.androdr.data.model.ProcessTelemetry
import com.androdr.data.model.ReceiverTelemetry
import dagger.hilt.android.qualifiers.ApplicationContext
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
@Suppress("TooManyFunctions") // Each evaluate* method maps a telemetry type to the rule evaluator
class SigmaRuleEngine @Inject constructor(
    @ApplicationContext private val context: Context
) {
    private var rules: List<SigmaRule> = emptyList()
    private var iocLookups: Map<String, (Any) -> Boolean> = emptyMap()
    private var evidenceProviders: Map<String, EvidenceProvider> = emptyMap()

    init {
        loadBundledRules()
    }

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

    fun setEvidenceProviders(providers: Map<String, EvidenceProvider>) {
        evidenceProviders = providers
    }

    fun getRules(): List<SigmaRule> = rules

    fun evaluateApps(telemetry: List<AppTelemetry>): List<Finding> {
        val records = telemetry.map { it.toFieldMap() }
        return SigmaRuleEvaluator.evaluate(rules, records, "app_scanner", iocLookups, evidenceProviders)
    }

    fun evaluateDevice(telemetry: List<DeviceTelemetry>): List<Finding> {
        val records = telemetry.map { it.toFieldMap() }
        return SigmaRuleEvaluator.evaluate(rules, records, "device_auditor", iocLookups, evidenceProviders)
    }

    fun evaluateProcesses(telemetry: List<ProcessTelemetry>): List<Finding> {
        val records = telemetry.map { it.toFieldMap() }
        return SigmaRuleEvaluator.evaluate(rules, records, "process_monitor", iocLookups, evidenceProviders)
    }

    fun evaluateDns(events: List<DnsEvent>): List<Finding> {
        val records = events.map { it.toFieldMap() }
        return SigmaRuleEvaluator.evaluate(rules, records, "dns_monitor", iocLookups, evidenceProviders)
    }

    fun evaluateFiles(telemetry: List<FileArtifactTelemetry>): List<Finding> {
        val records = telemetry.map { it.toFieldMap() }
        return SigmaRuleEvaluator.evaluate(rules, records, "file_scanner", iocLookups, evidenceProviders)
    }

    fun evaluateAccessibility(telemetry: List<AccessibilityTelemetry>): List<Finding> {
        val records = telemetry.map { it.toFieldMap() }
        return SigmaRuleEvaluator.evaluate(rules, records, "accessibility_audit", iocLookups, evidenceProviders)
    }

    fun evaluateReceivers(telemetry: List<ReceiverTelemetry>): List<Finding> {
        val records = telemetry.map { it.toFieldMap() }
        return SigmaRuleEvaluator.evaluate(rules, records, "receiver_audit", iocLookups, evidenceProviders)
    }

    fun evaluateAppOps(telemetry: List<AppOpsTelemetry>): List<Finding> {
        val records = telemetry.map { it.toFieldMap() }
        return SigmaRuleEvaluator.evaluate(rules, records, "appops_audit", iocLookups, evidenceProviders)
    }

    fun evaluateGeneric(records: List<Map<String, Any?>>, service: String): List<Finding> {
        return SigmaRuleEvaluator.evaluate(rules, records, service, iocLookups, evidenceProviders)
    }

    fun ruleCount(): Int = rules.size

    companion object {
        private const val TAG = "SigmaRuleEngine"
    }
}
