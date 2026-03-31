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
import com.androdr.R
import dagger.hilt.android.qualifiers.ApplicationContext
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
@Suppress("TooManyFunctions") // Each evaluate* method maps a telemetry type to the rule evaluator
class SigmaRuleEngine @Inject constructor(
    @ApplicationContext private val context: Context
) {
    @Volatile private var rules: List<SigmaRule> = emptyList()
    @Volatile private var iocLookups: Map<String, (Any) -> Boolean> = emptyMap()
    @Volatile private var evidenceProviders: Map<String, EvidenceProvider> = emptyMap()

    // Explicit manifest is inherently long but R8-safe;
    // catch-all prevents one bad rule from blocking all others
    @Suppress("LongMethod", "TooGenericExceptionCaught")
    fun loadBundledRules() {
        val loaded = mutableListOf<SigmaRule>()
        for (resId in BUNDLED_RULE_IDS) {
            try {
                val yaml = context.resources.openRawResource(resId)
                    .bufferedReader().use { it.readText() }
                SigmaRuleParser.parse(yaml)?.let { loaded.add(it) }
            } catch (e: Exception) {
                Log.w(TAG, "Failed to load rule resource: ${e.message}")
            }
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

        /** Explicit manifest of bundled SIGMA rule resources — R8-safe (no reflection). */
        private val BUNDLED_RULE_IDS = listOf(
            R.raw.sigma_androdr_001_package_ioc,
            R.raw.sigma_androdr_002_cert_hash_ioc,
            R.raw.sigma_androdr_003_domain_ioc,
            R.raw.sigma_androdr_005_graphite_paragon,
            R.raw.sigma_androdr_010_sideloaded_app,
            R.raw.sigma_androdr_011_surveillance_permissions,
            R.raw.sigma_androdr_012_accessibility_abuse,
            R.raw.sigma_androdr_013_device_admin_abuse,
            R.raw.sigma_androdr_014_app_impersonation,
            R.raw.sigma_androdr_015_firmware_implant,
            R.raw.sigma_androdr_016_system_name_disguise,
            R.raw.sigma_androdr_017_accessibility_surveillance_combo,
            R.raw.sigma_androdr_040_adb_enabled,
            R.raw.sigma_androdr_041_dev_options,
            R.raw.sigma_androdr_042_unknown_sources,
            R.raw.sigma_androdr_043_no_screen_lock,
            R.raw.sigma_androdr_044_stale_patch,
            R.raw.sigma_androdr_045_bootloader_unlocked,
            R.raw.sigma_androdr_046_wifi_adb,
            R.raw.sigma_androdr_047_cve_exploit,
            R.raw.sigma_androdr_048_pegasus_cves,
            R.raw.sigma_androdr_049_predator_cves,
            R.raw.sigma_androdr_050_graphite_cves,
            R.raw.sigma_androdr_060_active_accessibility,
            R.raw.sigma_androdr_061_sms_receiver,
            R.raw.sigma_androdr_062_call_receiver,
            R.raw.sigma_androdr_063_appops_microphone,
            R.raw.sigma_androdr_064_appops_camera,
            R.raw.sigma_androdr_065_appops_install_packages,
        )
    }
}
