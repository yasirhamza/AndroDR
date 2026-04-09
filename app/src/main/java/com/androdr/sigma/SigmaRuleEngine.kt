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
import com.androdr.data.model.ForensicTimelineEvent
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
    private val ruleLock = Any()
    @Volatile private var rules: List<SigmaRule> = emptyList()
    @Volatile private var bundledRules: List<SigmaRule> = emptyList()
    @Volatile private var iocLookups: Map<String, (Any) -> Boolean> = emptyMap()
    @Volatile private var evidenceProviders: Map<String, EvidenceProvider> = emptyMap()
    @Volatile private var remoteRulesLoaded = false
    @Volatile private var correlationRules: List<CorrelationRule> = emptyList()

    fun getCorrelationRules(): List<CorrelationRule> = correlationRules

    /**
     * Validate that every referenced rule ID in [parsedRules] corresponds to a
     * detection rule that has already been loaded, then store the correlation rules.
     * Must be called after detection rules are loaded (bundled and/or remote).
     */
    fun loadCorrelationRules(parsedRules: List<CorrelationRule>) {
        synchronized(ruleLock) {
            val knownIds = rules.map { it.id }.toSet()
            parsedRules.forEach { rule ->
                rule.referencedRuleIds.forEach { ref ->
                    if (ref !in knownIds) {
                        throw CorrelationParseException.UnresolvedRule(rule.id, ref)
                    }
                }
            }
            correlationRules = parsedRules
            Log.i(TAG, "Loaded ${correlationRules.size} correlation rules")
        }
    }

    // Explicit manifest is inherently long but R8-safe;
    // catch-all prevents one bad rule from blocking all others
    @Suppress("LongMethod", "TooGenericExceptionCaught")
    fun loadBundledRules() {
        synchronized(ruleLock) {
            if (bundledRules.isNotEmpty()) return
            val loaded = mutableListOf<SigmaRule>()
            val parsedCorrelations = mutableListOf<CorrelationRule>()
            for (resId in BUNDLED_RULE_IDS) {
                try {
                    val yaml = context.resources.openRawResource(resId)
                        .bufferedReader().use { it.readText() }
                    val detRule = SigmaRuleParser.parse(yaml)
                    if (detRule != null) {
                        loaded.add(detRule)
                    } else if (yaml.contains("correlation:")) {
                        try {
                            parsedCorrelations.add(SigmaRuleParser.parseCorrelation(yaml))
                        } catch (e: Exception) {
                            Log.w(TAG, "Failed to parse correlation rule: ${e.message}")
                        }
                    }
                } catch (e: Exception) {
                    Log.w(TAG, "Failed to load rule resource: ${e.message}")
                }
            }
            bundledRules = loaded
            rules = loaded
            Log.i(TAG, "Loaded ${rules.size} bundled SIGMA rules")
            if (parsedCorrelations.isNotEmpty()) {
                try {
                    val knownIds = rules.map { it.id }.toSet()
                    parsedCorrelations.forEach { rule ->
                        rule.referencedRuleIds.forEach { ref ->
                            if (ref !in knownIds) {
                                throw CorrelationParseException.UnresolvedRule(rule.id, ref)
                            }
                        }
                    }
                    correlationRules = parsedCorrelations
                    Log.i(TAG, "Loaded ${correlationRules.size} correlation rules")
                } catch (e: Exception) {
                    Log.w(TAG, "Failed to register correlation rules: ${e.message}")
                }
            }
        }
    }

    /**
     * For each event, compute the set of atom rule IDs whose selection.category
     * matches the event's category. Atom rules are detection rules with
     * level == "informational" that have a single `selection` with a `category`
     * equals matcher. Used by [SigmaCorrelationEngine] to bind raw timeline
     * events to the atom rule IDs referenced by correlation rules.
     */
    fun computeAtomBindings(events: List<ForensicTimelineEvent>): Map<Long, Set<String>> {
        val atomCategoryByRuleId: Map<String, String> = rules
            .asSequence()
            .filter { it.enabled }
            .filter { it.level == "informational" }
            .mapNotNull { rule ->
                val cat = extractAtomCategory(rule) ?: return@mapNotNull null
                rule.id to cat
            }
            .toMap()
        if (atomCategoryByRuleId.isEmpty() || events.isEmpty()) return emptyMap()
        return events.associate { event ->
            event.id to atomCategoryByRuleId
                .asSequence()
                .filter { (_, cat) -> cat == event.category }
                .map { it.key }
                .toSet()
        }
    }

    private fun extractAtomCategory(rule: SigmaRule): String? {
        // Atom rules use a single `selection` with a `category` equals matcher.
        val selection = rule.detection.selections["selection"] ?: return null
        val matcher = selection.fieldMatchers.firstOrNull { it.fieldName == "category" } ?: return null
        return matcher.values.firstOrNull()?.toString()
    }

    fun setRemoteRules(remoteRules: List<SigmaRule>) = synchronized(ruleLock) {
        val remoteById = remoteRules.associateBy { it.id }
        val merged = bundledRules.map { remoteById[it.id] ?: it }.toMutableList()
        val existingIds = merged.map { it.id }.toSet()
        for (rule in remoteRules) {
            if (rule.id !in existingIds) merged.add(rule)
        }
        rules = merged
        remoteRulesLoaded = remoteRules.isNotEmpty()
        Log.i(TAG, "Total rules after merge: ${rules.size} (${remoteById.size} remote)")
    }

    fun hasRemoteRules(): Boolean = remoteRulesLoaded

    // Signature is (fieldValue) -> Boolean. If a future lookup needs the full telemetry
    // record for cross-field correlation, widen to (Any, Map<String, Any?>) -> Boolean.
    fun setIocLookups(lookups: Map<String, (Any) -> Boolean>) {
        iocLookups = lookups
    }

    fun setEvidenceProviders(providers: Map<String, EvidenceProvider>) {
        evidenceProviders = providers
    }

    /**
     * Returns ALL rules, including rules with `enabled: false`.
     *
     * Prefer [getEnabledRules] when iterating for evaluation. This method
     * is intended for diagnostics, UI displays that show "X of Y rules
     * active", and any code path that must account for disabled rules.
     *
     * Callers that iterate this list to produce findings or correlation
     * bindings must filter by `enabled` themselves or use [getEnabledRules].
     */
    fun getRules(): List<SigmaRule> = rules

    /**
     * Returns all rules with `enabled: true`. Use this for evaluation-path
     * code that must not include disabled rules (e.g. correlation lookups,
     * rule-count displays for "active rules").
     *
     * [getRules] returns ALL rules including disabled ones for diagnostic
     * and UI purposes. If a caller cannot tolerate disabled rules in its
     * iteration, it must use this method instead of [getRules].
     *
     * This is a thin public wrapper over the internal [effectiveRules];
     * it exists to give external callers a discoverable API for the
     * enabled-only rule set.
     */
    fun getEnabledRules(): List<SigmaRule> = effectiveRules()

    /** Returns only rules that are enabled. Used internally by all evaluate* methods. */
    private fun effectiveRules(): List<SigmaRule> = getRules().filter { it.enabled }

    fun evaluateApps(telemetry: List<AppTelemetry>): List<Finding> {
        val records = telemetry.map { it.toFieldMap() }
        return SigmaRuleEvaluator.evaluate(effectiveRules(), records, "app_scanner", iocLookups, evidenceProviders)
    }

    fun evaluateDevice(telemetry: List<DeviceTelemetry>): List<Finding> {
        val records = telemetry.map { it.toFieldMap() }
        return SigmaRuleEvaluator.evaluate(effectiveRules(), records, "device_auditor", iocLookups, evidenceProviders)
    }

    fun evaluateProcesses(telemetry: List<ProcessTelemetry>): List<Finding> {
        val records = telemetry.map { it.toFieldMap() }
        return SigmaRuleEvaluator.evaluate(effectiveRules(), records, "process_monitor", iocLookups, evidenceProviders)
    }

    fun evaluateDns(events: List<DnsEvent>): List<Finding> {
        val records = events.map { it.toFieldMap() }
        return SigmaRuleEvaluator.evaluate(effectiveRules(), records, "dns_monitor", iocLookups, evidenceProviders)
    }

    fun evaluateFiles(telemetry: List<FileArtifactTelemetry>): List<Finding> {
        val records = telemetry.map { it.toFieldMap() }
        return SigmaRuleEvaluator.evaluate(effectiveRules(), records, "file_scanner", iocLookups, evidenceProviders)
    }

    fun evaluateAccessibility(telemetry: List<AccessibilityTelemetry>): List<Finding> {
        val records = telemetry.map { it.toFieldMap() }
        return SigmaRuleEvaluator.evaluate(
            effectiveRules(), records, "accessibility_audit", iocLookups, evidenceProviders
        )
    }

    fun evaluateReceivers(telemetry: List<ReceiverTelemetry>): List<Finding> {
        val records = telemetry.map { it.toFieldMap() }
        return SigmaRuleEvaluator.evaluate(effectiveRules(), records, "receiver_audit", iocLookups, evidenceProviders)
    }

    fun evaluateAppOps(telemetry: List<AppOpsTelemetry>): List<Finding> {
        val records = telemetry.map { it.toFieldMap() }
        return SigmaRuleEvaluator.evaluate(effectiveRules(), records, "appops_audit", iocLookups, evidenceProviders)
    }

    fun evaluateGeneric(records: List<Map<String, Any?>>, service: String): List<Finding> {
        return SigmaRuleEvaluator.evaluate(effectiveRules(), records, service, iocLookups, evidenceProviders)
    }

    /**
     * Returns the total number of loaded rules, **including rules with
     * `enabled: false`**. Callers wanting the count of active (evaluable)
     * rules should filter separately:
     *
     *     getRules().count { it.enabled }
     *
     * This method does NOT use [effectiveRules] because UI and debug paths
     * may want to show "X total, Y disabled" — the distinction is the
     * caller's responsibility.
     */
    fun ruleCount(): Int = rules.size

    companion object {
        private const val TAG = "SigmaRuleEngine"

        /** Explicit manifest of bundled SIGMA rule resources — R8-safe (no reflection). */
        private val BUNDLED_RULE_IDS = listOf(
            R.raw.sigma_androdr_001_package_ioc,
            R.raw.sigma_androdr_002_cert_hash_ioc,
            R.raw.sigma_androdr_003_domain_ioc,
            R.raw.sigma_androdr_004_apk_hash_ioc,
            R.raw.sigma_androdr_005_graphite_paragon,
            R.raw.sigma_androdr_010_sideloaded_app,
            R.raw.sigma_androdr_011_surveillance_permissions,
            R.raw.sigma_androdr_012_accessibility_abuse,
            R.raw.sigma_androdr_013_device_admin_abuse,
            R.raw.sigma_androdr_014_app_impersonation,
            R.raw.sigma_androdr_015_firmware_implant,
            R.raw.sigma_androdr_016_system_name_disguise,
            R.raw.sigma_androdr_017_accessibility_surveillance_combo,
            R.raw.sigma_androdr_020_spyware_artifact,
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
            R.raw.sigma_androdr_067_notification_listener,
            R.raw.sigma_androdr_068_hidden_launcher,
            // Atom rules — pass-through matchers for raw timeline event categories.
            // Referenced by sprint-75 correlation rules (Task 9); tagged
            // level: informational so they are filtered out of the user-facing
            // findings UI (see ReportFormatter / DashboardScreen / BugReportScreen).
            R.raw.sigma_androdr_atom_package_install,
            R.raw.sigma_androdr_atom_device_admin_grant,
            R.raw.sigma_androdr_atom_permission_use,
            R.raw.sigma_androdr_atom_dns_lookup,
            R.raw.sigma_androdr_atom_app_launch,
            // Correlation rules — parsed via SigmaRuleParser.parseCorrelation
            // (wired in Task 10). The detection parser silently skips these
            // files today because they have no `detection:` block.
            R.raw.sigma_androdr_corr_001_install_then_admin,
            R.raw.sigma_androdr_corr_002_install_then_permission,
            R.raw.sigma_androdr_corr_003_permission_then_c2,
            R.raw.sigma_androdr_corr_004_surveillance_burst,
        )
    }
}
