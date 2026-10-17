package com.androdr.reporting

import com.androdr.data.model.MISSING_SOURCE_MVT
import com.androdr.data.model.MISSING_SOURCE_RULES_REPO
import com.androdr.data.model.NotEvaluatedReason
import com.androdr.data.model.ScannerFailure

/**
 * How fully a scan covered one service a campaign is detected by (#394). Declared in the order
 * the rows are read from least to most trouble; [campaignCoverage] applies them by precedence.
 */
enum class ServiceCoverage {
    CHECKED,
    BUILT_IN_LISTS_ONLY,
    LISTS_UNKNOWN,
    NO_DETECTOR,
    PARTLY_UNREADABLE,
    PARTLY_SKIPPED,
    BLIND,
    NEEDS_IMPORT,
}

/** Why a [ServiceCoverage.BLIND] service did not run; each has its own row text and fix. */
enum class BlindReason { DNS_OFF, CHECK_FAILED, ATTRIBUTION_FAILED, UNKNOWN_SERVICE }

data class ServiceStatus(val service: String, val coverage: ServiceCoverage, val reason: BlindReason? = null)

/**
 * What one loaded rule can detect, for matching its "could not run" entries to campaigns (#394):
 * its logsource [service], the campaigns its `campaign.*` tags name (aliases folded), and whether
 * it can attribute ANY campaign through an IOC row ([carriesIocCampaign]: `evidence_type: ioc_match`
 * with an `ioc_lookup` matcher, e.g. androdr-001/003). Built by ReportInputs (Task A4).
 */
data class RuleScope(val service: String, val campaigns: Set<String>, val carriesIocCampaign: Boolean)

/** The scanner name the orchestrator records when the DNS snapshot read fails. */
internal const val DNS_SNAPSHOT_SCANNER = "dnsSnapshot"

/** The scanner name the orchestrator records when the DNS domain attribution prefetch fails or misses. */
internal const val ATTRIBUTION_SCANNER = "attribution"

/** The scanner name [visibilityGapsOrFailure] records when the feed-coverage query itself fails. */
internal const val VISIBILITY_GAPS_SCANNER = "visibility_gaps"

/**
 * Live-scan service -> the scanner name a crash of it is recorded under. Pinned against the
 * taxonomy and ScanOrchestrator by ServiceScannerMapCrossCheckTest.
 */
internal val SCANNER_FOR_SERVICE: Map<String, String> = mapOf(
    "app_scanner" to "appScanner",
    "device_auditor" to "deviceAuditor",
    "process_monitor" to "processScanner",
    "file_scanner" to "fileArtifactScanner",
    "accessibility_audit" to "accessibilityAuditScanner",
    "receiver_audit" to "receiverAuditScanner",
    "appops_audit" to "appOpsScanner",
    "dns_monitor" to DNS_SNAPSHOT_SCANNER,
)

/** Services only an imported bug report or intrusion log is evaluated against. */
internal val IMPORT_ONLY_SERVICES: Set<String> = setOf(
    "network_monitor", "security_log", "tombstone_parser", "wakelock_parser", "battery_daily",
    "package_install_history", "platform_compat", "db_info", "timeline",
)

/** Services whose matches come from threat lists that may still be loading. */
private val LIST_SERVICES = setOf("dns_monitor", "app_scanner")
private const val DNS_SERVICE = "dns_monitor"

/**
 * One status per service in [detectedBy], from what the scan stored, by precedence: import-only;
 * blind (DNS off, service unknown to this build, its scanner crashed, failed DNS attribution);
 * partly skipped (a "could not run" rule that could detect this campaign on this service); partly
 * unreadable (same, for unreadable paths); no detector (no rule in [rules] can detect this campaign
 * on this service: a campaign rule dropped by a hash mismatch, a failed fetch, a disabled rule or an
 * older build); lists unknown; built-in lists only; else checked. [rules] must hold only the loaded,
 * enabled rules, so a service never reads checked without a rule that could have matched there.
 * A "could not run" entry counts only when [rules] knows its rule (see [RuleScope]). Rules a build
 * cannot parse are an accepted residual: the report still lists them, but they count for no campaign.
 */
internal fun campaignCoverage(
    detectedBy: List<String>,
    campaignKey: String,
    scannerErrors: List<ScannerFailure>,
    rules: Map<String, RuleScope>,
): List<ServiceStatus> {
    val reasons = scannerErrors.mapNotNull { e -> NotEvaluatedReason.fromSentinel(e.exception)?.let { it to e } }
    val crashed = scannerErrors
        .filter { NotEvaluatedReason.fromSentinel(it.exception) == null }
        .map { it.scanner }
        .toSet()
    fun has(r: NotEvaluatedReason) = reasons.any { it.first == r }
    fun detects(scope: RuleScope, service: String) =
        scope.service == service && (campaignKey in scope.campaigns || scope.carriesIocCampaign)
    fun counts(e: ScannerFailure, service: String): Boolean {
        val scope = e.ruleId?.let { rules[it] } ?: return false
        return detects(scope, service)
    }
    fun hasDetector(service: String) = rules.values.any { detects(it, service) }
    fun skippedFor(service: String, reason: NotEvaluatedReason) =
        reasons.any { (r, e) -> r == reason && counts(e, service) }
    // Which list services ran on the built-in lists only. FEEDS_NOT_LOADED: both. CAMPAIGN_SOURCES_NOT_LOADED:
    // a missing MVT list touches domains only; a missing rules-repo list, or a row saved before
    // missingSources existed (empty), touches both (owner addition, #394).
    val builtInOnly: Set<String> = buildSet {
        if (has(NotEvaluatedReason.FEEDS_NOT_LOADED)) addAll(LIST_SERVICES)
        reasons.filter { it.first == NotEvaluatedReason.CAMPAIGN_SOURCES_NOT_LOADED }.forEach { (_, e) ->
            val src = e.missingSources
            if (src.isEmpty() || MISSING_SOURCE_RULES_REPO in src) addAll(LIST_SERVICES)
            if (MISSING_SOURCE_MVT in src) add(DNS_SERVICE)
        }
    }
    val feedsUnknown = VISIBILITY_GAPS_SCANNER in crashed
    val attributionFailed = ATTRIBUTION_SCANNER in crashed
    return detectedBy.map { service ->
        when {
            service in IMPORT_ONLY_SERVICES -> ServiceStatus(service, ServiceCoverage.NEEDS_IMPORT)
            service == DNS_SERVICE && has(NotEvaluatedReason.DNS_MONITOR_OFF) ->
                ServiceStatus(service, ServiceCoverage.BLIND, BlindReason.DNS_OFF)
            service !in SCANNER_FOR_SERVICE ->
                ServiceStatus(service, ServiceCoverage.BLIND, BlindReason.UNKNOWN_SERVICE)
            SCANNER_FOR_SERVICE.getValue(service) in crashed ->
                ServiceStatus(service, ServiceCoverage.BLIND, BlindReason.CHECK_FAILED)
            service == DNS_SERVICE && attributionFailed ->
                ServiceStatus(service, ServiceCoverage.BLIND, BlindReason.ATTRIBUTION_FAILED)
            skippedFor(service, NotEvaluatedReason.MISSING_CAPABILITY) ->
                ServiceStatus(service, ServiceCoverage.PARTLY_SKIPPED)
            skippedFor(service, NotEvaluatedReason.UNREADABLE_PATHS) ->
                ServiceStatus(service, ServiceCoverage.PARTLY_UNREADABLE)
            !hasDetector(service) -> ServiceStatus(service, ServiceCoverage.NO_DETECTOR)
            feedsUnknown && service in LIST_SERVICES -> ServiceStatus(service, ServiceCoverage.LISTS_UNKNOWN)
            service in builtInOnly -> ServiceStatus(service, ServiceCoverage.BUILT_IN_LISTS_ONLY)
            else -> ServiceStatus(service, ServiceCoverage.CHECKED)
        }
    }
}
