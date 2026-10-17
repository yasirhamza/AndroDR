package com.androdr.reporting

import com.androdr.data.model.NotEvaluatedReason
import com.androdr.data.model.ScannerFailure
import com.androdr.scanner.MISSING_SOURCE_MVT
import com.androdr.scanner.MISSING_SOURCE_RULES_REPO

/** How fully a scan covered one service a campaign is detected by (#394). */
enum class ServiceCoverage { CHECKED, BUILT_IN_LISTS_ONLY, PARTLY_UNREADABLE, BLIND, NEEDS_IMPORT }

/** Why a [ServiceCoverage.BLIND] service did not run; each has its own row text and fix. */
enum class BlindReason { DNS_OFF, CHECK_FAILED, UNKNOWN_SERVICE }

data class ServiceStatus(val service: String, val coverage: ServiceCoverage, val reason: BlindReason? = null)

/** The scanner name the orchestrator records when the DNS snapshot read fails. */
internal const val DNS_SNAPSHOT_SCANNER = "dnsSnapshot"

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
private const val FILE_SERVICE = "file_scanner"
private const val DNS_SERVICE = "dns_monitor"

/**
 * One status per service in [detectedBy], from what the scan stored: the first that applies of
 * import-only, blind (DNS off, a crash of its scanner, or a service this build doesn't know),
 * files partly unreadable for this campaign's own rule, built-in lists only, else checked.
 */
internal fun campaignCoverage(
    detectedBy: List<String>,
    campaignKey: String,
    scannerErrors: List<ScannerFailure>,
    ruleCampaigns: Map<String, Set<String>>,
): List<ServiceStatus> {
    val reasons = scannerErrors.mapNotNull { e -> NotEvaluatedReason.fromSentinel(e.exception)?.let { it to e } }
    val crashed = scannerErrors
        .filter { NotEvaluatedReason.fromSentinel(it.exception) == null }
        .map { it.scanner }
        .toSet()
    fun has(r: NotEvaluatedReason) = reasons.any { it.first == r }
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
    val ownPathsUnreadable = reasons.any { (r, e) ->
        r == NotEvaluatedReason.UNREADABLE_PATHS && campaignKey in e.ruleId?.let { ruleCampaigns[it] }.orEmpty()
    }
    return detectedBy.map { service ->
        when {
            service in IMPORT_ONLY_SERVICES -> ServiceStatus(service, ServiceCoverage.NEEDS_IMPORT)
            service == DNS_SERVICE && has(NotEvaluatedReason.DNS_MONITOR_OFF) ->
                ServiceStatus(service, ServiceCoverage.BLIND, BlindReason.DNS_OFF)
            service !in SCANNER_FOR_SERVICE ->
                ServiceStatus(service, ServiceCoverage.BLIND, BlindReason.UNKNOWN_SERVICE)
            SCANNER_FOR_SERVICE.getValue(service) in crashed ->
                ServiceStatus(service, ServiceCoverage.BLIND, BlindReason.CHECK_FAILED)
            service == FILE_SERVICE && ownPathsUnreadable -> ServiceStatus(service, ServiceCoverage.PARTLY_UNREADABLE)
            service in builtInOnly -> ServiceStatus(service, ServiceCoverage.BUILT_IN_LISTS_ONLY)
            else -> ServiceStatus(service, ServiceCoverage.CHECKED)
        }
    }
}
