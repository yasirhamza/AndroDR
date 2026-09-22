package com.androdr.sigma

import com.androdr.data.model.FileArtifactTelemetry
import com.androdr.data.model.ForensicTimelineEvent
import com.androdr.data.model.NotEvaluatedReason
import com.androdr.data.model.ScannerFailure

/**
 * Which rules had nothing to judge, and why.
 *
 * A rule evaluated against no evidence produces no finding, and a report built
 * from findings alone then reads exactly like a clean result. Two rules lived in
 * that gap: the CRITICAL artifact rule, whose paths an unprivileged app may not
 * read (#366), and the chain rules whose legs need event kinds only an imported
 * bug report carries (#370). Both are declared here as [ScannerFailure] entries
 * carrying a [NotEvaluatedReason], which the report renders as its own section
 * and which never count towards the partial-scan banner.
 *
 * Pure: (rules, evidence) -> declarations. No platform, no I/O.
 */
object RuleCoverage {

    /** Logsource service of the rules that inspect filesystem artifacts. */
    const val FILE_SERVICE = "file_scanner"

    private const val FILE_SCANNER = "fileArtifactScanner"
    private const val CORRELATION = "correlation"

    /**
     * File rules cannot see a path the app was refused. Declared whenever any path
     * went unread, because an unread path was never checked -- "clear" for the rest
     * of the list is not a verdict on it.
     */
    fun unreadableArtifactSkips(
        rules: List<SigmaRule>,
        telemetry: List<FileArtifactTelemetry>,
    ): List<ScannerFailure> {
        if (telemetry.isEmpty()) return emptyList()
        val unreadable = telemetry.count { !it.accessible }
        if (unreadable == 0) return emptyList()
        return rules.filter { it.service == FILE_SERVICE }.map { rule ->
            ScannerFailure(
                scanner = FILE_SCANNER,
                exception = NotEvaluatedReason.UNREADABLE_PATHS.sentinel,
                message = "${rule.title} (${rule.id}): $unreadable of ${telemetry.size} " +
                    "path(s) could not be read on this device",
                ruleId = rule.id,
            )
        }
    }

    /**
     * A chain rule fires only if every leg has events to bind to. A leg whose atom
     * rule never loaded, or whose event kind nothing recorded, makes the whole chain
     * unevaluable -- silently, until now.
     */
    fun noEventSkips(
        rules: List<CorrelationRule>,
        atomCategoryByRuleId: Map<String, String>,
        presentCategories: Set<String>,
    ): List<ScannerFailure> = rules.mapNotNull { rule ->
        val missing = rule.referencedRuleIds
            .map { atomCategoryByRuleId[it] }
            .filter { it == null || it !in presentCategories }
            .distinct()
        if (missing.isEmpty()) {
            null
        } else {
            ScannerFailure(
                scanner = CORRELATION,
                exception = NotEvaluatedReason.NO_EVENTS_TO_CHECK.sentinel,
                message = "${rule.title} (${rule.id}): needs ${missing.joinToString(" and ") { plain(it) }}, " +
                    "none recorded in this scan",
                ruleId = rule.id,
            )
        }
    }

    /** As [noEventSkips], reading the recorded categories off the events themselves. */
    fun noEventSkipsFor(
        rules: List<CorrelationRule>,
        atomCategoryByRuleId: Map<String, String>,
        events: List<ForensicTimelineEvent>,
    ): List<ScannerFailure> =
        noEventSkips(rules, atomCategoryByRuleId, events.mapTo(HashSet()) { it.category })

    /** What an event category is called in a sentence a reader can act on. */
    private fun plain(category: String?): String = when (category) {
        null -> "events of a kind nothing in this build records"
        "permission_use" ->
            "records of apps using sensitive permissions (only an imported bug report carries these)"
        "package_install" -> "app installations"
        "package_uninstall" -> "app removals"
        "package_update" -> "app updates"
        "device_admin_grant" -> "device-administrator grants"
        "app_foreground" -> "app launches"
        "dns_query" -> "DNS lookups"
        "ioc_match", "dns_match" -> "DNS lookups matched against a threat list"
        "network_connect" -> "network connections"
        "security_event" -> "device security events"
        else -> "a kind of event this build does not record"
    }
}
