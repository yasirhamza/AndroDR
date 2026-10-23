package com.androdr.data.db

import com.androdr.data.model.FindingKind

/**
 * Frozen inputs of MIGRATION_20_21 (spec §5.4 Migration): what the migration needs to classify a
 * schema-20 finding as a state finding or an alert, as these facts stood when schema 21 was made.
 * Frozen on purpose — a migration must give the same answer whatever later rules or taxonomy say —
 * so nothing here may be derived from today's rule set or `TaxonomyContract`.
 */
object FrozenRuleServices {
    /** Logsource service of every finding-producing rule (bundled and rules-repo) at schema 21. */
    val SERVICE_BY_RULE: Map<String, String> = mapOf(
        "androdr-001" to "app_scanner",
        "androdr-002" to "app_scanner",
        "androdr-003" to "dns_monitor",
        "androdr-004" to "app_scanner",
        "androdr-010" to "app_scanner",
        "androdr-011" to "app_scanner",
        "androdr-012" to "app_scanner",
        "androdr-013" to "app_scanner",
        "androdr-014" to "app_scanner",
        "androdr-015" to "app_scanner",
        "androdr-016" to "app_scanner",
        "androdr-017" to "app_scanner",
        "androdr-020" to "file_scanner",
        "androdr-040" to "device_auditor",
        "androdr-041" to "device_auditor",
        "androdr-042" to "device_auditor",
        "androdr-043" to "device_auditor",
        "androdr-044" to "device_auditor",
        "androdr-045" to "device_auditor",
        "androdr-046" to "device_auditor",
        "androdr-047" to "device_auditor",
        "androdr-048" to "device_auditor",
        "androdr-049" to "device_auditor",
        "androdr-050" to "device_auditor",
        "androdr-051" to "device_auditor",
        "androdr-052" to "device_auditor",
        "androdr-060" to "accessibility_audit",
        "androdr-061" to "receiver_audit",
        "androdr-062" to "receiver_audit",
        "androdr-063" to "appops_audit",
        "androdr-064" to "appops_audit",
        "androdr-065" to "appops_audit",
        "androdr-066" to "app_scanner",
        "androdr-067" to "app_scanner",
        "androdr-068" to "app_scanner",
        "androdr-069" to "app_scanner",
        "androdr-070" to "dns_monitor",
        "androdr-071" to "tombstone_parser",
        "androdr-072" to "wakelock_parser",
        "androdr-073" to "battery_daily",
        "androdr-074" to "package_install_history",
        "androdr-075" to "platform_compat",
        "androdr-076" to "db_info",
        "androdr-077" to "app_scanner",
        "androdr-078" to "app_scanner",
        "androdr-079" to "app_scanner",
        "androdr-080" to "app_scanner",
        "androdr-081" to "app_scanner",
        "androdr-082" to "app_scanner",
        "androdr-083" to "app_scanner",
        "androdr-087" to "app_scanner",
        "androdr-088" to "app_scanner",
        "androdr-089" to "app_scanner",
        "androdr-092" to "app_scanner",
        "androdr-093" to "app_scanner",
        "androdr-094" to "app_scanner",
        "androdr-095" to "app_scanner",
        "androdr-108" to "file_scanner",
        "androdr-109" to "app_scanner",
        "androdr-110" to "battery_daily",
    )

    /** Each service's event-time field at schema 21 (a service without one holds snapshots). */
    val EVENT_TIME_FIELD_BY_SERVICE: Map<String, String> = mapOf(
        "dns_monitor" to "timestamp",
        "appops_audit" to "event_time_ms",
        "network_monitor" to "timestamp",
        "tombstone_parser" to "crash_timestamp",
        "wakelock_parser" to "acquired_at",
        "battery_daily" to "timestamp",
        "package_install_history" to "timestamp",
        "security_log" to "timestamp",
        "usage_stats" to "timestamp",
    )
}

/**
 * The kind rule for a finding with no stored fact (spec §5.4 Kind) — the evaluate-only fallback at
 * run time, and pre-store findings in MIGRATION_20_21: one function, so the two cannot drift.
 */
object FindingKinds {
    /** Services whose every record is an event, whatever its fields say. */
    val ALWAYS_EVENT: Set<String> = setOf("dns_monitor", "network_monitor", "security_log")

    /**
     * ALERT iff [service] is always-event, or [matchContext] holds its [eventTimeField] as a number
     * > 0; otherwise STATE. A finding with no service (an unknown rule) is STATE.
     */
    fun noFact(service: String?, eventTimeField: String?, matchContext: Map<String, String>): FindingKind {
        if (service == null) return FindingKind.STATE
        val event = service in ALWAYS_EVENT || eventTime(eventTimeField, matchContext) != null
        return if (event) FindingKind.ALERT else FindingKind.STATE
    }

    /** The event time [noFact] reads from [matchContext] (null when absent, unparsable or ≤ 0). */
    fun eventTime(eventTimeField: String?, matchContext: Map<String, String>): Long? =
        eventTimeField?.let { matchContext[it]?.toLongOrNull() }?.takeIf { it > 0L }
}
