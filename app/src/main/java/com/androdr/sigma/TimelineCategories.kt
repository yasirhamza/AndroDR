package com.androdr.sigma

/**
 * The timeline category of a telemetry record (spec §4.3).
 *
 * Categories are a detection contract: atom rules bind to them by exact
 * equality, so these values preserve what the timeline writes today
 * (TimelineAdapter, UsageStatsScanner, AppOpsModule, InstallTimeModule,
 * BatteryDailyModule). Gate K1 checks every atom category has a producer;
 * gate X1 pins the outputs.
 */
object TimelineCategories {

    private const val EVENT_TYPE = "event_type"

    /**
     * Category for one record of [service]. Services outside the table
     * (snapshot services, tombstones, wakelocks) use the service name.
     */
    fun categoryOf(service: String, fields: Map<String, Any?>): String = when (service) {
        "usage_stats", "battery_daily" -> fields[EVENT_TYPE]?.toString() ?: service
        "appops_audit" -> "permission_use"
        "package_install_history" -> "package_install"
        "network_monitor" -> "network_connect"
        "security_log" -> "security_event"
        "dns_monitor" -> if (fields["reason"] != null) "ioc_match" else "dns_query"
        else -> service
    }
}
