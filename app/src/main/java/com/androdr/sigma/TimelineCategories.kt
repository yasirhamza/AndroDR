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
     * Only an INSTALL was ever a legacy `package_install` row; an update or uninstall gets its own
     * category, so it is never an install atom (ruling R26).
     */
    private fun installHistoryCategory(eventType: String?): String = when (eventType) {
        "INSTALL" -> "package_install"
        "UPDATE" -> "package_update"
        "UNINSTALL" -> "package_uninstall"
        else -> "package_install_history"
    }

    /**
     * Category for one record of [service]. Services outside the table
     * (snapshot services, tombstones, wakelocks) use the service name.
     */
    fun categoryOf(service: String, fields: Map<String, Any?>): String = when (service) {
        "usage_stats", "battery_daily" -> fields[EVENT_TYPE]?.toString() ?: service
        // System-UID ops never got a legacy timeline row: their own category, so they are not
        // permission_use atoms (ruling R26; spec §4.3).
        "appops_audit" -> if (fields["is_system_app"] == true) "system_permission_use" else "permission_use"
        "package_install_history" -> installHistoryCategory(fields[EVENT_TYPE]?.toString())
        "network_monitor" -> "network_connect"
        "security_log" -> "security_event"
        "dns_monitor" -> if (fields["reason"] != null) "ioc_match" else "dns_query"
        else -> service
    }
}
