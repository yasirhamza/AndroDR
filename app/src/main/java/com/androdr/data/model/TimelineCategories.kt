package com.androdr.data.model

/**
 * Every value AndroDR writes to [ForensicTimelineEvent.category].
 *
 * Atom rules bind timeline events by exact equality on this field, and a rule
 * naming a value nothing writes binds to nothing: `androdr-atom-dns-lookup`
 * selected `dns_match` for five months while producers wrote `ioc_match`, so
 * androdr-corr-003 could never fire and every test stayed green (#378). This set
 * is the vocabulary atoms are checked against, in AndroDR CI, for both the
 * bundled rules and the rules-repo copy pinned by the submodule -- so a typo in
 * either fails before it reaches a device.
 *
 * Kept honest by AtomCategoriesAreProducedTest: every value here must appear as
 * a literal in a file that builds timeline rows, so the set cannot quietly hold
 * a value no producer writes any more.
 */
object TimelineCategories {
    val PRODUCED: Set<String> = setOf(
        // DnsEvent -> timeline (TimelineAdapter): matched vs not
        "dns_query", "ioc_match",
        // intrusion-log import (TimelineAdapter)
        "network_connect", "security_event",
        // findings and correlation signals written to the timeline
        "app_risk", "device_posture", "correlation",
        // scan-time install emitter, bug-report install history
        "package_install",
        // bug-report battery history
        "package_uninstall", "package_update", "package_downgrade",
        // live package broadcasts (PackageLifecycleReceiver)
        "package_installed", "package_updated", "package_removed",
        // DeviceAdminGrantEmitter
        "device_admin_grant",
        // bug-report AppOps history -- no live producer (#370)
        "permission_use",
        // bug-report adb keys
        "adb_trusted_key",
        // UsageStatsScanner
        "app_foreground", "app_background",
    )
}
