package com.androdr.reporting

import com.androdr.sigma.RuleCoverage

/**
 * What a timeline event category is called in a sentence a reader can act on.
 *
 * Presentation, deliberately: the categories themselves are the detection
 * vocabulary (`logsource-taxonomy.yml`, cross-checked by
 * `LogsourceTaxonomyCrossCheckTest`), and rules carrying new ones reach the app
 * from the rules repo every 12 hours without an app release. So an unknown
 * category must degrade to something true -- it names the category rather than
 * claiming the build does not record it, because the build may well record it
 * and only this wording table be behind.
 */
internal fun evidenceName(category: String): String = when (category) {
    RuleCoverage.UNBOUND_LEG -> "an event kind no loaded rule binds to"
    "permission_use" ->
        "records of apps using sensitive permissions (only an imported bug report carries these)"
    "package_install" -> "app installations"
    "package_uninstall" -> "app removals"
    "package_update" -> "app updates"
    "package_downgrade" -> "app downgrades"
    "device_admin_grant" -> "device-administrator grants"
    "app_foreground" -> "app launches"
    "adb_trusted_key" -> "trusted USB debugging keys"
    "dns_query" -> "DNS lookups"
    "ioc_match" -> "DNS lookups that matched a threat list"
    "network_connect" -> "network connections"
    "security_event" -> "device security events"
    else -> "events recorded as '$category'"
}
