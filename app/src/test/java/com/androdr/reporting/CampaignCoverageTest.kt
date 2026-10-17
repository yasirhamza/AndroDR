package com.androdr.reporting

import com.androdr.data.model.MISSING_SOURCE_MVT
import com.androdr.data.model.MISSING_SOURCE_RULES_REPO
import com.androdr.data.model.NotEvaluatedReason
import com.androdr.data.model.ScannerFailure
import org.junit.Assert.assertEquals
import org.junit.Test

class CampaignCoverageTest {

    private val predatorFileRule = mapOf("androdr-108" to RuleScope("file_scanner", setOf("predator"), false))
    private val iocRule = mapOf("androdr-003" to RuleScope("dns_monitor", emptySet(), true))
    private val pegasusFileRule = mapOf("androdr-900" to RuleScope("file_scanner", setOf("pegasus"), false))

    /** A detector for every campaign on the list services, and for predator on files. */
    private val coveringAll = mapOf(
        "androdr-001" to RuleScope("app_scanner", emptySet(), true),
        "androdr-003" to RuleScope("dns_monitor", emptySet(), true),
        "androdr-108" to RuleScope("file_scanner", setOf("predator"), false),
    )

    private fun sentinel(reason: NotEvaluatedReason, scanner: String = "x", ruleId: String? = null) =
        ScannerFailure(scanner = scanner, exception = reason.sentinel, message = "m", ruleId = ruleId)
    private fun crash(scanner: String) =
        ScannerFailure(scanner = scanner, exception = "IllegalStateException", message = "boom")
    private fun one(
        service: String,
        errors: List<ScannerFailure>,
        key: String = "predator",
        rules: Map<String, RuleScope> = coveringAll,
    ) = campaignCoverage(listOf(service), key, errors, rules).single()

    @Test
    fun `nothing recorded means every service was checked`() {
        assertEquals(
            listOf(
                ServiceStatus("dns_monitor", ServiceCoverage.CHECKED),
                ServiceStatus("file_scanner", ServiceCoverage.CHECKED),
            ),
            campaignCoverage(listOf("dns_monitor", "file_scanner"), "predator", emptyList(), coveringAll),
        )
    }

    @Test
    fun `dns monitor off is blind with the dns reason`() {
        assertEquals(ServiceStatus("dns_monitor", ServiceCoverage.BLIND, BlindReason.DNS_OFF),
            one("dns_monitor", listOf(sentinel(NotEvaluatedReason.DNS_MONITOR_OFF, "dns_monitor"))))
    }

    @Test
    fun `dns monitor off wins over a failed dns snapshot read`() {
        assertEquals(ServiceStatus("dns_monitor", ServiceCoverage.BLIND, BlindReason.DNS_OFF),
            one("dns_monitor", listOf(sentinel(NotEvaluatedReason.DNS_MONITOR_OFF, "dns_monitor"),
                crash(DNS_SNAPSHOT_SCANNER))))
    }

    @Test
    fun `a failed dns snapshot read is blind with the failure reason`() {
        assertEquals(ServiceStatus("dns_monitor", ServiceCoverage.BLIND, BlindReason.CHECK_FAILED),
            one("dns_monitor", listOf(crash(DNS_SNAPSHOT_SCANNER))))
    }

    @Test
    fun `a crashed scanner makes its service blind`() {
        assertEquals(ServiceStatus("app_scanner", ServiceCoverage.BLIND, BlindReason.CHECK_FAILED),
            one("app_scanner", listOf(crash("appScanner"))))
    }

    @Test
    fun `a sentinel recorded under a scanner name is not a crash`() {
        assertEquals(ServiceCoverage.BUILT_IN_LISTS_ONLY,
            one("app_scanner", listOf(sentinel(NotEvaluatedReason.FEEDS_NOT_LOADED, "appScanner"))).coverage)
    }

    @Test
    fun `crash beats feeds not loaded`() {
        assertEquals(ServiceCoverage.BLIND,
            one("app_scanner", listOf(crash("appScanner"), sentinel(NotEvaluatedReason.FEEDS_NOT_LOADED))).coverage)
    }

    @Test
    fun `a crash beats a skipped rule that counts`() {
        val skipped = sentinel(NotEvaluatedReason.MISSING_CAPABILITY, "appScanner", ruleId = "androdr-200")
        assertEquals(ServiceStatus("app_scanner", ServiceCoverage.BLIND, BlindReason.CHECK_FAILED),
            one("app_scanner", listOf(crash("appScanner"), skipped),
                rules = mapOf("androdr-200" to RuleScope("app_scanner", setOf("predator"), false))))
    }

    @Test
    fun `missing MVT only marks DNS built-in-only, not installed apps`() {
        val mvtOnly = ScannerFailure("threat_intel", NotEvaluatedReason.CAMPAIGN_SOURCES_NOT_LOADED.sentinel, "m",
            missingSources = listOf(MISSING_SOURCE_MVT))
        assertEquals(ServiceCoverage.BUILT_IN_LISTS_ONLY, one("dns_monitor", listOf(mvtOnly)).coverage)
        assertEquals(ServiceCoverage.CHECKED, one("app_scanner", listOf(mvtOnly)).coverage)
        val repo = mvtOnly.copy(missingSources = listOf(MISSING_SOURCE_RULES_REPO))
        assertEquals(ServiceCoverage.BUILT_IN_LISTS_ONLY, one("app_scanner", listOf(repo)).coverage)
    }

    @Test
    fun `campaign sources listing both sources leave both list services built-in-only`() {
        val both = ScannerFailure("threat_intel", NotEvaluatedReason.CAMPAIGN_SOURCES_NOT_LOADED.sentinel, "m",
            missingSources = listOf(MISSING_SOURCE_RULES_REPO, MISSING_SOURCE_MVT))
        assertEquals(ServiceCoverage.BUILT_IN_LISTS_ONLY, one("dns_monitor", listOf(both)).coverage)
        assertEquals(ServiceCoverage.BUILT_IN_LISTS_ONLY, one("app_scanner", listOf(both)).coverage)
    }

    @Test
    fun `feeds or campaign sources not loaded leave the list services on the built-in lists`() {
        listOf(NotEvaluatedReason.FEEDS_NOT_LOADED, NotEvaluatedReason.CAMPAIGN_SOURCES_NOT_LOADED).forEach { r ->
            assertEquals(r.name, ServiceCoverage.BUILT_IN_LISTS_ONLY, one("dns_monitor", listOf(sentinel(r))).coverage)
            assertEquals(r.name, ServiceCoverage.BUILT_IN_LISTS_ONLY, one("app_scanner", listOf(sentinel(r))).coverage)
            assertEquals(r.name, ServiceCoverage.CHECKED, one("file_scanner", listOf(sentinel(r))).coverage)
        }
    }

    @Test
    fun `unreadable paths of this campaign's rule leave files partly checked`() {
        val e = sentinel(NotEvaluatedReason.UNREADABLE_PATHS, "file_scanner", ruleId = "androdr-108")
        assertEquals(ServiceCoverage.PARTLY_UNREADABLE,
            one("file_scanner", listOf(e), rules = predatorFileRule).coverage)
    }

    @Test
    fun `unreadable paths of another campaign's rule do not count`() {
        val e = sentinel(NotEvaluatedReason.UNREADABLE_PATHS, "file_scanner", ruleId = "androdr-108")
        assertEquals(ServiceCoverage.CHECKED,
            one("file_scanner", listOf(e), key = "pegasus", rules = predatorFileRule + pegasusFileRule).coverage)
        val otherPredatorRule = mapOf("androdr-901" to RuleScope("file_scanner", setOf("predator"), false))
        assertEquals(ServiceCoverage.CHECKED, one("file_scanner", listOf(e), rules = otherPredatorRule).coverage)
    }

    @Test
    fun `unreadable paths of a rule on another service do not count`() {
        val e = sentinel(NotEvaluatedReason.UNREADABLE_PATHS, "file_scanner", ruleId = "androdr-108")
        assertEquals(ServiceCoverage.CHECKED, one("app_scanner", listOf(e), rules = coveringAll).coverage)
    }

    @Test
    fun `missing capability for a rule tagged with this campaign is partly skipped`() {
        val e = sentinel(NotEvaluatedReason.MISSING_CAPABILITY, "file_scanner", ruleId = "androdr-108")
        assertEquals(ServiceCoverage.PARTLY_SKIPPED, one("file_scanner", listOf(e), rules = predatorFileRule).coverage)
        assertEquals(ServiceCoverage.CHECKED,
            one("file_scanner", listOf(e), key = "pegasus", rules = predatorFileRule + pegasusFileRule).coverage)
    }

    @Test
    fun `missing capability for an ioc match rule is partly skipped for any campaign`() {
        val e = sentinel(NotEvaluatedReason.MISSING_CAPABILITY, "dnsSnapshot", ruleId = "androdr-003")
        assertEquals(ServiceCoverage.PARTLY_SKIPPED, one("dns_monitor", listOf(e), rules = iocRule).coverage)
        assertEquals(ServiceCoverage.PARTLY_SKIPPED,
            one("dns_monitor", listOf(e), key = "pegasus", rules = iocRule).coverage)
    }

    @Test
    fun `missing capability for a rule this build does not have counts for no campaign`() {
        val e = sentinel(NotEvaluatedReason.MISSING_CAPABILITY, "file_scanner", ruleId = "androdr-999")
        assertEquals(ServiceCoverage.CHECKED, one("file_scanner", listOf(e), rules = predatorFileRule).coverage)
    }

    @Test
    fun `a failed attribution lookup blinds dns monitor and not installed apps`() {
        val attribution = crash("attribution")
        assertEquals(ServiceStatus("dns_monitor", ServiceCoverage.BLIND, BlindReason.ATTRIBUTION_FAILED),
            one("dns_monitor", listOf(attribution)))
        assertEquals(ServiceCoverage.CHECKED, one("app_scanner", listOf(attribution)).coverage)
    }

    @Test
    fun `a failed feed state query leaves both list services unknown and files checked`() {
        val gaps = crash("visibility_gaps")
        assertEquals(ServiceCoverage.LISTS_UNKNOWN, one("dns_monitor", listOf(gaps)).coverage)
        assertEquals(ServiceCoverage.LISTS_UNKNOWN, one("app_scanner", listOf(gaps)).coverage)
        assertEquals(ServiceCoverage.CHECKED, one("file_scanner", listOf(gaps)).coverage)
    }

    @Test
    fun `an import-only service needs an import`() {
        assertEquals(ServiceStatus("security_log", ServiceCoverage.NEEDS_IMPORT), one("security_log", emptyList()))
    }

    @Test
    fun `unknown service is blind`() {
        assertEquals(ServiceStatus("usage_stats", ServiceCoverage.BLIND, BlindReason.UNKNOWN_SERVICE),
            one("usage_stats", emptyList()))
        // CampaignRegistry turns an invalid detected_by value into this; it must stay unknown to every map.
        assertEquals(ServiceStatus("unknown", ServiceCoverage.BLIND, BlindReason.UNKNOWN_SERVICE),
            one("unknown", emptyList()))
    }

    // -- NO_DETECTOR: a service counts as checked only if a loaded, enabled rule can detect the campaign on it --

    @Test
    fun `no loaded rule for the service means no detector`() {
        assertEquals(ServiceStatus("file_scanner", ServiceCoverage.NO_DETECTOR),
            one("file_scanner", emptyList(), rules = iocRule))
    }

    @Test
    fun `a tagged rule is a detector for its own campaign only`() {
        assertEquals(ServiceCoverage.CHECKED, one("file_scanner", emptyList(), rules = predatorFileRule).coverage)
        assertEquals(ServiceCoverage.NO_DETECTOR,
            one("file_scanner", emptyList(), key = "pegasus", rules = predatorFileRule).coverage)
    }

    @Test
    fun `an ioc-carrying rule is a detector for any campaign`() {
        assertEquals(ServiceCoverage.CHECKED, one("dns_monitor", emptyList(), rules = iocRule).coverage)
        assertEquals(ServiceCoverage.CHECKED,
            one("dns_monitor", emptyList(), key = "pegasus", rules = iocRule).coverage)
    }

    @Test
    fun `a rule on another service is not a detector`() {
        assertEquals(ServiceCoverage.NO_DETECTOR, one("dns_monitor", emptyList(), rules = predatorFileRule).coverage)
        assertEquals(ServiceCoverage.NO_DETECTOR, one("app_scanner", emptyList(), rules = iocRule).coverage)
    }

    @Test
    fun `no loaded rules at all - no listed service reads checked`() {
        val services = listOf("dns_monitor", "app_scanner", "file_scanner")
        assertEquals(services.map { ServiceStatus(it, ServiceCoverage.NO_DETECTOR) },
            campaignCoverage(services, "predator", emptyList(), emptyMap()))
    }

    @Test
    fun `a crashed scanner beats no detector`() {
        assertEquals(ServiceStatus("app_scanner", ServiceCoverage.BLIND, BlindReason.CHECK_FAILED),
            one("app_scanner", listOf(crash("appScanner")), rules = emptyMap()))
    }

    @Test
    fun `no detector beats lists unknown and built-in lists only`() {
        assertEquals(ServiceCoverage.NO_DETECTOR,
            one("dns_monitor", listOf(crash("visibility_gaps")), rules = emptyMap()).coverage)
        assertEquals(ServiceCoverage.NO_DETECTOR,
            one("dns_monitor", listOf(sentinel(NotEvaluatedReason.FEEDS_NOT_LOADED)), rules = emptyMap()).coverage)
    }

    @Test
    fun `an import-only service still needs an import with no rules loaded`() {
        assertEquals(ServiceCoverage.NEEDS_IMPORT, one("security_log", emptyList(), rules = emptyMap()).coverage)
    }

    @Test
    fun `patch level only campaign has no services`() {
        assertEquals(emptyList<ServiceStatus>(), campaignCoverage(emptyList(), "landfall", emptyList(), emptyMap()))
    }
}
