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

    private fun sentinel(reason: NotEvaluatedReason, scanner: String = "x", ruleId: String? = null) =
        ScannerFailure(scanner = scanner, exception = reason.sentinel, message = "m", ruleId = ruleId)
    private fun crash(scanner: String) =
        ScannerFailure(scanner = scanner, exception = "IllegalStateException", message = "boom")
    private fun one(
        service: String,
        errors: List<ScannerFailure>,
        key: String = "predator",
        rules: Map<String, RuleScope> = emptyMap(),
    ) = campaignCoverage(listOf(service), key, errors, rules).single()

    @Test
    fun `nothing recorded means every service was checked`() {
        assertEquals(
            listOf(
                ServiceStatus("dns_monitor", ServiceCoverage.CHECKED),
                ServiceStatus("file_scanner", ServiceCoverage.CHECKED),
            ),
            campaignCoverage(listOf("dns_monitor", "file_scanner"), "predator", emptyList(), emptyMap()),
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
            one("file_scanner", listOf(e), key = "pegasus", rules = predatorFileRule).coverage)
        assertEquals(ServiceCoverage.CHECKED, one("file_scanner", listOf(e), rules = emptyMap()).coverage)
    }

    @Test
    fun `unreadable paths of a rule on another service do not count`() {
        val e = sentinel(NotEvaluatedReason.UNREADABLE_PATHS, "file_scanner", ruleId = "androdr-108")
        assertEquals(ServiceCoverage.CHECKED, one("app_scanner", listOf(e), rules = predatorFileRule).coverage)
    }

    @Test
    fun `missing capability for a rule tagged with this campaign is partly skipped`() {
        val e = sentinel(NotEvaluatedReason.MISSING_CAPABILITY, "file_scanner", ruleId = "androdr-108")
        assertEquals(ServiceCoverage.PARTLY_SKIPPED, one("file_scanner", listOf(e), rules = predatorFileRule).coverage)
        assertEquals(ServiceCoverage.CHECKED,
            one("file_scanner", listOf(e), key = "pegasus", rules = predatorFileRule).coverage)
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
    }

    @Test
    fun `patch level only campaign has no services`() {
        assertEquals(emptyList<ServiceStatus>(), campaignCoverage(emptyList(), "landfall", emptyList(), emptyMap()))
    }
}
