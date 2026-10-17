package com.androdr.reporting

import com.androdr.data.model.NotEvaluatedReason
import com.androdr.data.model.ScannerFailure
import com.androdr.scanner.MISSING_SOURCE_MVT
import com.androdr.scanner.MISSING_SOURCE_RULES_REPO
import org.junit.Assert.assertEquals
import org.junit.Test

class CampaignCoverageTest {

    private fun sentinel(reason: NotEvaluatedReason, scanner: String = "x", ruleId: String? = null) =
        ScannerFailure(scanner = scanner, exception = reason.sentinel, message = "m", ruleId = ruleId)
    private fun crash(scanner: String) =
        ScannerFailure(scanner = scanner, exception = "IllegalStateException", message = "boom")
    private fun one(service: String, errors: List<ScannerFailure>, key: String = "predator",
                    ruleCampaigns: Map<String, Set<String>> = emptyMap()) =
        campaignCoverage(listOf(service), key, errors, ruleCampaigns).single()

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
    fun `crash beats feeds not loaded`() {
        assertEquals(ServiceCoverage.BLIND,
            one("app_scanner", listOf(crash("appScanner"), sentinel(NotEvaluatedReason.FEEDS_NOT_LOADED))).coverage)
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
            one("file_scanner", listOf(e), ruleCampaigns = mapOf("androdr-108" to setOf("predator"))).coverage)
    }

    @Test
    fun `unreadable paths of another campaign's rule do not count`() {
        val e = sentinel(NotEvaluatedReason.UNREADABLE_PATHS, "file_scanner", ruleId = "androdr-108")
        assertEquals(ServiceCoverage.CHECKED,
            one("file_scanner", listOf(e), key = "pegasus",
                ruleCampaigns = mapOf("androdr-108" to setOf("predator"))).coverage)
        assertEquals(ServiceCoverage.CHECKED, one("file_scanner", listOf(e), ruleCampaigns = emptyMap()).coverage)
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
