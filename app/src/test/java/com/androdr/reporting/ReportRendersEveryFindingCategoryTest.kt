package com.androdr.reporting

import com.androdr.data.model.ScanResult
import com.androdr.sigma.Finding
import com.androdr.sigma.FindingCategory
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Every display bucket must have a place in the report. A [FindingCategory] value
 * with no renderer is a bucket a finding can be filed into and never seen -- which
 * is what `network` was: allowed by the schema, mapped by the parser, rendered by
 * nothing. This test makes adding a bucket without a section a build failure.
 */
class ReportRendersEveryFindingCategoryTest {

    @Test
    fun `a triggered finding of every category appears in the findings section`() {
        FindingCategory.values().forEach { category ->
            val marker = "PROBE-${category.name}-FINDING"
            val finding = Finding(
                ruleId = "androdr-probe-${category.name.lowercase()}",
                title = marker,
                level = "high",
                category = category,
                triggered = true,
                matchContext = mapOf("package_name" to "com.example.probe"),
            )
            val scan = ScanResult(
                id = 1L,
                timestamp = 1711900800000,
                findings = listOf(finding),
                bugReportFindings = emptyList(),
                riskySideloadCount = 0,
                knownMalwareCount = 0,
                scannerErrors = emptyList(),
            )

            val findingsSection = ReportFormatter.formatScanReport(
                scan, emptyList(), emptyList(), versionName = "test", mode = ExportMode.FINDINGS_ONLY,
            )

            assertTrue(
                "FindingCategory.$category has no renderer: '$marker' is absent from the findings section",
                findingsSection.contains(marker),
            )
        }
    }
}
