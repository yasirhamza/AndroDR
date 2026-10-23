package com.androdr.reporting

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * R2 (spec §7): every report goes through [ReportExporter]. The History sheet, the debug harness
 * receiver and the exporter each used to assemble their own report from their own inputs, and the
 * telemetry they printed came from `ScanOrchestrator`'s last-scan caches -- so an older scan's
 * report showed whatever the most recent scan had collected. The caches are gone and the
 * formatter has exactly one caller.
 */
class SingleReportPathTest {

    private val roots: List<File> = listOf("src/main/java", "src/debug/java").map { rel ->
        listOf(File(rel), File("app/$rel")).first { it.isDirectory }
    }

    private val sources: List<File> by lazy {
        roots.flatMap { root -> root.walkTopDown().filter { it.isFile && it.extension == "kt" }.toList() }
    }

    @Test
    fun `the sources are found`() {
        assertTrue(sources.any { it.name == "ReportExporter.kt" })
        assertTrue(sources.any { it.name == "ReportFormatter.kt" })
    }

    @Test
    fun `writeScanReport is called only from ReportExporter`() {
        val callers = sources.filter { file ->
            file.readLines().any { "writeScanReport(" in it && "fun writeScanReport(" !in it }
        }.map { it.name }
        assertEquals(listOf("ReportExporter.kt"), callers)
    }

    @Test
    fun `no last-scan telemetry cache or old report entry point remains`() {
        val cache = Regex("""\blast[A-Za-z]*Telemetry""")
        val banned = listOf("APP_TELEMETRY_CACHE_MAX_AGE_MS", "formatScanReport", "INTRUSION_ROW_LIMIT")
        val offenders = sources.flatMap { file ->
            file.readLines().mapIndexedNotNull { i, line ->
                val hit = cache.containsMatchIn(line) || banned.any { it in line }
                if (hit) "${file.name}:${i + 1}: ${line.trim()}" else null
            }
        }
        assertTrue(offenders.joinToString("\n"), offenders.isEmpty())
    }
}
