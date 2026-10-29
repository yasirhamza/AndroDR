package com.androdr.scanner.bugreport

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.File
import java.time.ZoneId

class DumpsysSectionParserTest {

    private val parser = DumpsysSectionParser()

    private fun streamOf(text: String) =
        ByteArrayInputStream(text.toByteArray(Charsets.UTF_8))

    @Test
    fun `extracts section with DUMP OF SERVICE header`() {
        val dumpstate = """
            Some preamble text
            -------------------------------------------------------------------------------
            DUMP OF SERVICE accessibility:
            enabled services:
              com.evil.spy/.SpyService
            -------------------------------------------------------------------------------
            DUMP OF SERVICE package:
            Packages:
              Package [com.example]
        """.trimIndent()

        val section = parser.extractSection(streamOf(dumpstate), "accessibility")
        assertNotNull(section)
        assertTrue(section!!.contains("com.evil.spy/.SpyService"))
        assertTrue(!section.contains("Package [com.example]"))
    }

    @Test
    fun `extracts section with dashed SERVICE header format`() {
        val dumpstate = """
            ---------- SERVICE accessibility ----------
            enabled services:
              com.evil.spy/.SpyService
            ---------- SERVICE package ----------
            Packages:
              Package [com.example]
        """.trimIndent()

        val section = parser.extractSection(streamOf(dumpstate), "accessibility")
        assertNotNull(section)
        assertTrue(section!!.contains("com.evil.spy/.SpyService"))
    }

    @Test
    fun `returns null for missing section`() {
        val dumpstate = """
            DUMP OF SERVICE package:
            Packages:
              Package [com.example]
        """.trimIndent()

        val section = parser.extractSection(streamOf(dumpstate), "nonexistent")
        assertNull(section)
    }

    @Test
    fun `extracts last section (no trailing delimiter)`() {
        val dumpstate = """
            DUMP OF SERVICE package:
            Packages:
              Package [com.example]
            DUMP OF SERVICE appops:
            Uid 10050:
              CAMERA: allow
        """.trimIndent()

        val section = parser.extractSection(streamOf(dumpstate), "appops")
        assertNotNull(section)
        assertTrue(section!!.contains("CAMERA: allow"))
    }

    @Test
    fun `extractSections returns multiple sections in one pass`() {
        val dumpstate = """
            DUMP OF SERVICE accessibility:
            service1
            DUMP OF SERVICE package:
            packages here
            DUMP OF SERVICE appops:
            ops here
        """.trimIndent()

        val sections = parser.extractSections(
            streamOf(dumpstate),
            setOf("accessibility", "appops")
        )

        assertEquals(2, sections.size)
        assertTrue(sections["accessibility"]!!.contains("service1"))
        assertTrue(sections["appops"]!!.contains("ops here"))
        assertNull(sections["package"])
    }

    @Test
    fun `extractSections handles missing requested sections gracefully`() {
        val dumpstate = """
            DUMP OF SERVICE package:
            packages here
        """.trimIndent()

        val sections = parser.extractSections(
            streamOf(dumpstate),
            setOf("accessibility", "package")
        )

        assertEquals(1, sections.size)
        assertNotNull(sections["package"])
        assertNull(sections["accessibility"])
    }

    @Test
    fun `extractSystemProperties returns properties section`() {
        val dumpstate = """
            some header
            ------ SYSTEM PROPERTIES ------
            [ro.build.version.sdk]: [34]
            [ro.build.display.id]: [AP1A.240305.019]
            ------ SECTION AFTER ------
            other stuff
        """.trimIndent()

        val props = parser.extractSystemProperties(streamOf(dumpstate))
        assertNotNull(props)
        assertTrue(props!!.contains("ro.build.version.sdk"))
        assertTrue(!props.contains("other stuff"))
    }

    private fun realFormatText(): String {
        val name = "fixtures/bugreport-real-format-headers.txt"
        return listOf(File("src/test/resources/$name"), File("app/src/test/resources/$name"))
            .first { it.isFile }.readText()
    }

    /**
     * Real dumpstate titles a RunCommand section with its command in parentheses:
     * `------ SYSTEM PROPERTIES (getprop) ------` (F916B, API 33). The parser matched only the
     * synthetic `------ SYSTEM PROPERTIES ------`, so no real report ever yielded its properties
     * (source device UNKNOWN, no snapshots, clock assumed UTC). Battery finding B6.
     */
    @Test
    fun `real SYSTEM PROPERTIES (getprop) header yields the properties up to the duration line`() {
        val props = parser.extractSystemProperties(streamOf(realFormatText()))
        assertNotNull("real getprop header not recognised", props)
        assertTrue(props!!.contains("[persist.sys.timezone]: [Asia/Qatar]"))
        assertTrue(props.contains("[wlan.driver.status]: [ok]"))
        assertTrue("stops at the duration line", !props.contains("was the duration"))
        assertTrue("stops before the next section", !props.contains("vmap"))

        val clock = DumpsysClock.fromSystemProperties(props)
        assertEquals(ZoneId.of("Asia/Qatar"), clock.zone)
        assertTrue(!clock.assumedUtc)
        assertEquals("samsung" to "samsung", GetpropParser().extractManufacturerAndBrand(props.lineSequence()))
        assertEquals(9, GetpropParser().parse(props.lineSequence(), capturedAt = 0L).size)
    }

    @Test
    fun `any parenthesised command suffix on the SYSTEM PROPERTIES title is accepted`() {
        val text = "------ SYSTEM PROPERTIES (/system/bin/getprop -Z) ------\n[a.b]: [c]\n------ X ------\n"
        assertEquals("[a.b]: [c]\n", parser.extractSystemProperties(streamOf(text)))
    }

    @Test
    fun `the SYSTEM PROPERTIES duration line alone does not open the section`() {
        val text = "------ 0.053s was the duration of 'SYSTEM PROPERTIES' ------\n[a.b]: [c]\n"
        assertNull(parser.extractSystemProperties(streamOf(text)))
    }

    @Test
    fun `empty stream returns null`() {
        val section = parser.extractSection(streamOf(""), "accessibility")
        assertNull(section)
    }

    @Test
    fun `section with only whitespace content is returned`() {
        val dumpstate = """
            DUMP OF SERVICE accessibility:

            DUMP OF SERVICE package:
            stuff
        """.trimIndent()

        val section = parser.extractSection(streamOf(dumpstate), "accessibility")
        assertNotNull(section)
    }
}
