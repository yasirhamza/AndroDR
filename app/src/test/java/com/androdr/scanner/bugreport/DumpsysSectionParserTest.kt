package com.androdr.scanner.bugreport

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream

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
