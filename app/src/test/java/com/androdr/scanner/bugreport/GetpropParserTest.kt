package com.androdr.scanner.bugreport

import com.androdr.data.model.TelemetrySource
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class GetpropParserTest {

    private val parser = GetpropParser()

    @Test
    fun `parses bracket format getprop lines`() {
        val lines = """
            [ro.product.manufacturer]: [Samsung]
            [ro.product.brand]: [samsung]
            [ro.build.fingerprint]: [samsung/a51/a51:11/...]
        """.trimIndent().lines().asSequence()

        val result = parser.parse(lines, capturedAt = 1000L)

        assertEquals(3, result.size)
        assertEquals("ro.product.manufacturer", result[0].key)
        assertEquals("Samsung", result[0].value)
        assertEquals(TelemetrySource.BUGREPORT_IMPORT, result[0].source)
        assertEquals(1000L, result[0].capturedAt)
    }

    @Test
    fun `parses equals format getprop lines`() {
        val lines = """
            ro.product.manufacturer=Samsung
            ro.product.brand=samsung
        """.trimIndent().lines().asSequence()

        val result = parser.parse(lines, capturedAt = 2000L)

        assertEquals(2, result.size)
        assertEquals("ro.product.manufacturer", result[0].key)
        assertEquals("Samsung", result[0].value)
    }

    @Test
    fun `ignores non-getprop lines`() {
        val lines = """
            Some garbage text
            [ro.product.manufacturer]: [Samsung]
            more garbage
            --- section separator ---
            [ro.product.brand]: [samsung]
        """.trimIndent().lines().asSequence()

        val result = parser.parse(lines, capturedAt = 0L)

        assertEquals(2, result.size)
    }

    @Test
    fun `extractManufacturerAndBrand finds both from bracket format`() {
        val lines = """
            Some header text
            [ro.product.manufacturer]: [Google]
            [ro.product.brand]: [google]
            [other.key]: [value]
        """.trimIndent().lines().asSequence()

        val (manufacturer, brand) = parser.extractManufacturerAndBrand(lines)
        assertEquals("Google", manufacturer)
        assertEquals("google", brand)
    }

    @Test
    fun `extractManufacturerAndBrand returns empty strings when missing`() {
        val lines = "no property here".lines().asSequence()
        val (manufacturer, brand) = parser.extractManufacturerAndBrand(lines)
        assertEquals("", manufacturer)
        assertEquals("", brand)
    }

    @Test
    fun `extractManufacturerAndBrand works with brand different from manufacturer`() {
        val lines = """
            [ro.product.manufacturer]: [Xiaomi]
            [ro.product.brand]: [Redmi]
        """.trimIndent().lines().asSequence()
        val (manufacturer, brand) = parser.extractManufacturerAndBrand(lines)
        assertEquals("Xiaomi", manufacturer)
        assertEquals("Redmi", brand)
    }

    @Test
    fun `parse handles empty sequence`() {
        val result = parser.parse(emptySequence(), capturedAt = 0L)
        assertTrue(result.isEmpty())
    }
}
