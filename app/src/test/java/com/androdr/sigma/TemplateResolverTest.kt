package com.androdr.sigma

import org.junit.Assert.assertEquals
import org.junit.Test

class TemplateResolverTest {

    @Test
    fun `resolves single variable`() {
        val result = TemplateResolver.resolve("{count} Unpatched CVEs", mapOf("count" to "12"))
        assertEquals("12 Unpatched CVEs", result)
    }

    @Test
    fun `resolves multiple variables`() {
        val result = TemplateResolver.resolve(
            "{count} unpatched · {campaign_count} linked to spyware",
            mapOf("count" to "12", "campaign_count" to "3")
        )
        assertEquals("12 unpatched · 3 linked to spyware", result)
    }

    @Test
    fun `leaves unresolved variables as-is`() {
        val result = TemplateResolver.resolve("{count} CVEs ({unknown})", mapOf("count" to "5"))
        assertEquals("5 CVEs ({unknown})", result)
    }

    @Test
    fun `handles empty template`() {
        assertEquals("", TemplateResolver.resolve("", mapOf("count" to "5")))
    }

    @Test
    fun `handles no variables in template`() {
        assertEquals("No variables here", TemplateResolver.resolve("No variables here", emptyMap()))
    }

    @Test
    fun `resolves list of strings`() {
        val templates = listOf("Update to {target_patch_level} or later.", "Run a scan.")
        val vars = mapOf("target_patch_level" to "2025-03-01")
        val result = TemplateResolver.resolveAll(templates, vars)
        assertEquals("Update to 2025-03-01 or later.", result[0])
        assertEquals("Run a scan.", result[1])
    }
}
