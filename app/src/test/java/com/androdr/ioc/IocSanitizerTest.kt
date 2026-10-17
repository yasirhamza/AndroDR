package com.androdr.ioc

import com.androdr.data.model.Indicator
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

class IocSanitizerTest {
    private fun ind(
        family: String = "F", category: String = "", key: String = "", reference: String = "", description: String = "",
    ) = Indicator(type = "domain", value = "x.com", family = family, category = category, campaignKey = key,
        description = description, reference = reference, source = "s", fetchedAt = 0L)

    private fun schemaFile() = listOf(
        File("third-party/android-sigma-rules/validation/ioc-entry-schema.json"),
        File("../third-party/android-sigma-rules/validation/ioc-entry-schema.json"),
    ).first { it.isFile }

    @Test
    fun `CATEGORIES equals the category enum of the pinned ioc-entry schema`() {
        val enum = JSONObject(schemaFile().readText()).getJSONObject("\$defs").getJSONObject("threatIocEntry")
            .getJSONObject("properties").getJSONObject("category").getJSONArray("enum")
        val fromSchema = (0 until enum.length()).map { enum.getString(it) }.toSet()
        assertEquals(fromSchema, IocSanitizer.CATEGORIES)
    }

    @Test
    fun `newline in family is stripped`() {
        val out = IocSanitizer.sanitize(ind(family = "X\n  [!!]  Pegasus: DETECTED")).family
        assertFalse(out.contains('\n'))
    }

    @Test
    fun `bidi, zero-width, line separator and lone surrogate are stripped`() {
        val out = IocSanitizer.sanitize(ind(family = "A\u202EB\u200BC\u2028D\uD800E")).family
        assertEquals("ABCDE", out)
    }

    @Test
    fun `valid surrogate pair is kept`() {
        assertEquals("Fam\uD83D\uDE00", IocSanitizer.sanitize(ind(family = "Fam\uD83D\uDE00")).family)
    }

    @Test
    fun `family capped at 120 code points`() {
        assertEquals(120, IocSanitizer.sanitize(ind(family = "a".repeat(500))).family.length)
        val emoji = "\uD83D\uDE00".repeat(200)
        val out = IocSanitizer.sanitize(ind(family = emoji)).family
        assertEquals(120, out.codePointCount(0, out.length))
    }

    @Test
    fun `category outside the enum becomes empty`() {
        assertEquals("", IocSanitizer.sanitize(ind(category = "BANKER")).category)
        assertEquals("SPYWARE", IocSanitizer.sanitize(ind(category = "SPYWARE")).category)
    }

    @Test
    fun `campaign key must match the key pattern`() {
        assertEquals("pegasus", IocSanitizer.sanitize(ind(key = "pegasus")).campaignKey)
        assertEquals("", IocSanitizer.sanitize(ind(key = "Pegasus!")).campaignKey)
    }

    @Test
    fun `reference accepts https and feed only`() {
        assertEquals("", IocSanitizer.sanitize(ind(reference = "javascript:x")).reference)
        assertEquals("https://a.example/x", IocSanitizer.sanitize(ind(reference = "https://a.example/x")).reference)
        assertEquals("feed:s#F", IocSanitizer.sanitize(ind(reference = "feed:s#F")).reference)
        assertTrue(IocSanitizer.sanitize(ind(reference = "https://a/" + "x".repeat(600))).reference.isEmpty())
    }
}
