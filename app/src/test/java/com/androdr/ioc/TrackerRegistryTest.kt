package com.androdr.ioc

import android.content.Context
import android.content.res.Resources
import com.androdr.privacy.model.DomainGrammar
import com.androdr.privacy.model.TrackerCategory
import io.mockk.every
import io.mockk.mockk
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

class TrackerRegistryTest {

    private fun firstExisting(vararg paths: String): File? =
        paths.map { File(it) }.firstOrNull { it.isFile }

    private fun bundledText(): String {
        val f = firstExisting("src/main/res/raw/trackers.yml", "app/src/main/res/raw/trackers.yml")
        assertNotNull("bundled trackers.yml missing", f)
        return f!!.readText()
    }

    private fun submoduleFile(name: String): File {
        val f = firstExisting(
            "../third-party/android-sigma-rules/validation/$name",
            "third-party/android-sigma-rules/validation/$name",
        )
        assertNotNull("submodule validation/$name missing", f)
        return f!!
    }

    private fun contextWith(raw: () -> String): Context {
        val ctx: Context = mockk(relaxed = true)
        val res: Resources = mockk(relaxed = true)
        every { ctx.resources } returns res
        every { res.openRawResource(any()) } answers { raw().byteInputStream() }
        return ctx
    }

    private fun entry(
        id: Int,
        prefixes: List<String> = listOf("com.t$id.sdk"),
        patterns: List<String> = emptyList(),
        categories: List<String> = listOf("Analytics"),
        website: String = "https://t$id.example",
    ): String = buildString {
        appendLine("- id: $id")
        appendLine("  name: T$id")
        appendLine("  website: '$website'")
        appendLine("  categories: [${categories.joinToString { "'$it'" }}]")
        appendLine("  code_prefixes: [${prefixes.joinToString { "'$it'" }}]")
        appendLine("  code_segments: []")
        appendLine("  domain_suffixes: []")
        appendLine("  domain_labels: []")
        appendLine("  domain_patterns: [${patterns.joinToString { "'$it'" }}]")
        appendLine("  excluded_domains: [ignored.example]")
    }

    private fun file(entries: List<String>, version: Int = 1, padTo: Int = TrackerRegistry.MIN_TRACKERS): String {
        val filler = (entries.size until padTo).map { entry(100_000 + it) }
        return "version: $version\ntrackers:\n" + (entries + filler).joinToString("")
    }

    @Test
    fun `the bundled file parses with at least 400 trackers`() {
        val set = TrackerRegistry.parse(bundledText())
        assertNotNull(set)
        assertTrue("size=${set!!.size}", set.size >= 400)
        assertEquals(com.androdr.integrity.ManifestVerifier.sha256(bundledText()), set.sourceSha256)
    }

    @Test
    fun `first-party hosts match nothing in the bundled registry`() {
        val set = TrackerRegistry.parse(bundledText())!!
        val hosts = submoduleFile("first_party_hosts.txt").readLines()
            .map { it.trim() }.filter { it.isNotEmpty() && !it.startsWith("#") }
        assertTrue(hosts.isNotEmpty())
        for (h in hosts) assertEquals("first-party host $h", emptySet<Any>(), set.matchDomain(h))
    }

    @Test
    fun `an unknown category maps to OTHER and Uncategorised maps to UNCATEGORISED`() {
        val set = TrackerRegistry.parse(
            file(listOf(entry(1, categories = listOf("Uncategorised", "Brand New", "Analytics"))))
        )!!
        val t = set.trackers.first { it.id == 1 }
        assertEquals(
            setOf(TrackerCategory.UNCATEGORISED, TrackerCategory.OTHER, TrackerCategory.ANALYTICS),
            t.categories,
        )
        assertEquals(listOf("Uncategorised", "Brand New", "Analytics"), t.rawCategories)
    }

    @Test
    fun `a bad pattern drops the pattern, not the file`() {
        val set = TrackerRegistry.parse(
            file(listOf(entry(1, patterns = listOf("[z-a]x", "(a+)+", "ok[0-9]*\\.ex\\.com", ".*"))))
        )!!
        val t = set.trackers.first { it.id == 1 }
        assertEquals(1, t.domainPatterns.size)
        assertEquals(setOf(t), set.matchDomain("ok7.ex.com"))
    }

    @Test
    fun `an invalid prefix drops the item and an emptied entry is dropped`() {
        val set = TrackerRegistry.parse(
            file(
                listOf(entry(1, prefixes = listOf("Com.Bad", "com.good.sdk")), entry(2, prefixes = listOf("NOPE"))),
                padTo = 305,
            )
        )!!
        assertEquals(listOf("com.good.sdk"), set.trackers.first { it.id == 1 }.codePrefixes)
        assertTrue(set.trackers.none { it.id == 2 })
    }

    @Test
    fun `pattern caps keep 4 per tracker and 64 per file`() {
        val six = (1..6).map { "a$it\\.ex\\.com" }
        val many = (1..20).map { id -> entry(id, patterns = (1..4).map { "p$id$it\\.ex\\.com" }) }
        val set = TrackerRegistry.parse(file(listOf(entry(500, patterns = six)) + many))!!
        assertEquals(4, set.trackers.first { it.id == 500 }.domainPatterns.size)
        val total = set.trackers.sumOf { it.domainPatterns.size }
        assertEquals(DomainGrammar.MAX_PATTERNS_TOTAL, total)
    }

    @Test
    fun `too few, too many, wrong version, deep nesting -- null`() {
        assertNull(TrackerRegistry.parse(file(emptyList(), padTo = TrackerRegistry.MIN_TRACKERS - 1)))
        assertNull(TrackerRegistry.parse(file(emptyList(), padTo = TrackerRegistry.MAX_TRACKERS + 1)))
        assertNull(TrackerRegistry.parse(file(emptyList(), version = 2)))
        assertNull(TrackerRegistry.parse("version: 1\ntrackers: " + "[".repeat(100_000) + "]".repeat(100_000)))
        assertNull(TrackerRegistry.parse("not: a registry"))
        assertNull(TrackerRegistry.parse(""))
    }

    @Test
    fun `the grammar rejects the probe-confirmed backtracking patterns`() {
        for (p in listOf("((a+))+$", "(a+?)+$", "(a{1,30}){1,30}$", "a*b*c*d", ".*")) {
            assertFalse(p, DomainGrammar.isRestrictedPattern(p))
        }
        for (p in listOf("adservice\\.google\\..*", "mst[0-9]*\\.is\\.autonavi\\.com", "mt[0-9]*\\.google\\.cn")) {
            assertTrue(p, DomainGrammar.isRestrictedPattern(p))
        }
    }

    @Test
    fun `website check is ASCII-only, userinfo-free and allows at-sign in the path`() {
        val ok = DomainGrammar.FIELD_CHECKS.getValue("website")
        assertTrue(ok(""))
        assertTrue(ok("https://www.example.com/a@b?x=1"))
        assertTrue(ok("HTTP://Example.com:8080/"))
        assertFalse(ok("https://user@example.com"))
        assertFalse(ok("https://exaKple.com")) // KELVIN SIGN must not match [a-z]
        assertFalse(ok("https://ſite.com"))     // LONG S likewise
        assertFalse(ok("ftp://example.com"))
        assertFalse(ok("https://example.com/a b"))
    }

    @Test
    fun `DomainGrammar agrees with domain_grammar_py on the shared fixture list`() {
        var n = 0
        for (line in submoduleFile("domain_grammar_fixtures.txt").readLines()) {
            if (line.isBlank() || line.startsWith("#")) continue
            val verdict = line.substringBefore(' ')
            val pattern = line.substringAfter(' ')
            val expected = when (verdict) {
                "ACCEPT" -> true
                "REJECT" -> false
                else -> error("bad fixture line: $line")
            }
            assertEquals("pattern '$pattern'", expected, DomainGrammar.isRestrictedPattern(pattern))
            n++
        }
        assertTrue(n >= 20)
    }

    @Test
    fun `refresh keeps the previous set when the manifest refuses`() = runBlocking {
        val good = file(listOf(entry(1)))
        val bad = FakeRemote(mapOf(TrackerRegistry.PATH to good))
        bad.set(TrackerRegistry.PATH, good + "\n# tampered\n")
        val registry = TrackerRegistry(contextWith { bundledText() }, IocDataManifest(bad))
        val before = registry.current()
        assertNotNull(before)
        assertEquals(0, registry.refresh())
        assertTrue(before === registry.current())
    }

    @Test
    fun `refresh replaces the set when a verified file parses`() = runBlocking {
        val good = file(listOf(entry(1)))
        val registry = TrackerRegistry(
            contextWith { bundledText() },
            IocDataManifest(FakeRemote(mapOf(TrackerRegistry.PATH to good))),
        )
        val before = registry.current()
        val accepted = registry.refresh()
        assertEquals(TrackerRegistry.MIN_TRACKERS, accepted)
        assertTrue(before !== registry.current())
        assertEquals(TrackerRegistry.MIN_TRACKERS, registry.current()!!.size)
        assertEquals(com.androdr.integrity.ManifestVerifier.sha256(good), registry.current()!!.sourceSha256)
    }

    @Test
    fun `construction does not parse`() {
        var opened = 0
        val ctx = contextWith { opened++; error("boom") }
        val registry = TrackerRegistry(ctx, IocDataManifest(FakeRemote(emptyMap())))
        assertEquals(0, opened)
        assertFalse(registry.available.value)
    }

    @Test
    fun `a corrupt bundled file gives null until a verified refresh succeeds`() = runBlocking {
        val good = file(listOf(entry(1)))
        val registry = TrackerRegistry(
            contextWith { "version: 1\ntrackers: [" },
            IocDataManifest(FakeRemote(mapOf(TrackerRegistry.PATH to good))),
        )
        assertNull(registry.current())
        assertFalse(registry.available.value)
        assertTrue(registry.refresh() > 0)
        assertNotNull(registry.current())
        assertTrue(registry.available.value)
    }

    @Test
    fun `a good bundled file makes the registry available on first use`() {
        val registry = TrackerRegistry(contextWith { bundledText() }, IocDataManifest(FakeRemote(emptyMap())))
        assertFalse(registry.available.value)
        assertNotNull(registry.current())
        assertTrue(registry.available.value)
    }
}
