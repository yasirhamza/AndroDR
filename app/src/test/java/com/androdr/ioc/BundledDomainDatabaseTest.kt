package com.androdr.ioc

import android.content.Context
import io.mockk.every
import io.mockk.mockk
import io.mockk.verify
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test
import java.io.File

class BundledDomainDatabaseTest {

    private fun db(json: String): Pair<BundledDomainDatabase, Context> {
        val ctx = mockk<Context>()
        every { ctx.resources.openRawResource(any()) } answers { json.byteInputStream() }
        return BundledDomainDatabase(ctx) to ctx
    }

    @Test
    fun `decodes attribution fields and the blocked subset`() {
        val (d, _) = db(
            """[{"domain":"Evil.Example","familyName":"Fam","category":"SPYWARE","campaign":"graphite",
            "severity":"CRITICAL","description":"x","source":"s","reference":"https://r","blockByDefault":true},
            {"domain":"quiet.example","familyName":"Q"}]"""
        )
        val hit = d.lookup("EVIL.example")!!
        assertEquals("Fam", hit.family)
        assertEquals("graphite", hit.campaignKey)
        assertEquals("https://r", hit.reference)
        assertEquals("bundled", hit.source)
        assertEquals(setOf("evil.example"), d.blockedDomains())
        assertEquals("quiet.example", d.lookup("quiet.example")!!.value)
        assertNull(d.lookup("other.example"))
    }

    @Test
    fun `loads the resource once, so later lookups do no I-O`() {
        val (d, ctx) = db("""[{"domain":"a.example","familyName":"A"}]""")
        repeat(5) { d.lookup("a.example"); d.blockedDomains() }
        verify(exactly = 1) { ctx.resources.openRawResource(any()) }
    }

    @Test
    fun `a corrupt resource yields an empty database`() {
        val (d, _) = db("not json")
        assertNull(d.lookup("a.example"))
        assertEquals(emptySet<String>(), d.blockedDomains())
    }

    @Test
    fun `the shipped domain list decodes with the production decoder`() {
        val raw = File(if (File("app/src/main/res/raw").isDirectory) "app/src/main/res/raw" else "src/main/res/raw",
            "known_bad_domains.json").readText()
        val (d, _) = db(raw)
        assertEquals(291, d.blockedDomains().size)
    }
}
