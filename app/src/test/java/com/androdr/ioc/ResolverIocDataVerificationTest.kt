package com.androdr.ioc

import android.content.Context
import android.content.res.Resources
import io.mockk.every
import io.mockk.mockk
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.File

/** Brand and OEM resolvers must ignore remote content whose hash mismatches ioc-data.sha256. */
class ResolverIocDataVerificationTest {

    private fun ioc(name: String): String? = listOf(
        File("third-party/android-sigma-rules/ioc-data/$name"),
        File("../third-party/android-sigma-rules/ioc-data/$name"),
    ).firstOrNull { it.isFile }?.readText()

    private fun context(): Context {
        val ctx: Context = mockk(relaxed = true)
        val res: Resources = mockk(relaxed = true)
        every { ctx.resources } returns res
        every { res.openRawResource(any()) } answers { "entries: []".byteInputStream() }
        return ctx
    }

    private fun filesOf(vararg names: String): Map<String, String>? {
        val m = names.associate { "ioc-data/$it" to ioc(it) }
        return if (m.values.any { it == null }) null else m.mapValues { it.value!! }
    }

    @Test
    fun `brand resolver accepts verified and ignores tampered content`() = runBlocking {
        val files = filesOf("brand-names.yml", "brand-domains.yml")
        assumeTrue("submodule not checked out", files != null)
        val good = FakeRemote(files!!)
        assertTrue(BrandImpersonationResolver(context(), IocDataManifest(good)).refresh() > 0)

        val bad = FakeRemote(files)
        bad.set("ioc-data/brand-names.yml", files["ioc-data/brand-names.yml"] + "\n# tampered\n")
        assertEquals(0, BrandImpersonationResolver(context(), IocDataManifest(bad)).refresh())
    }

    @Test
    fun `oem resolver accepts verified and ignores tampered content`() = runBlocking {
        val files = filesOf("known-oem-prefixes.yml")
        assumeTrue("submodule not checked out", files != null)
        assertTrue(OemPrefixResolver(context(), IocDataManifest(FakeRemote(files!!))).refresh() > 0)

        val bad = FakeRemote(files)
        bad.set("ioc-data/known-oem-prefixes.yml", files["ioc-data/known-oem-prefixes.yml"] + "\n# tampered\n")
        assertEquals(0, OemPrefixResolver(context(), IocDataManifest(bad)).refresh())
    }
}
