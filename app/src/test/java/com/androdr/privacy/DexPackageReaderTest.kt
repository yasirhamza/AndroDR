package com.androdr.privacy

import com.androdr.privacy.DexPackageReader.DexOutcome
import com.androdr.privacy.DexPackageReader.ReadBudget
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

class DexPackageReaderTest {

    @get:Rule val tmp = TemporaryFolder()

    @After fun clearProbe() {
        DexPackageReader.scanProbe = null
    }

    private fun budget() = ReadBudget(deadlineNanos = Long.MAX_VALUE, nanoTime = { 0L })

    /** A clock that reports "expired" (1 >= deadline 1) once more than [expireAfter] calls were made. */
    private class Clock(val expireAfter: Long) {
        var calls = 0L
        fun now(): Long {
            calls++
            return if (calls > expireAfter) 1L else 0L
        }
        fun budget() = ReadBudget(deadlineNanos = 1L, nanoTime = ::now)
    }

    private fun apk(vararg entries: Pair<String, ByteArray>, stored: Boolean = true) =
        SyntheticDex.apk(linkedMapOf(*entries), stored)

    @Test fun `packages come from loaded dex files and are de-duplicated`() {
        val f = apk(
            "classes.dex" to SyntheticDex.dex(listOf("Lcom/a/B;", "Lcom/a/C\$D;")),
            "classes2.dex" to SyntheticDex.dex(listOf("Lcom/x/Y;", "LTop;")),
        )
        val r = DexPackageReader.read(f, budget())
        assertEquals(setOf("com.a", "com.x"), r.packages)
        assertFalse(r.partial)
    }

    @Test fun `dex versions 035 through 041 are accepted`() {
        for (v in listOf("035", "039", "041")) {
            val r = DexPackageReader.read(apk("classes.dex" to SyntheticDex.dex(listOf("Lcom/a/B;"), v)), budget())
            assertEquals(v, setOf("com.a"), r.packages)
            assertEquals(v, DexOutcome.READ, r.dexOutcomes["classes.dex"])
        }
    }

    @Test fun `an unsupported dex version is malformed`() {
        val r = DexPackageReader.read(apk("classes.dex" to SyntheticDex.dex(listOf("Lcom/a/B;"), "042")), budget())
        assertEquals(DexOutcome.MALFORMED, r.dexOutcomes["classes.dex"])
    }

    @Test fun `a dex outside the load sequence is not read`() {
        val d = SyntheticDex.dex(listOf("Lcom/a/B;"))
        val e = SyntheticDex.dex(listOf("Lcom/z/B;"))
        val r = DexPackageReader.read(
            apk("classes.dex" to d, "classes3.dex" to e, "classes99.dex" to e),
            budget(),
        )
        assertEquals(setOf("com.a"), r.packages)
        assertEquals(setOf("classes.dex"), r.dexOutcomes.keys)
        assertFalse(r.partial)
    }

    @Test fun `a zip that lies about the entry size is capped by bytes actually read`() {
        val r = DexPackageReader.read(SyntheticDex.bomb(1_000, 2_000_000), budget(), maxDexBytes = 400_000)
        assertEquals(DexOutcome.SKIPPED_OVER_CAP, r.dexOutcomes["classes.dex"])
        assertTrue("bytesRead=${r.bytesRead}", r.bytesRead <= 400_000 + 65_536)
        assertTrue(r.partial)
    }

    @Test fun `an entry with unknown size is capped the same way`() {
        val r = DexPackageReader.read(SyntheticDex.bomb(-1, 2_000_000), budget(), maxDexBytes = 400_000)
        assertEquals(DexOutcome.SKIPPED_OVER_CAP, r.dexOutcomes["classes.dex"])
        assertTrue("bytesRead=${r.bytesRead}", r.bytesRead <= 400_000 + 65_536)
    }

    @Test fun `the per-app byte budget is shared across APKs`() {
        val dex = SyntheticDex.dex((0 until 1000).map { "Lcom/a/C$it;" })
        val shared = ReadBudget(
            deadlineNanos = Long.MAX_VALUE, remainingAppBytes = dex.size * 3L / 2, nanoTime = { 0L },
        )
        val base = DexPackageReader.read(apk("classes.dex" to dex), shared)
        val split = DexPackageReader.read(apk("classes.dex" to dex), shared)
        assertEquals(DexOutcome.READ, base.dexOutcomes["classes.dex"])
        assertEquals(DexOutcome.SKIPPED_OVER_CAP, split.dexOutcomes["classes.dex"])
        assertTrue(split.partial)
    }

    @Test fun `an expired deadline stops reading and marks the remaining dex TIME_LIMIT`() {
        val d1 = SyntheticDex.dex(listOf("Lcom/a/B;"))
        val d2 = SyntheticDex.dex(listOf("Lcom/x/Y;"))
        val probe = Clock(Long.MAX_VALUE)
        DexPackageReader.read(apk("classes.dex" to d1), probe.budget())
        val clock = Clock(probe.calls)
        val r = DexPackageReader.read(apk("classes.dex" to d1, "classes2.dex" to d2), clock.budget())
        assertEquals(setOf("com.a"), r.packages)
        assertEquals(DexOutcome.READ, r.dexOutcomes["classes.dex"])
        assertEquals(DexOutcome.TIME_LIMIT, r.dexOutcomes["classes2.dex"])
        assertTrue(r.partial)
    }

    @Test fun `a malformed dex costs that dex, the other dex files still count`() {
        val bad = SyntheticDex.assemble(
            ByteArray(16), listOf(0), listOf(0), stringIdsOff = 0x7FFFFFF0L,
        )
        val r = DexPackageReader.read(
            apk("classes.dex" to SyntheticDex.dex(listOf("Lcom/a/B;")), "classes2.dex" to bad),
            budget(),
        )
        assertEquals(setOf("com.a"), r.packages)
        assertEquals(DexOutcome.MALFORMED, r.dexOutcomes["classes2.dex"])
        assertTrue(r.partial)
    }

    @Test fun `huge table counts do not overflow`() {
        val bad = SyntheticDex.assemble(ByteArray(16), listOf(0), listOf(0), stringIdsSize = 0xFFFFFFF0L)
        val bad2 = SyntheticDex.assemble(ByteArray(16), listOf(0), listOf(0), typeIdsSize = 0xFFFFFFF0L)
        val r = DexPackageReader.read(apk("classes.dex" to bad, "classes2.dex" to bad2), budget())
        assertEquals(DexOutcome.MALFORMED, r.dexOutcomes["classes.dex"])
        assertEquals(DexOutcome.MALFORMED, r.dexOutcomes["classes2.dex"])
        assertTrue(r.packages.isEmpty())
    }

    @Test fun `a string_data offset outside the dex is malformed`() {
        val bad = SyntheticDex.assemble(ByteArray(16), listOf(1_000_000), listOf(0))
        val r = DexPackageReader.read(apk("classes.dex" to bad), budget())
        assertEquals(DexOutcome.MALFORMED, r.dexOutcomes["classes.dex"])
    }

    @Test fun `a six byte uleb128 is malformed`() {
        val data = byteArrayOf(0x81.toByte(), 0x81.toByte(), 0x81.toByte(), 0x81.toByte(), 0x81.toByte(), 1, 0)
        val bad = SyntheticDex.assemble(data, listOf(0), listOf(0))
        val r = DexPackageReader.read(apk("classes.dex" to bad), budget())
        assertEquals(DexOutcome.MALFORMED, r.dexOutcomes["classes.dex"])
    }

    @Test fun `a descriptor with no NUL within the bound is skipped and the scan stays bounded`() {
        val data = SyntheticDex.uleb(10) + ByteArray(4 * 1024 * 1024) { 'a'.code.toByte() }
        val n = 4096
        val dex = SyntheticDex.assemble(data, (0 until n).toList(), (0 until n).toList())
        val scans = ArrayList<Int>()
        DexPackageReader.scanProbe = { scans.add(it) }
        val r = DexPackageReader.read(apk("classes.dex" to dex), budget())
        assertEquals(DexOutcome.READ, r.dexOutcomes["classes.dex"])
        assertTrue(r.packages.isEmpty())
        assertEquals(n, scans.size)
        assertTrue("max scan ${scans.max()}", scans.max() <= 3 * DexPackageReader.MAX_DESCRIPTOR_CHARS + 1)
    }

    @Test fun `invalid MUTF-8 skips the descriptor, not the dex`() {
        val good = SyntheticDex.stringData("Lcom/ok/A;")
        val badStr = byteArrayOf(5, 0xFF.toByte(), 0xFE.toByte(), 0x80.toByte(), 0xC3.toByte(), 0)
        val bad4 = byteArrayOf(4, 0xF0.toByte(), 0x9F.toByte(), 0x98.toByte(), 0x80.toByte(), 0)
        val data = badStr + bad4 + good
        val dex = SyntheticDex.assemble(data, listOf(0, badStr.size, badStr.size + bad4.size), listOf(0, 1, 2))
        val r = DexPackageReader.read(apk("classes.dex" to dex), budget())
        assertEquals(DexOutcome.READ, r.dexOutcomes["classes.dex"])
        assertEquals(setOf("com.ok"), r.packages)
    }

    @Test fun `an entry whose compressed size exceeds the cap is skipped unread`() {
        val r = DexPackageReader.read(apk("classes.dex" to ByteArray(100_001)), budget(), maxDexBytes = 100_000)
        assertEquals(DexOutcome.SKIPPED_OVER_CAP, r.dexOutcomes["classes.dex"])
        assertEquals(0L, r.bytesRead)
    }

    @Test fun `a loaded dex beyond MAX_DEX_FILES marks the result partial`() {
        val d = SyntheticDex.dex(listOf("Lcom/a/B;"))
        val r = DexPackageReader.read(
            apk("classes.dex" to d, "classes2.dex" to d, "classes3.dex" to d), budget(), maxDexFiles = 2,
        )
        assertEquals(DexOutcome.READ, r.dexOutcomes["classes2.dex"])
        assertEquals(DexOutcome.SKIPPED_OVER_CAP, r.dexOutcomes["classes3.dex"])
        assertTrue(r.partial)
    }

    @Test fun `the deadline is checked inside table loops`() {
        val dex = SyntheticDex.dex((0 until 9000).map { "Lcom/a/C$it;" })
        val probe = Clock(Long.MAX_VALUE)
        DexPackageReader.read(apk("classes.dex" to dex), probe.budget())
        val clock = Clock(probe.calls - 1)
        val r = DexPackageReader.read(apk("classes.dex" to dex), clock.budget())
        assertEquals(DexOutcome.TIME_LIMIT, r.dexOutcomes["classes.dex"])
        assertEquals(setOf("com.a"), r.packages)
        assertTrue(r.partial)
    }

    @Test fun `multi-byte uleb128 and non-ASCII names are read`() {
        val path = "aaaaaaaaa/".repeat(20)
        val r = DexPackageReader.read(
            apk(
                "classes.dex" to SyntheticDex.dex(
                    listOf("L${path}C;", "Lcom/ex/Café;", "Lcom/ünï/A;"),
                ),
            ),
            budget(),
        )
        val expected = "aaaaaaaaa.".repeat(19) + "aaaaaaaaa"
        assertEquals(setOf(expected, "com.ex", "com.ünï"), r.packages)
        assertEquals(DexOutcome.READ, r.dexOutcomes["classes.dex"])
    }

    @Test fun `odd descriptors are skipped without marking the dex malformed`() {
        val long = "L" + "a/".repeat(300) + "C;"
        val r = DexPackageReader.read(
            apk(
                "classes.dex" to SyntheticDex.dex(
                    listOf("Lcom/a/-\$\$Lambda\$Foo;", long, "Lcom/a b/C;", "[I", "J", "Lcom//C;"),
                ),
            ),
            budget(),
        )
        assertEquals(setOf("com.a"), r.packages)
        assertEquals(DexOutcome.READ, r.dexOutcomes["classes.dex"])
        assertFalse(r.partial)
    }

    @Test fun `hitting the package cap marks the result partial`() {
        val dex = SyntheticDex.dex((0 until 30).map { "Lp$it/A;" })
        val b = ReadBudget(deadlineNanos = Long.MAX_VALUE, remainingPackages = 20, nanoTime = { 0L })
        val r = DexPackageReader.read(apk("classes.dex" to dex), b)
        assertEquals(20, r.packages.size)
        assertTrue(r.packageCapHit)
        assertTrue(r.partial)
    }

    @Test fun `the package cap bounds the in-memory set not just the result`() {
        val dex = SyntheticDex.dex((0 until 5000).map { "Lp$it/A;" })
        val b = ReadBudget(deadlineNanos = Long.MAX_VALUE, remainingPackages = 100, nanoTime = { 0L })
        val peaks = ArrayList<Int>()
        DexPackageReader.localSetProbe = { peaks.add(it) }
        try {
            val r = DexPackageReader.read(apk("classes.dex" to dex), b)
            assertTrue(r.packages.size <= 100)
            assertTrue(r.packageCapHit)
            assertTrue(r.partial)
            assertEquals(DexOutcome.READ, r.dexOutcomes["classes.dex"])
            assertEquals(listOf(100), peaks)
            assertEquals(0, b.remainingPackages)
        } finally {
            DexPackageReader.localSetProbe = null
        }
    }

    @Test fun `a package already stored from an earlier dex does not consume budget`() {
        val b = ReadBudget(deadlineNanos = Long.MAX_VALUE, remainingPackages = 3, nanoTime = { 0L })
        val r = DexPackageReader.read(
            apk(
                "classes.dex" to SyntheticDex.dex(listOf("Lcom/a/X;", "Lcom/b/X;")),
                "classes2.dex" to SyntheticDex.dex(listOf("Lcom/a/Y;", "Lcom/c/Y;")),
            ),
            b,
        )
        assertEquals(setOf("com.a", "com.b", "com.c"), r.packages)
        assertFalse(r.packageCapHit)
        assertEquals(0, b.remainingPackages)
    }

    @Test fun `stored and deflated entries both read`() {
        val dex = SyntheticDex.dex(listOf("Lcom/a/B;"))
        for (stored in listOf(true, false)) {
            val r = DexPackageReader.read(apk("classes.dex" to dex, stored = stored), budget())
            assertEquals("stored=$stored", setOf("com.a"), r.packages)
        }
    }

    @Test fun `a file that is not a zip throws ApkUnreadableException`() {
        val f = tmp.newFile("x.apk")
        f.writeText("this is not a zip file at all")
        try {
            DexPackageReader.read(f, budget())
            fail("expected ApkUnreadableException")
        } catch (_: DexPackageReader.ApkUnreadableException) {
            // expected
        }
    }
}
