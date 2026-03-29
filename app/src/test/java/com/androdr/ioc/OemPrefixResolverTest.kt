package com.androdr.ioc

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class OemPrefixResolverTest {

    private val resolver = OemPrefixResolver()

    @Test
    fun `bundled prefixes match known OEM packages`() {
        assertTrue(resolver.isOemPrefix("com.samsung.accessory.zenithmgr"))
        assertTrue(resolver.isOemPrefix("com.google.android.gms"))
        assertTrue(resolver.isOemPrefix("com.miui.notes"))
        assertTrue(resolver.isOemPrefix("com.tmobile.m1"))
        assertTrue(resolver.isOemPrefix("com.mediatek.op01.phone.plugin"))
    }

    @Test
    fun `bundled prefixes do not match user apps`() {
        assertFalse(resolver.isOemPrefix("com.instagram.android"))
        assertFalse(resolver.isOemPrefix("com.callapp.contacts"))
        assertFalse(resolver.isOemPrefix("com.evil.spy"))
    }

    @Test
    fun `bundled installers are trusted`() {
        assertTrue(resolver.isTrustedInstaller("com.android.vending"))
        assertTrue(resolver.isTrustedInstaller("com.sec.android.app.samsungapps"))
        assertTrue(resolver.isTrustedInstaller("com.xiaomi.market"))
    }

    @Test
    fun `OEM-prefix installers are trusted`() {
        assertTrue(resolver.isTrustedInstaller("com.samsung.android.app.omcagent"))
        assertTrue(resolver.isTrustedInstaller("com.tmobile.pr.adapt"))
    }

    @Test
    fun `unknown installers are not trusted`() {
        assertFalse(resolver.isTrustedInstaller("com.unknown.installer"))
    }

    @Test
    fun `parseOemPrefixYaml extracts prefixes and installers`() {
        val yaml = """
            version: "2026-03-29"
            test_prefixes:
              - "com.test."
              - "com.example."
            trusted_installers:
              - "com.test.market"
        """.trimIndent()
        val result = resolver.parseOemPrefixYaml(yaml)
        assertTrue(result.prefixes.contains("com.test."))
        assertTrue(result.prefixes.contains("com.example."))
        assertTrue(result.installers.contains("com.test.market"))
    }

    @Test
    fun `IronSource Aura is NOT an OEM prefix`() {
        assertFalse(resolver.isOemPrefix("com.ironsrc.aura.tmo"))
    }
}
