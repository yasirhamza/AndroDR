package com.androdr.ioc

import android.content.Context
import android.content.res.Resources
import com.androdr.R
import io.mockk.every
import io.mockk.mockk
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class OemPrefixResolverTest {

    private val resolver: OemPrefixResolver

    init {
        val context: Context = mockk(relaxed = true)
        val resources: Resources = mockk(relaxed = true)
        every { context.resources } returns resources
        val yamlStream = javaClass.classLoader!!
            .getResourceAsStream("raw/known_oem_prefixes.yml")!!
        every { resources.openRawResource(R.raw.known_oem_prefixes) } returns yamlStream
        resolver = OemPrefixResolver(context)
    }

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
    fun `parseOemPrefixYaml separates strict and partnership prefixes`() {
        val yaml = """
            version: "2026-03-29"
            oem_prefixes:
              - "com.test."
              - "com.example."
            partnership_prefixes:
              - "com.partner."
            trusted_installers:
              - "com.test.market"
        """.trimIndent()
        val result = resolver.parseOemPrefixYaml(yaml)
        assertTrue(result.strictPrefixes.contains("com.test."))
        assertTrue(result.strictPrefixes.contains("com.example."))
        assertFalse(result.strictPrefixes.contains("com.partner."))
        assertTrue(result.partnershipPrefixes.contains("com.partner."))
        assertTrue(result.installers.contains("com.test.market"))
    }

    @Test
    fun `partnership prefixes are not strict OEM prefixes`() {
        // Partnership pre-installs (Facebook, Microsoft, etc.) should NOT match isOemPrefix
        assertFalse(resolver.isOemPrefix("com.facebook.katana"))
        assertFalse(resolver.isOemPrefix("com.microsoft.office.word"))
    }

    @Test
    fun `monotype and hiya are strict OEM prefixes per YAML`() {
        // These moved from partnership to samsung_prefixes (strict) in the bundled YAML
        assertTrue(resolver.isOemPrefix("com.monotype.android.font"))
        assertTrue(resolver.isOemPrefix("com.hiya.star"))
    }

    @Test
    fun `partnership prefixes match isPartnershipPrefix`() {
        assertTrue(resolver.isPartnershipPrefix("com.facebook.katana"))
        assertTrue(resolver.isPartnershipPrefix("com.microsoft.office.word"))
        assertTrue(resolver.isPartnershipPrefix("com.touchtype.swiftkey"))
    }

    @Test
    fun `digitalturbine is a strict OEM prefix`() {
        assertTrue(resolver.isOemPrefix("com.digitalturbine.ultraman"))
    }

    @Test
    fun `IronSource Aura is NOT an OEM prefix`() {
        assertFalse(resolver.isOemPrefix("com.ironsrc.aura.tmo"))
    }

    @Test
    fun `android prefix does not match androidmalware packages`() {
        assertFalse(resolver.isOemPrefix("androidmalware.evil.spy"))
        assertTrue(resolver.isOemPrefix("android.provider.contacts"))
    }
}
