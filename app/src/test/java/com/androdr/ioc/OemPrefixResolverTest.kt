package com.androdr.ioc

import android.content.Context
import android.content.res.Resources
import com.androdr.R
import io.mockk.every
import io.mockk.mockk
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Legacy behavior tests for OemPrefixResolver. These verify that when the
 * device identity matches the conditional block (e.g., assessing a Samsung
 * device), the appropriate prefixes are classified as OEM. The new
 * device-conditional behavior (Samsung prefix on a Pixel is NOT OEM) is
 * covered by [OemPrefixResolverConditionalTest].
 */
class OemPrefixResolverTest {

    private val resolver: OemPrefixResolver
    private val samsung = DeviceIdentity(manufacturer = "samsung", brand = "samsung")
    private val xiaomi = DeviceIdentity(manufacturer = "xiaomi", brand = "xiaomi")
    private val tmobile = DeviceIdentity(manufacturer = "samsung", brand = "tmobile")
    private val generic = DeviceIdentity(manufacturer = "google", brand = "google")

    init {
        val context: Context = mockk(relaxed = true)
        val resources: Resources = mockk(relaxed = true)
        every { context.resources } returns resources
        val yamlStream = javaClass.classLoader!!
            .getResourceAsStream("raw/known_oem_prefixes.yml")!!
        every { resources.openRawResource(R.raw.known_oem_prefixes) } returns yamlStream
        resolver = OemPrefixResolver(context)
    }

    private fun resolverFromYaml(yaml: String): OemPrefixResolver {
        val ctx: Context = mockk(relaxed = true)
        val res: Resources = mockk(relaxed = true)
        every { ctx.resources } returns res
        every { res.openRawResource(R.raw.known_oem_prefixes) } returns
            yaml.byteInputStream()
        return OemPrefixResolver(ctx)
    }

    private val syntheticYaml = """
        version: "test"
        unconditional:
          aosp_prefixes: ["com.android."]
          trusted_installers: ["com.android.vending"]
        conditional:
          samsung:
            manufacturer_match: ["samsung"]
            brand_match: ["samsung"]
            strict_prefixes: ["com.samsung."]
            trusted_installers: ["com.sec.android.app.samsungapps"]
    """.trimIndent()

    private val motorola = DeviceIdentity(manufacturer = "motorola", brand = "motorola")

    @Test
    fun `parseOemPrefixYaml reads per-block trusted_installers`() {
        val r = resolverFromYaml(syntheticYaml)
        val samsungInstallers = r.applicablePrefixesFor(samsung).installers
        assertTrue(samsungInstallers.contains("com.sec.android.app.samsungapps"))
        assertTrue(samsungInstallers.contains("com.android.vending")) // unconditional included
    }

    @Test
    fun `conditional installers apply only on a matching device`() {
        val r = resolverFromYaml(syntheticYaml)
        assertTrue(r.applicablePrefixesFor(samsung).installers.contains("com.sec.android.app.samsungapps"))
        assertFalse(r.applicablePrefixesFor(motorola).installers.contains("com.sec.android.app.samsungapps"))
        // Unconditional store is present on every device:
        assertTrue(r.applicablePrefixesFor(motorola).installers.contains("com.android.vending"))
    }

    @Test
    fun `Samsung packages are OEM on a Samsung device`() {
        assertTrue(resolver.isOemPrefix("com.samsung.accessory.zenithmgr", samsung))
        assertTrue(resolver.isOemPrefix("com.sec.android.app.launcher", samsung))
    }

    @Test
    fun `AOSP and Google packages are OEM on any device`() {
        assertTrue(resolver.isOemPrefix("com.google.android.gms", samsung))
        assertTrue(resolver.isOemPrefix("com.google.android.gms", xiaomi))
        assertTrue(resolver.isOemPrefix("com.google.android.gms", generic))
    }

    @Test
    fun `chipset prefixes are OEM on any device`() {
        assertTrue(resolver.isOemPrefix("com.mediatek.op01.phone.plugin", generic))
        assertTrue(resolver.isOemPrefix("com.unisoc.android.wifi", generic))
        assertTrue(resolver.isOemPrefix("com.qualcomm.qti.telephonyservice", samsung))
    }

    @Test
    fun `Xiaomi packages are OEM on a Xiaomi device`() {
        assertTrue(resolver.isOemPrefix("com.miui.notes", xiaomi))
        assertTrue(resolver.isOemPrefix("com.xiaomi.account", xiaomi))
    }

    @Test
    fun `US carrier packages are OEM on carrier-branded builds`() {
        assertTrue(resolver.isOemPrefix("com.tmobile.m1", tmobile))
    }

    @Test
    fun `user apps are not OEM on any device`() {
        assertFalse(resolver.isOemPrefix("com.instagram.android", samsung))
        assertFalse(resolver.isOemPrefix("com.instagram.android", generic))
        assertFalse(resolver.isOemPrefix("com.callapp.contacts", generic))
        assertFalse(resolver.isOemPrefix("com.evil.spy", generic))
    }

    @Test
    fun `bundled OEM stores are trusted only on their ecosystem (#280)`() {
        assertTrue(resolver.isTrustedInstaller("com.android.vending", generic))
        assertTrue(resolver.isTrustedInstaller("com.android.vending", samsung))
        assertTrue(resolver.isTrustedInstaller("com.sec.android.app.samsungapps", samsung))
        assertFalse(resolver.isTrustedInstaller("com.sec.android.app.samsungapps", generic))
        assertTrue(resolver.isTrustedInstaller("com.xiaomi.market", xiaomi))
        assertFalse(resolver.isTrustedInstaller("com.xiaomi.market", samsung))
    }

    @Test
    fun `MIUI package installer is no longer a trusted installer anywhere (#280)`() {
        assertFalse(resolver.isTrustedInstaller("com.miui.packageinstaller", xiaomi))
        assertFalse(resolver.isTrustedInstaller("com.miui.packageinstaller", generic))
    }

    @Test
    fun `forged store-looking installer names are not trusted (#267)`() {
        assertFalse(resolver.isTrustedInstaller("com.google.play.svcupdate", generic))
        assertFalse(resolver.isTrustedInstaller("com.google.android.packageinstaller", generic))
        assertFalse(resolver.isTrustedInstaller("com.android.packageinstaller", generic))
    }

    @Test
    fun `unknown installers are not trusted`() {
        assertFalse(resolver.isTrustedInstaller("com.unknown.installer", generic))
    }

    @Test
    fun `store trust is device-conditional when data uses per-block installers (#280)`() {
        val r = resolverFromYaml(syntheticYaml)
        assertTrue(r.isTrustedInstaller("com.sec.android.app.samsungapps", samsung))
        assertFalse(r.isTrustedInstaller("com.sec.android.app.samsungapps", motorola)) // cross-device forgery closed
        assertTrue(r.isTrustedInstaller("com.android.vending", motorola)) // Play everywhere
    }

    @Test
    fun `partner prefixes are not strict OEM prefixes on any device`() {
        // Former partnership concept retired in #147: Facebook/Microsoft preloads
        // are now classified via the known_good_apps.json DB, not prefix matching.
        // isOemPrefix must return false for these — they're user-space bundle IDs.
        assertFalse(resolver.isOemPrefix("com.facebook.katana", samsung))
        assertFalse(resolver.isOemPrefix("com.microsoft.office.word", samsung))
    }

    @Test
    fun `android prefix does not match androidmalware packages`() {
        assertFalse(resolver.isOemPrefix("androidmalware.evil.spy", generic))
        assertTrue(resolver.isOemPrefix("android.provider.contacts", generic))
    }
}
