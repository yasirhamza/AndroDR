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
 * Regression test for #90: device-conditional OEM resolution. The attack
 * this test prevents: an attacker ships a sideloaded APK with a foreign
 * vendor's package prefix (e.g. com.samsung.*) on a device that doesn't
 * actually use that vendor (e.g. a Pixel). Under the old global allowlist,
 * the malware was classified as OEM and suppressed from findings. Under
 * the new conditional allowlist, it's classified on its own merits.
 */
class OemPrefixResolverConditionalTest {

    private val resolver: OemPrefixResolver
    private val pixel = DeviceIdentity(manufacturer = "google", brand = "google")
    private val samsung = DeviceIdentity(manufacturer = "samsung", brand = "samsung")
    private val xiaomi = DeviceIdentity(manufacturer = "xiaomi", brand = "redmi")
    private val unknown = DeviceIdentity.UNKNOWN

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
    fun `Samsung prefix is NOT OEM on a Pixel`() {
        assertFalse(
            "com.samsung.android.gearclient on a Pixel must not be classified as OEM",
            resolver.isOemPrefix("com.samsung.android.gearclient", pixel),
        )
        assertFalse(resolver.isOemPrefix("com.sec.android.app.camera", pixel))
    }

    @Test
    fun `Samsung prefix IS OEM on a Samsung device`() {
        assertTrue(resolver.isOemPrefix("com.samsung.android.gearclient", samsung))
        assertTrue(resolver.isOemPrefix("com.sec.android.app.camera", samsung))
    }

    @Test
    fun `Xiaomi prefix is NOT OEM on a Samsung device`() {
        assertFalse(resolver.isOemPrefix("com.miui.notes", samsung))
        assertFalse(resolver.isOemPrefix("com.xiaomi.account", samsung))
    }

    @Test
    fun `Xiaomi prefix IS OEM on a Redmi device (Xiaomi manufacturer, Redmi brand)`() {
        assertTrue(resolver.isOemPrefix("com.miui.notes", xiaomi))
        assertTrue(resolver.isOemPrefix("com.xiaomi.account", xiaomi))
    }

    @Test
    fun `chipset prefixes apply on ALL devices including Pixel`() {
        assertTrue(resolver.isOemPrefix("com.unisoc.android.wifi", pixel))
        assertTrue(resolver.isOemPrefix("com.qualcomm.qti.telephonyservice", pixel))
    }

    @Test
    fun `AOSP prefixes apply on ALL devices`() {
        assertTrue(resolver.isOemPrefix("com.android.systemui", pixel))
        assertTrue(resolver.isOemPrefix("com.google.android.gms", samsung))
    }

    @Test
    fun `UNKNOWN device identity only matches unconditional prefixes`() {
        assertFalse(resolver.isOemPrefix("com.samsung.android.gearclient", unknown))
        assertFalse(resolver.isOemPrefix("com.miui.notes", unknown))
        assertTrue(resolver.isOemPrefix("com.android.systemui", unknown))
        assertTrue(resolver.isOemPrefix("com.qualcomm.qti.telephonyservice", unknown))
    }

    @Test
    fun `applicablePrefixesFor caches per device identity`() {
        val a = resolver.applicablePrefixesFor(pixel)
        val b = resolver.applicablePrefixesFor(pixel)
        val c = resolver.applicablePrefixesFor(samsung)
        assertTrue(a === b)
        assertFalse(a === c)
    }

    @Test
    fun `Huawei manufacturer matches huawei or honor brand`() {
        val honor = DeviceIdentity(manufacturer = "honor", brand = "honor")
        assertTrue(resolver.isOemPrefix("com.huawei.browser", honor))
        assertTrue(resolver.isOemPrefix("com.honor.appmarket", honor))
    }

    @Test
    fun `OPPO manufacturer matches coloros and heytap prefixes`() {
        val oppo = DeviceIdentity(manufacturer = "oppo", brand = "oppo")
        assertTrue(resolver.isOemPrefix("com.oppo.camera", oppo))
        assertTrue(resolver.isOemPrefix("com.coloros.safecenter", oppo))
        assertTrue(resolver.isOemPrefix("com.heytap.market", oppo))
    }
}
