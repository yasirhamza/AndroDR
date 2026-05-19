package com.androdr.ioc

import android.content.Context
import android.content.res.Resources
import com.androdr.R
import io.mockk.every
import io.mockk.mockk
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Coverage lock: every (DeviceIdentity, package) pair below must remain
 * recognized as an OEM prefix. Strip a prefix from known_oem_prefixes.yml
 * and this test will name the case that broke.
 *
 * Add a case whenever the audit script surfaces a new prefix that lands
 * in the YAML.
 */
class OemPrefixCoverageRegressionTest {

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
    fun `every coverage case still matches its expected device identity`() {
        val cases: List<Pair<DeviceIdentity, String>> = listOf(
            // Honor / Huawei (the original bug fix from #90)
            DeviceIdentity("honor", "honor") to "com.hihonor.appmarket",
            DeviceIdentity("huawei", "huawei") to "com.huawei.systemmanager",
            // Samsung
            DeviceIdentity("samsung", "samsung") to "com.samsung.android.sm",
            // Xiaomi (brand=redmi tests the brand_match list)
            DeviceIdentity("xiaomi", "redmi") to "com.miui.gallery",
            // OnePlus
            DeviceIdentity("oneplus", "oneplus") to "com.oneplus.gallery",
            // OPPO
            DeviceIdentity("oppo", "oppo") to "com.oplus.gallery",
            // Vivo
            DeviceIdentity("vivo", "vivo") to "com.vivo.email",
            // Asus
            DeviceIdentity("asus", "asus") to "com.asus.deskclock",
            // Motorola
            DeviceIdentity("motorola", "motorola") to "com.motorola.launcher3",
            // Lenovo (manufacturer=lenovo matches the motorola block's manufacturer_match)
            DeviceIdentity("lenovo", "lenovo") to "com.lenovo.leos.appstore",
            // Realme
            DeviceIdentity("realme", "realme") to "com.realme.launcher",
            // LG
            DeviceIdentity("lge", "lge") to "com.lge.launcher3",
            // Sony
            DeviceIdentity("sony", "sony") to "com.sonymobile.xperiaservices",
            // Amazon
            DeviceIdentity("amazon", "amazon") to "com.amazon.kindle",
            // Transsion (manufacturer=transsion, brand=tecno — brand_match includes "tecno")
            DeviceIdentity("transsion", "tecno") to "com.transsion.XOSLauncher",
            // Nothing
            DeviceIdentity("nothing", "nothing") to "com.nothing.launcher",
            // ZTE (manufacturer=zte)
            DeviceIdentity("zte", "zte") to "com.zte.mifavor.launcher",
            // Nubia (manufacturer=nubia matches the zte block's manufacturer_match)
            DeviceIdentity("nubia", "nubia") to "cn.nubia.accounts",
            // TCL
            DeviceIdentity("tcl", "tcl") to "com.tcl.android.launcher",
            // Meizu
            DeviceIdentity("meizu", "meizu") to "com.meizu.flyme.launcher",
            // HMD / Nokia (brand=nokia matches via brand_match)
            DeviceIdentity("hmd", "nokia") to "com.hmdglobal.camera2",
            // Blackview
            DeviceIdentity("blackview", "blackview") to "com.blackview.launcher",
            // Fairphone
            DeviceIdentity("fairphone", "fairphone") to "com.fairphone.activator",
            // Wiko
            DeviceIdentity("wiko", "wiko") to "com.wiko.services",
        )

        val failures = cases.filterNot { (device, pkg) ->
            resolver.isOemPrefix(pkg, device)
        }

        assertTrue(
            "Lost OEM coverage for ${failures.size} case(s):\n" +
                failures.joinToString("\n") { (d, p) -> "  - $p on $d" },
            failures.isEmpty(),
        )
    }
}
