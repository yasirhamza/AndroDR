package com.androdr.scanner

import android.content.pm.ApplicationInfo

/**
 * Determines whether a package should be treated as a system/OEM app for
 * detection purposes. Checks [ApplicationInfo.FLAG_SYSTEM] first, then
 * falls back to known OEM package name prefixes — because Samsung (and
 * other OEMs) preload apps that lose FLAG_SYSTEM after a Play Store update.
 */
object OemPackageHelper {

    private val oemPrefixes = listOf(
        // AOSP / Google
        "com.android.", "com.google.", "android",
        // Samsung / Knox / SEC
        "com.samsung.", "com.sec.", "com.osp.", "com.knox.",
        "com.skms.", "com.mygalaxy.",
        // Chipset vendors
        "com.qualcomm.", "com.qti.", "vendor.qti.",
        // Other Android OEMs
        "com.motorola.", "com.oneplus.", "com.miui.", "com.lge.",
        "com.htc.", "com.sony.", "com.huawei.", "com.asus.",
        "com.oppo.", "com.realme.", "com.vivo.",
        // Custom ROMs
        "org.lineageos.", "com.cyanogenmod.",
        // MediaTek
        "com.mediatek."
    )

    /**
     * Returns true if the package should be treated as a system/OEM app.
     * Uses FLAG_SYSTEM when available, with OEM prefix fallback.
     */
    fun isSystemOrOem(packageName: String, appInfo: ApplicationInfo?): Boolean {
        if (appInfo != null && appInfo.flags and ApplicationInfo.FLAG_SYSTEM != 0) {
            return true
        }
        return oemPrefixes.any { packageName.startsWith(it) }
    }
}
