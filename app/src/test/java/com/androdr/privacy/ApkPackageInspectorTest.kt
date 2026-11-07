package com.androdr.privacy

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import androidx.test.core.app.ApplicationProvider
import com.androdr.privacy.DexPackageReader.ReadBudget
import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows.shadowOf

@RunWith(RobolectricTestRunner::class)
class ApkPackageInspectorTest {

    private val context: Context = ApplicationProvider.getApplicationContext()
    private val inspector = ApkPackageInspector(context)

    private fun budget() = ReadBudget(deadlineNanos = Long.MAX_VALUE, nanoTime = { 0L })

    private fun apk(vararg descriptors: String): File =
        SyntheticDex.apk(linkedMapOf("classes.dex" to SyntheticDex.dex(descriptors.toList())))

    private fun app(vararg paths: File) = InstalledApp(
        packageName = "com.example.app", versionCode = 1L, lastUpdateTime = 0L, appLabel = "App",
        isSystemApp = false, apkPaths = paths.map { it.absolutePath },
    )

    @Test fun `installedApps lists base and split paths, update time and the system flag`() {
        val user = PackageInfo().apply {
            packageName = "com.zeta.user"
            longVersionCode = 42L
            lastUpdateTime = 1234L
            applicationInfo = ApplicationInfo().apply {
                packageName = "com.zeta.user"
                sourceDir = "/data/app/zeta/base.apk"
                splitSourceDirs = arrayOf("/data/app/zeta/split_a.apk", null)
                nonLocalizedLabel = "Zeta"
            }
        }
        val system = PackageInfo().apply {
            packageName = "com.alpha.sys"
            applicationInfo = ApplicationInfo().apply {
                packageName = "com.alpha.sys"
                sourceDir = "/system/app/alpha.apk"
                flags = ApplicationInfo.FLAG_SYSTEM
            }
        }
        shadowOf(context.packageManager).installPackage(user)
        shadowOf(context.packageManager).installPackage(system)

        val apps = inspector.installedApps().filter { it.packageName in setOf("com.zeta.user", "com.alpha.sys") }

        assertEquals(listOf("com.alpha.sys", "com.zeta.user"), apps.map { it.packageName })
        val z = apps[1]
        assertEquals(42L, z.versionCode)
        assertEquals(1234L, z.lastUpdateTime)
        assertEquals("Zeta", z.appLabel)
        assertFalse(z.isSystemApp)
        assertEquals(listOf("/data/app/zeta/base.apk", "/data/app/zeta/split_a.apk"), z.apkPaths)
        assertTrue(apps[0].isSystemApp)
    }

    @Test fun `inspect unions base and split packages`() {
        val r = inspector.inspect(app(apk("Lcom/a/B;"), apk("Lcom/c/D;")), budget())
        assertEquals(setOf("com.a", "com.c"), r.packages)
        assertEquals(InspectOutcome.INSPECTED, r.outcome)
        assertNull(r.reason)
    }

    @Test fun `a missing apk file is COULD_NOT_INSPECT with a reason`() {
        val r = inspector.inspect(app(File("/nonexistent/base.apk")), budget())
        assertEquals(InspectOutcome.COULD_NOT_INSPECT, r.outcome)
        assertTrue(r.packages.isEmpty())
        assertNotNull(r.reason)
    }

    @Test fun `one unreadable split of two is PARTIAL and keeps the readable one`() {
        val r = inspector.inspect(app(apk("Lcom/a/B;"), File("/nonexistent/split.apk")), budget())
        assertEquals(InspectOutcome.PARTIAL, r.outcome)
        assertEquals(setOf("com.a"), r.packages)
        assertNotNull(r.reason)
    }

    @Test fun `a partial dex result makes the app PARTIAL`() {
        val bad = SyntheticDex.apk(
            linkedMapOf(
                "classes.dex" to SyntheticDex.dex(listOf("Lcom/a/B;")),
                "classes2.dex" to byteArrayOf(1, 2, 3),
            ),
        )
        val r = inspector.inspect(app(bad), budget())
        assertEquals(InspectOutcome.PARTIAL, r.outcome)
        assertEquals(setOf("com.a"), r.packages)
        assertTrue(r.reason!!.contains("classes2.dex"))
    }

    @Test fun `base and split share one byte budget`() {
        val dexSize = SyntheticDex.dex(listOf("Lcom/a/B;")).size
        val b = ReadBudget(deadlineNanos = Long.MAX_VALUE, remainingAppBytes = dexSize + 10L, nanoTime = { 0L })
        val r = inspector.inspect(app(apk("Lcom/a/B;"), apk("Lcom/c/D;")), b)
        assertEquals(InspectOutcome.PARTIAL, r.outcome)
        assertEquals(setOf("com.a"), r.packages)
        assertTrue(b.remainingAppBytes < 0)
    }

    // --- R13: code stored outside the APK -------------------------------------------------------

    private fun noDexApk(): File = SyntheticDex.apk(linkedMapOf("resources.arsc" to byteArrayOf(0, 1, 2, 3)))

    /** A fresh folder holding a no-dex base APK, optionally with an `oat/` folder beside it (a stripped system app). */
    private fun appFolder(withOat: Boolean): File {
        val dir = kotlin.io.path.createTempDirectory("app-dir").toFile().also { it.deleteOnExit() }
        if (withOat) File(dir, "oat/arm64").mkdirs()
        val base = File(dir, "base.apk")
        noDexApk().copyTo(base)
        return base
    }

    @Test fun `declared code with no dex and an oat folder beside the apk is COULD_NOT_INSPECT, code stored outside`() {
        val base = appFolder(withOat = true)
        val r = inspector.inspect(app(base, noDexApk()).copy(hasCode = true), budget())
        assertEquals(InspectOutcome.COULD_NOT_INSPECT, r.outcome)
        assertEquals("code stored outside the APK", r.reason)
        assertTrue(r.packages.isEmpty())
    }

    // #452: resource-only system apps (overlays, *-res, Safety Center Resources) carry HAS_CODE by default but have
    // no code anywhere; "code stored outside the APK" was false for every one of them.
    @Test fun `a system-image app with no dex and no oat folder beside the apk is INSPECTED with an empty set`() {
        val r = inspector.inspect(
            app(appFolder(withOat = false)).copy(hasCode = true, isSystemApp = true, onSystemImage = true), budget(),
        )
        assertEquals(InspectOutcome.INSPECTED, r.outcome)
        assertNull(r.reason)
        assertTrue(r.packages.isEmpty())
    }

    // Security review of #452: a user app (in /data/app) can leave out classes.dex and load code another way; a
    // listable folder must not turn that into "none found". Only the read-only system image holds resource-only apps.
    @Test fun `a user app with no dex and no oat folder stays COULD_NOT_INSPECT`() {
        val r = inspector.inspect(app(appFolder(withOat = false)).copy(hasCode = true), budget())
        assertEquals(InspectOutcome.COULD_NOT_INSPECT, r.outcome)
        assertEquals("code stored outside the APK", r.reason)
    }

    @Test fun `a system app not on the system image (an update in data-app) stays COULD_NOT_INSPECT`() {
        val r = inspector.inspect(
            app(appFolder(withOat = false)).copy(hasCode = true, isSystemApp = true, onSystemImage = false), budget(),
        )
        assertEquals(InspectOutcome.COULD_NOT_INSPECT, r.outcome)
    }

    @Test fun `declared code with no dex in a folder that cannot be listed stays COULD_NOT_INSPECT`() {
        val base = appFolder(withOat = false)
        val dir = base.parentFile!!
        assertTrue(dir.setReadable(false, false))
        try {
            org.junit.Assume.assumeTrue("running as root: every folder is listable", dir.list() == null)
            val r = inspector.inspect(
                app(base).copy(hasCode = true, isSystemApp = true, onSystemImage = true), budget(),
            )
            assertEquals(InspectOutcome.COULD_NOT_INSPECT, r.outcome)
            assertEquals("code stored outside the APK", r.reason)
        } finally {
            dir.setReadable(true, false)
        }
    }

    @Test fun `a code-less package with no dex stays INSPECTED with an empty set`() {
        val r = inspector.inspect(app(noDexApk()).copy(hasCode = false), budget())
        assertEquals(InspectOutcome.INSPECTED, r.outcome)
        assertNull(r.reason)
        assertTrue(r.packages.isEmpty())
    }

    @Test fun `declared code with a valid dex is INSPECTED`() {
        val r = inspector.inspect(app(apk("Lcom/a/B;")).copy(hasCode = true), budget())
        assertEquals(InspectOutcome.INSPECTED, r.outcome)
        assertEquals(setOf("com.a"), r.packages)
    }

    @Test fun `declared code with a dex only in a split is INSPECTED`() {
        val r = inspector.inspect(app(noDexApk(), apk("Lcom/a/B;")).copy(hasCode = true), budget())
        assertEquals(InspectOutcome.INSPECTED, r.outcome)
        assertEquals(setOf("com.a"), r.packages)
    }

    @Test fun `declared code with a dex of zero class packages is INSPECTED, not code outside`() {
        val r = inspector.inspect(app(apk()).copy(hasCode = true), budget())
        assertEquals(InspectOutcome.INSPECTED, r.outcome)
        assertTrue(r.packages.isEmpty())
    }

    @Test fun `installedApps marks only non-updated system apps as on the system image`() {
        fun pkg(name: String, flags: Int) = PackageInfo().apply {
            packageName = name
            applicationInfo = ApplicationInfo().apply {
                packageName = name
                sourceDir = "/x/$name.apk"
                this.flags = flags
            }
        }
        shadowOf(context.packageManager).installPackage(pkg("com.img", ApplicationInfo.FLAG_SYSTEM))
        shadowOf(context.packageManager).installPackage(
            pkg("com.upd", ApplicationInfo.FLAG_SYSTEM or ApplicationInfo.FLAG_UPDATED_SYSTEM_APP),
        )
        shadowOf(context.packageManager).installPackage(pkg("com.usr", 0))
        val apps = inspector.installedApps().associateBy { it.packageName }
        assertTrue(apps.getValue("com.img").onSystemImage)
        assertFalse(apps.getValue("com.upd").onSystemImage)
        assertFalse(apps.getValue("com.usr").onSystemImage)
    }

    @Test fun `installedApps carries FLAG_HAS_CODE`() {
        val withCode = PackageInfo().apply {
            packageName = "com.has.code"
            applicationInfo = ApplicationInfo().apply {
                packageName = "com.has.code"
                sourceDir = "/system/app/c.apk"
                flags = ApplicationInfo.FLAG_HAS_CODE
            }
        }
        val overlay = PackageInfo().apply {
            packageName = "com.no.code"
            applicationInfo = ApplicationInfo().apply {
                packageName = "com.no.code"
                sourceDir = "/system/overlay/o.apk"
                flags = 0
            }
        }
        shadowOf(context.packageManager).installPackage(withCode)
        shadowOf(context.packageManager).installPackage(overlay)
        val apps = inspector.installedApps().associateBy { it.packageName }
        assertTrue(apps.getValue("com.has.code").hasCode)
        assertFalse(apps.getValue("com.no.code").hasCode)
    }

    @Test fun `a time limit before any package is COULD_NOT_INSPECT`() {
        val b = ReadBudget(deadlineNanos = 1L, nanoTime = { 1L })
        val r = inspector.inspect(app(apk("Lcom/a/B;")), b)
        assertEquals(InspectOutcome.COULD_NOT_INSPECT, r.outcome)
        assertTrue(r.packages.isEmpty())
        assertTrue(r.reason!!.contains("time limit"))
    }
}
