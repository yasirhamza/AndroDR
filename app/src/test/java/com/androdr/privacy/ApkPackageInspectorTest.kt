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

    @Test fun `a time limit before any package is COULD_NOT_INSPECT`() {
        val b = ReadBudget(deadlineNanos = 1L, nanoTime = { 1L })
        val r = inspector.inspect(app(apk("Lcom/a/B;")), b)
        assertEquals(InspectOutcome.COULD_NOT_INSPECT, r.outcome)
        assertTrue(r.packages.isEmpty())
        assertTrue(r.reason!!.contains("time limit"))
    }
}
