package com.androdr.privacy

import com.androdr.data.repo.TimelineRowDeleter
import com.androdr.data.store.StoreFixture
import com.androdr.ioc.TrackerRegistry
import com.androdr.privacy.DexPackageReader.ReadBudget
import com.androdr.privacy.model.RegistryState
import com.androdr.privacy.model.Tracker
import com.androdr.privacy.model.TrackerCategory
import com.androdr.privacy.model.TrackerSet
import io.mockk.coEvery
import io.mockk.every
import io.mockk.mockk
import io.mockk.spyk
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

/** A privacy scan writes its Timeline entries in the transaction that completes it (spec 2026-11-10 §5.4). */
@RunWith(RobolectricTestRunner::class)
class PrivacyScanTimelineTest {
    private companion object {
        const val DAY = 86_400_000L
        const val NOW = 100 * DAY
    }

    private val set = TrackerSet(
        listOf(
            Tracker(
                id = 1, name = "Flurry", website = "", categories = setOf(TrackerCategory.ANALYTICS),
                rawCategories = listOf("Analytics"), codePrefixes = listOf("com.flurry"), codeSegments = emptyList(),
                domainSuffixes = listOf("flurry.com"), domainLabels = emptyList(), domainPatterns = emptyList(),
            ),
        ),
        "sha",
    )

    private class Inspector(var apps: List<InstalledApp>, val packages: Map<String, Set<String>>) : AppInspector {
        override fun installedApps() = apps
        override fun inspect(app: InstalledApp, budget: ReadBudget) =
            AppInspection(app, packages[app.packageName].orEmpty(), InspectOutcome.INSPECTED, null)
    }

    private val f = StoreFixture()
    private val db = f.db
    private val job = SupervisorJob()
    private val scope = CoroutineScope(job + Dispatchers.IO)

    @After fun tearDown() {
        job.cancel()
        f.close()
    }

    /** The privacy entries as stored (the export reads leave them out, so plain SQL). */
    private data class Entry(val id: Long, val category: String, val packageName: String, val at: Long, val scan: Long)

    private fun app(pkg: String) = InstalledApp(pkg, 1, 10, "Label $pkg", false, listOf("/data/app/$pkg/base.apk"))

    private fun writer() = PrivacyTimelineWriter(
        db.forensicTimelineEventDao(),
        TimelineRowDeleter(db.forensicTimelineEventDao(), f.store, db.signalMemberDao()),
    )

    private fun runner(
        inspector: AppInspector = Inspector(listOf(app("a"), app("b")), mapOf("a" to setOf("com.flurry.sdk"))),
        timeline: PrivacyTimelineWriter = writer(),
    ): PrivacyScanRunner {
        val registry: TrackerRegistry = mockk {
            every { current() } returns set
            every { state } returns MutableStateFlow(RegistryState.AVAILABLE)
        }
        val usage: UsageIntervalReader = mockk { every { read(any(), any()) } returns null }
        return PrivacyScanRunner(inspector, registry, db.privacyDao(), db.dnsEventDao(), usage, scope, db, timeline)
            .also { it.clock = { NOW }; it.nanoTime = { 0L }; awaitIdle() }
    }

    private fun awaitIdle() = runBlocking {
        withTimeout(120_000) { while (job.children.any { it.isActive }) job.children.toList().forEach { it.join() } }
    }

    private fun scan(r: PrivacyScanRunner) {
        assertTrue(r.start())
        awaitIdle()
    }

    private fun entries(): List<Entry> = db.query(
        "SELECT id, category, packageName, startTimestamp, scanResultId FROM forensic_timeline " +
            "WHERE telemetrySource = 'PRIVACY_SCAN' ORDER BY id", null,
    ).use { c ->
        buildList { while (c.moveToNext()) add(Entry(c.getLong(0), c.getString(1), c.getString(2), c.getLong(3), c.getLong(4))) }
    }

    @Test fun `a completed scan writes its Timeline entries`() {
        scan(runner())
        val rows = entries()
        assertEquals(listOf("privacy_scan", "privacy_app"), rows.map { it.category })
        assertEquals("a", rows[1].packageName)
        assertTrue(rows.all { it.at == NOW })
    }

    @Test fun `a newer scan replaces the previous scan's entries`() {
        val r = runner()
        scan(r)
        val first = entries().map { it.id }
        scan(r)
        val second = entries()
        assertEquals(2, second.size)
        assertTrue(second.none { it.id in first })
    }

    @Test fun `Delete privacy results removes the entries`() {
        val r = runner()
        scan(r)
        assertTrue(runBlocking { r.deleteAll() })
        assertTrue(entries().isEmpty())
    }

    @Test fun `a failure while writing entries leaves the previous scan and its entries`() {
        scan(runner())
        val before = entries().map { it.id }
        val previousScan = runBlocking { db.privacyDao().latestCompletedOnce()!!.id }
        val failing = spyk(writer())
        coEvery { failing.replace(any()) } throws IllegalStateException("disk full")
        scan(runner(timeline = failing))
        assertEquals(before, entries().map { it.id })
        assertEquals(previousScan, runBlocking { db.privacyDao().latestCompletedOnce()!!.id })
        val unfinished = db.query("SELECT COUNT(*) FROM privacy_scan WHERE finishedAt IS NULL", null)
            .use { it.moveToFirst(); it.getInt(0) }
        assertEquals("the new scan was not completed", 1, unfinished)
    }

    @Test fun `entries never carry a security scan id`() {
        scan(runner())
        val scanId = runBlocking { db.privacyDao().latestCompletedOnce()!!.id }
        assertTrue(entries().all { it.scan == -1L })
        assertNotEquals(-1L, scanId)
    }

    @Test fun `a privacy scan adds no finding and opens no alert`() {
        scan(runner())
        val findings = db.query("SELECT COUNT(*) FROM scan_finding", null).use { it.moveToFirst(); it.getInt(0) }
        val alerts = db.query("SELECT COUNT(*) FROM alert", null).use { it.moveToFirst(); it.getInt(0) }
        assertEquals(0, findings)
        assertEquals(0, alerts)
    }
}
