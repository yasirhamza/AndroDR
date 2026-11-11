package com.androdr.privacy

import com.androdr.data.db.AppDatabase
import com.androdr.data.db.DnsEventDao
import com.androdr.data.db.PrivacyDao
import com.androdr.data.db.RoomTestDb
import com.androdr.data.model.DnsEvent
import com.androdr.data.model.NetworkStatus
import com.androdr.data.model.PrivacyAppResult
import com.androdr.data.model.PrivacyPackageSet
import com.androdr.data.model.PrivacyScan
import com.androdr.data.model.PrivacyTrackerEvidence
import com.androdr.data.repo.ScanLock
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
import io.mockk.verify
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNotSame
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

@RunWith(RobolectricTestRunner::class)
class PrivacyScanRunnerTest {

    private companion object {
        const val DAY = 86_400_000L
        const val NOW = 100 * DAY
        const val NANO = 7_000L
        const val FLURRY = 1
        const val ADMOB = 2
        const val OTHER = 3
    }

    private fun tracker(id: Int, prefix: String, suffix: String) = Tracker(
        id = id, name = "T$id", website = "https://t$id.example", categories = setOf(TrackerCategory.ANALYTICS),
        rawCategories = listOf("Analytics", "Profiling"), codePrefixes = listOf(prefix), codeSegments = emptyList(),
        domainSuffixes = listOf(suffix), domainLabels = emptyList(), domainPatterns = emptyList(),
    )

    private val set = TrackerSet(
        listOf(
            tracker(FLURRY, "com.flurry", "flurry.com"),
            tracker(ADMOB, "com.google.android.gms.ads", "doubleclick.net"),
            tracker(OTHER, "io.other", "other.example"),
        ),
        "sha-a",
    )

    private class FakeInspector : AppInspector {
        @Volatile var apps: List<InstalledApp> = emptyList()
        val packages = ConcurrentHashMap<String, Set<String>>()
        val outcomes = ConcurrentHashMap<String, InspectOutcome>()
        val inspected = CopyOnWriteArrayList<String>()
        val budgets = CopyOnWriteArrayList<ReadBudget>()
        @Volatile var onInspect: (InstalledApp) -> Unit = {}
        @Volatile var onList: () -> Unit = {}

        override fun installedApps(): List<InstalledApp> {
            onList()
            return apps
        }

        override fun inspect(app: InstalledApp, budget: ReadBudget): AppInspection {
            inspected += app.packageName
            budgets += budget
            onInspect(app)
            val outcome = outcomes[app.packageName] ?: InspectOutcome.INSPECTED
            return AppInspection(app, packages[app.packageName].orEmpty(), outcome, null)
        }
    }

    private lateinit var db: AppDatabase
    private val inspector = FakeInspector()
    private val job = SupervisorJob()
    private val scope = CoroutineScope(job + Dispatchers.IO)

    @Before fun setUp() {
        db = RoomTestDb.inMemory()
    }

    @After fun tearDown() {
        job.cancel()
        db.close()
    }

    private fun app(pkg: String, version: Long = 1, updated: Long = 10) =
        InstalledApp(pkg, version, updated, pkg, false, listOf("/data/app/$pkg/base.apk"))

    private fun registryOf(s: TrackerSet?): TrackerRegistry = mockk {
        every { current() } returns s
        every { state } returns MutableStateFlow(if (s != null) RegistryState.AVAILABLE else RegistryState.UNAVAILABLE)
    }

    private fun usageReader(u: UsageIntervals?): UsageIntervalReader = mockk {
        every { read(any(), any()) } returns u
    }

    private fun runner(
        dao: PrivacyDao = db.privacyDao(),
        dns: DnsEventDao = db.dnsEventDao(),
        usage: UsageIntervals? = null,
        registry: TrackerRegistry = registryOf(set),
    ) = PrivacyScanRunner(inspector, registry, dao, dns, usageReader(usage), scope).also {
        it.clock = { NOW }
        it.nanoTime = { NANO }
        awaitIdle()
    }

    private fun awaitIdle() = runBlocking {
        withTimeout(120_000) {
            while (job.children.any { it.isActive }) job.children.toList().forEach { it.join() }
        }
    }

    private fun scan(r: PrivacyScanRunner): PrivacyScanProgress {
        assertTrue(r.start())
        awaitIdle()
        return r.progress.value
    }

    private fun latest(): PrivacyScan = runBlocking { requireNotNull(db.privacyDao().latestCompletedOnce()) }

    private fun evidence(): List<PrivacyTrackerEvidence> = runBlocking { db.privacyDao().evidenceOnce(latest().id) }

    private fun evidence(pkg: String, trackerId: Int) = evidence().singleOrNull {
        it.packageName == pkg && it.trackerId == trackerId
    }

    private fun result(pkg: String) = runBlocking {
        db.privacyDao().resultsOnce(latest().id).single { it.packageName == pkg }
    }

    private fun count(table: String): Int =
        db.query("SELECT COUNT(*) FROM $table", null).use { it.moveToFirst(); it.getInt(0) }

    private fun seed(vararg rows: DnsEvent) = runBlocking { db.dnsEventDao().insertAll(rows.toList()) }

    private fun dns(pkg: String?, domain: String, ts: Long) = DnsEvent(
        timestamp = ts, domain = domain, appUid = 10_100, appName = pkg, isBlocked = false, reason = null,
    )

    // --- inspection -----------------------------------------------------------------------------

    @Test fun `in-code trackers come from matchPackages`() {
        inspector.apps = listOf(app("a"))
        inspector.packages["a"] = setOf("com.flurry.sdk", "com.example.ui")
        assertTrue(scan(runner()) is PrivacyScanProgress.Finished)
        val ev = requireNotNull(evidence("a", FLURRY))
        assertTrue(ev.inCode)
        assertEquals(0, ev.lookups)
        assertNull(ev.firstSeen)
        assertNull(ev.background)
        assertEquals("T1", ev.trackerName)
        assertEquals("Analytics\u001FProfiling", ev.categories)
        assertEquals(1, evidence().size)
        assertEquals("INSPECTED", result("a").outcome)
    }

    @Test fun `an inspector that throws OutOfMemoryError yields COULD_NOT_INSPECT and the scan finishes`() {
        inspector.apps = listOf(app("a"), app("b"))
        inspector.packages["b"] = setOf("com.flurry.sdk")
        inspector.onInspect = { if (it.packageName == "a") throw OutOfMemoryError("boom") }
        assertTrue(scan(runner()) is PrivacyScanProgress.Finished)
        assertEquals("COULD_NOT_INSPECT", result("a").outcome)
        assertEquals("resource limit: OutOfMemoryError", result("a").reason)
        assertEquals("INSPECTED", result("b").outcome)
        assertEquals(1, latest().appsFailed)
        assertEquals(1, latest().appsInspected)
        assertNotNull(evidence("b", FLURRY))
    }

    @Test fun `an ordinary exception reads could not read, never resource limit`() {
        inspector.apps = listOf(app("a"), app("b"))
        inspector.onInspect = {
            when (it.packageName) {
                "a" -> throw java.io.IOException("bad zip")
                else -> throw StackOverflowError()
            }
        }
        assertTrue(scan(runner()) is PrivacyScanProgress.Finished)
        assertEquals("could not read: IOException", result("a").reason)
        assertEquals("resource limit: StackOverflowError", result("b").reason)
        assertEquals("COULD_NOT_INSPECT", result("a").outcome)
    }

    @Test fun `the runner passes a deadline PER_APP_TIMEOUT_MS ahead and one budget per app`() {
        inspector.apps = listOf(app("a"), app("b"))
        scan(runner())
        assertEquals(2, inspector.budgets.size)
        val expected = NANO + PrivacyScanRunner.PER_APP_TIMEOUT_MS * 1_000_000
        inspector.budgets.forEach { assertEquals(expected, it.deadlineNanos) }
        assertNotSame(inspector.budgets[0], inspector.budgets[1])
        assertFalse(inspector.budgets[0].expired())
    }

    @Test fun `a PARTIAL inspection is recorded and not cached`() {
        inspector.apps = listOf(app("a"))
        inspector.packages["a"] = setOf("com.flurry.sdk")
        inspector.outcomes["a"] = InspectOutcome.PARTIAL
        scan(runner())
        assertEquals("PARTIAL", result("a").outcome)
        assertEquals(1, latest().appsPartial)
        assertNull(runBlocking { db.privacyDao().packageSet("a") })
        assertTrue(requireNotNull(evidence("a", FLURRY)).inCode)
    }

    @Test fun `an INSPECTED app is cached with its package set`() {
        inspector.apps = listOf(app("a", version = 4, updated = 44))
        inspector.packages["a"] = setOf("com.flurry.sdk", "com.example")
        scan(runner())
        val row = requireNotNull(runBlocking { db.privacyDao().packageSet("a") })
        assertEquals(4L, row.versionCode)
        assertEquals(44L, row.lastUpdateTime)
        assertEquals(PrivacyScanRunner.READER_VERSION, row.readerVersion)
        assertEquals(setOf("com.flurry.sdk", "com.example"), row.packagesText.split('\n').toSet())
    }

    @Test fun `an over-size package text is not cached`() {
        inspector.apps = listOf(app("a"))
        val pad = "x".repeat(60)
        inspector.packages["a"] = (0 until 20_000).map { "com.big$it.$pad" }.toSet() + "com.flurry.sdk"
        scan(runner())
        assertEquals("INSPECTED", result("a").outcome)
        assertNull(runBlocking { db.privacyDao().packageSet("a") })
        assertNotNull(evidence("a", FLURRY))
    }

    @Test fun `a cache row that throws on read is deleted and the app re-inspected`() {
        val real = db.privacyDao()
        val deleted = CopyOnWriteArrayList<String>()
        val dao = object : PrivacyDao by real {
            override suspend fun packageSet(pkg: String): PrivacyPackageSet? = error("corrupt")
            override suspend fun deletePackageSet(pkg: String) {
                deleted += pkg
                real.deletePackageSet(pkg)
            }
        }
        inspector.apps = listOf(app("a"))
        inspector.packages["a"] = setOf("com.flurry.sdk")
        assertTrue(scan(runner(dao = dao)) is PrivacyScanProgress.Finished)
        assertEquals(listOf("a"), deleted)
        assertEquals(listOf("a"), inspector.inspected)
        assertEquals("INSPECTED", result("a").outcome)
    }

    @Test fun `cancellation during the cache read propagates`() {
        val real = db.privacyDao()
        val deleted = CopyOnWriteArrayList<String>()
        val dao = object : PrivacyDao by real {
            override suspend fun packageSet(pkg: String): PrivacyPackageSet? = throw CancellationException("stop")
            override suspend fun deletePackageSet(pkg: String) {
                deleted += pkg
            }
        }
        inspector.apps = listOf(app("a"))
        val r = runner(dao = dao)
        assertTrue(r.start())
        awaitIdle()
        // Not converted into a per-app COULD_NOT_INSPECT, and not swallowed: the run ends, and the UI is not left
        // showing a scan that will never finish.
        assertEquals(PrivacyScanProgress.Failed(PrivacyScanRunner.CANCELLED), r.progress.value)
        assertEquals(emptyList<String>(), deleted)
        assertEquals(emptyList<String>(), inspector.inspected)
        assertEquals(0, count("privacy_app_result"))
        assertNull(runBlocking { real.latestCompletedOnce() })
        assertTrue("the lock is released", r.start())
        awaitIdle()
    }

    @Test fun `an unchanged app (version, update time, reader version) reuses the cached package set`() {
        inspector.apps = listOf(app("a"))
        inspector.packages["a"] = setOf("com.flurry.sdk")
        val r = runner()
        scan(r)
        inspector.packages["a"] = emptySet()
        assertTrue(scan(r) is PrivacyScanProgress.Finished)
        assertEquals(listOf("a"), inspector.inspected)
        assertTrue(requireNotNull(evidence("a", FLURRY)).inCode)
        assertEquals("INSPECTED", result("a").outcome)
    }

    @Test fun `a changed lastUpdateTime re-inspects`() {
        inspector.apps = listOf(app("a", updated = 10))
        inspector.packages["a"] = setOf("com.flurry.sdk")
        val r = runner()
        scan(r)
        inspector.apps = listOf(app("a", updated = 11))
        inspector.packages["a"] = setOf("io.other.sdk")
        scan(r)
        assertEquals(listOf("a", "a"), inspector.inspected)
        assertNull(evidence("a", FLURRY))
        assertNotNull(evidence("a", OTHER))
    }

    @Test fun `a changed version code or reader version re-inspects`() {
        runBlocking {
            db.privacyDao().upsertPackageSet(
                PrivacyPackageSet("a", 1, 10, PrivacyScanRunner.READER_VERSION + 1, "com.flurry.sdk"),
            )
            db.privacyDao().upsertPackageSet(PrivacyPackageSet("b", 2, 10, PrivacyScanRunner.READER_VERSION, "x"))
        }
        inspector.apps = listOf(app("a"), app("b", version = 3))
        scan(runner())
        assertEquals(listOf("a", "b"), inspector.inspected)
    }

    // --- newSinceLastScan -----------------------------------------------------------------------

    @Test fun `the first scan marks nothing new`() {
        inspector.apps = listOf(app("a"))
        inspector.packages["a"] = setOf("com.flurry.sdk", "io.other.x")
        scan(runner())
        assertEquals(2, evidence().size)
        assertTrue(evidence().none { it.newSinceLastScan })
    }

    @Test fun `newSinceLastScan marks pairs absent from the previous completed scan`() {
        inspector.apps = listOf(app("a", updated = 10))
        inspector.packages["a"] = setOf("com.flurry.sdk")
        val r = runner()
        scan(r)
        inspector.apps = listOf(app("a", updated = 11))
        inspector.packages["a"] = setOf("com.flurry.sdk", "io.other.x")
        scan(r)
        assertFalse(requireNotNull(evidence("a", FLURRY)).newSinceLastScan)
        assertTrue(requireNotNull(evidence("a", OTHER)).newSinceLastScan)
    }

    @Test fun `an app not INSPECTED in the previous scan is not marked new`() {
        inspector.apps = listOf(app("a", updated = 10))
        inspector.outcomes["a"] = InspectOutcome.PARTIAL
        val r = runner()
        scan(r)
        inspector.apps = listOf(app("a", updated = 11))
        inspector.outcomes.remove("a")
        inspector.packages["a"] = setOf("com.flurry.sdk")
        scan(r)
        assertFalse(requireNotNull(evidence("a", FLURRY)).newSinceLastScan)
    }

    @Test fun `an app absent from the previous scan is not marked new`() {
        inspector.apps = listOf(app("a"))
        val r = runner()
        scan(r)
        inspector.apps = listOf(app("a"), app("b"))
        inspector.packages["b"] = setOf("com.flurry.sdk")
        scan(r)
        assertFalse(requireNotNull(evidence("b", FLURRY)).newSinceLastScan)
    }

    // --- scan lifecycle -------------------------------------------------------------------------

    @Test fun `appsTotal equals installedApps size`() {
        inspector.apps = listOf(app("a"), app("b"), app("c"))
        inspector.onInspect = { if (it.packageName == "b") error("bad") }
        scan(runner())
        assertEquals(3, latest().appsTotal)
        assertEquals(2, latest().appsInspected)
        assertEquals(1, latest().appsFailed)
    }

    @Test fun `completing a scan deletes older scans and prunes package sets of uninstalled apps`() {
        runBlocking { db.privacyDao().upsertPackageSet(PrivacyPackageSet("gone", 1, 1, 1, "x")) }
        inspector.apps = listOf(app("a"))
        inspector.packages["a"] = setOf("com.flurry.sdk")
        val r = runner()
        scan(r)
        val first = latest().id
        scan(r)
        assertEquals(1, count("privacy_scan"))
        assertTrue(latest().id > first)
        assertEquals(emptyList<Any>(), runBlocking { db.privacyDao().resultsOnce(first) })
        assertEquals(emptyList<Any>(), runBlocking { db.privacyDao().evidenceOnce(first) })
        assertNull(runBlocking { db.privacyDao().packageSet("gone") })
        assertNotNull(runBlocking { db.privacyDao().packageSet("a") })
    }

    @Test fun `a throw after the loop (dao fails in finishScan) gives Failed and releases the lock`() {
        val real = db.privacyDao()
        val dao = object : PrivacyDao by real {
            override suspend fun finishScan(
                id: Long, finishedAt: Long, inspected: Int, partial: Int, failed: Int,
                dnsCoverageDays: Int, usageFrom: Long?, networkStatus: String,
            ) {
                error("disk full")
            }
        }
        inspector.apps = listOf(app("a"))
        val r = runner(dao = dao)
        assertEquals(PrivacyScanProgress.Failed("IllegalStateException"), scan(r))
        assertTrue(r.start())
        awaitIdle()
    }

    @Test fun `a null registry gives Failed without a scan row`() {
        inspector.apps = listOf(app("a"))
        val r = runner(registry = registryOf(null))
        assertEquals(PrivacyScanProgress.Failed("tracker registry unavailable"), scan(r))
        assertEquals(0, count("privacy_scan"))
        assertEquals(emptyList<String>(), inspector.inspected)
    }

    @Test fun `start returns false while a scan runs`() {
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        inspector.apps = listOf(app("a"))
        inspector.onList = {
            entered.countDown()
            release.await(30, TimeUnit.SECONDS)
        }
        val r = runner()
        assertTrue(r.start())
        assertTrue(entered.await(30, TimeUnit.SECONDS))
        assertFalse(r.start())
        release.countDown()
        awaitIdle()
        assertTrue(r.progress.value is PrivacyScanProgress.Finished)
    }

    @Test fun `the scan never touches ScanLock`() {
        val lock = ScanLock()
        runBlocking { lock.mutex.lock() }
        inspector.apps = listOf(app("a"))
        assertTrue(scan(runner()) is PrivacyScanProgress.Finished)
        assertTrue(lock.mutex.isLocked)
        lock.mutex.unlock()
    }

    @Test fun `a registry refresh during the scan does not change the set used`() {
        val refreshed = TrackerSet(listOf(tracker(99, "com.flurry", "flurry.com")), "sha-b")
        val registry = registryOf(set)
        inspector.apps = listOf(app("a"), app("b"))
        inspector.packages["a"] = setOf("com.flurry.sdk")
        inspector.packages["b"] = setOf("com.flurry.sdk")
        inspector.onInspect = { every { registry.current() } returns refreshed }
        assertTrue(scan(runner(registry = registry)) is PrivacyScanProgress.Finished)
        assertEquals("sha-a", latest().registrySha256)
        assertEquals(setOf(FLURRY), evidence().map { it.trackerId }.toSet())
        assertEquals(2, evidence().size)
    }

    @Test fun `the scan row records the registry hash and coverage days`() {
        seed(
            dns("a", "x.flurry.com", 80 * DAY + 5), dns("a", "x.flurry.com", 81 * DAY),
            dns("a", "www.example.org", 81 * DAY + 9), dns("b", "www.example.org", 85 * DAY),
            dns(null, "www.example.org", 82 * DAY), dns("a", "x.flurry.com", 60 * DAY),
        )
        inspector.apps = listOf(app("a"))
        scan(runner(usage = UsageIntervals(75 * DAY, emptyMap())))
        val s = latest()
        assertEquals("sha-a", s.registrySha256)
        assertEquals(3, s.registrySize)
        assertEquals(3, s.dnsCoverageDays)
        assertEquals(NOW - PrivacyScanRunner.DNS_WINDOW_MS, s.dnsWindowStart)
        assertEquals(NOW, s.startedAt)
        assertEquals(NOW, s.finishedAt)
        assertEquals(75 * DAY, s.usageCoverageFrom)
        assertEquals(NetworkStatus.COMPLETE.name, s.networkStatus)
        val ev = requireNotNull(evidence("a", FLURRY))
        assertFalse(ev.inCode)
        assertEquals(2, ev.lookups)
        assertEquals(2, ev.lookupDays)
        assertEquals(2, ev.background)
        assertEquals(80 * DAY + 5, ev.firstSeen)
        assertEquals(81 * DAY, ev.lastSeen)
    }

    @Test fun `usage access absent leaves usage coverage null`() {
        inspector.apps = listOf(app("a"))
        scan(runner(usage = null))
        assertNull(latest().usageCoverageFrom)
    }

    @Test fun `deleteAll empties the tables and returns false while running`() {
        inspector.apps = listOf(app("a"))
        inspector.packages["a"] = setOf("com.flurry.sdk")
        val r = runner()
        scan(r)
        assertEquals(1, count("privacy_package_set"))
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        inspector.onList = {
            entered.countDown()
            release.await(30, TimeUnit.SECONDS)
        }
        assertTrue(r.start())
        assertTrue(entered.await(30, TimeUnit.SECONDS))
        assertFalse(runBlocking { r.deleteAll() })
        assertEquals("nothing deleted", 1, count("privacy_package_set"))
        assertEquals("nothing deleted", 1, count("privacy_scan"))
        release.countDown()
        awaitIdle()
        assertTrue(runBlocking { r.deleteAll() })
        listOf("privacy_scan", "privacy_app_result", "privacy_tracker_evidence", "privacy_package_set")
            .forEach { assertEquals(it, 0, count(it)) }
        assertEquals(PrivacyScanProgress.Idle, r.progress.value)
    }

    // --- network --------------------------------------------------------------------------------

    @Test fun `20,000 seeded DnsEvent rows for one pair finish the scan, with background null for that pair`() {
        val rows = List(20_000) { dns("a", "x.flurry.com", 80 * DAY + it) }
        runBlocking { db.dnsEventDao().insertAll(rows) }
        inspector.apps = listOf(app("a"))
        assertTrue(scan(runner(usage = UsageIntervals(70 * DAY, emptyMap()))) is PrivacyScanProgress.Finished)
        val ev = requireNotNull(evidence("a", FLURRY))
        assertEquals(20_000, ev.lookups)
        assertNull(ev.background)
        assertEquals(NetworkStatus.COMPLETE.name, latest().networkStatus)
    }

    @Test fun `a network-step failure keeps the code evidence and records networkStatus FAILED`() {
        val dns = mockk<DnsEventDao>(relaxed = true)
        coEvery { dns.domainsAfter(any(), any(), any(), any()) } throws IllegalStateException("db locked")
        inspector.apps = listOf(app("a"))
        inspector.packages["a"] = setOf("com.flurry.sdk")
        assertTrue(scan(runner(dns = dns)) is PrivacyScanProgress.Finished)
        assertEquals(NetworkStatus.FAILED.name, latest().networkStatus)
        assertTrue(requireNotNull(evidence("a", FLURRY)).inCode)
    }

    @Test fun `a network deadline that has passed records networkStatus TRUNCATED`() {
        seed(dns("a", "x.flurry.com", 80 * DAY))
        inspector.apps = listOf(app("a"))
        var calls = 0L
        val r = runner()
        // The network deadline is read once, then every check sees time far past it.
        r.nanoTime = { if (calls++ < 2) NANO else Long.MAX_VALUE }
        scan(r)
        assertEquals(NetworkStatus.TRUNCATED.name, latest().networkStatus)
    }

    @Test fun `network evidence for uninstalled apps is not recorded`() {
        seed(dns("gone", "x.flurry.com", 80 * DAY), dns("a", "x.flurry.com", 80 * DAY))
        inspector.apps = listOf(app("a"))
        scan(runner())
        assertEquals(listOf("a"), evidence().map { it.packageName })
    }

    // --- fix round 1 ---------------------------------------------------------------------------

    @Test fun `a package set that makes matchPackages throw costs only that app`() {
        val spy = spyk(set)
        every { spy.matchPackagesDetailed(match { "com.bad.x" in it }) } throws OutOfMemoryError("crafted")
        inspector.apps = listOf(app("a"), app("b"), app("c"))
        inspector.packages["a"] = setOf("com.flurry.sdk")
        inspector.packages["b"] = setOf("com.bad.x", "com.flurry.sdk")
        inspector.packages["c"] = setOf("io.other.y")
        assertTrue(scan(runner(registry = registryOf(spy))) is PrivacyScanProgress.Finished)
        assertEquals("COULD_NOT_INSPECT", result("b").outcome)
        assertEquals("resource limit: OutOfMemoryError", result("b").reason)
        assertEquals("INSPECTED", result("a").outcome)
        assertEquals("INSPECTED", result("c").outcome)
        assertNotNull(evidence("a", FLURRY))
        assertNotNull(evidence("c", OTHER))
        assertTrue(evidence().none { it.packageName == "b" })
        assertEquals(1, latest().appsFailed)
        val cached = runBlocking { db.privacyDao().packageSet("b") }
        assertNull("a package set that could not be matched is not cached", cached)
    }

    @Test fun `a coverage read failure fails the network step - no network rows, code evidence kept`() {
        seed(dns("a", "ads.doubleclick.net", 80 * DAY))
        val real = db.dnsEventDao()
        val dns = object : DnsEventDao by real {
            override suspend fun coverageDaysSince(since: Long): Int = error("db locked")
        }
        inspector.apps = listOf(app("a"))
        inspector.packages["a"] = setOf("com.flurry.sdk")
        assertTrue(scan(runner(dns = dns)) is PrivacyScanProgress.Finished)
        assertEquals(NetworkStatus.FAILED.name, latest().networkStatus)
        assertEquals(0, latest().dnsCoverageDays)
        assertTrue(evidence().all { it.lookups == 0 })
        assertNull(evidence("a", ADMOB))
        assertTrue(requireNotNull(evidence("a", FLURRY)).inCode)
    }

    @Test fun `a network deadline passed during the coverage read records TRUNCATED`() {
        seed(dns("a", "x.flurry.com", 80 * DAY))
        val real = db.dnsEventDao()
        val late = java.util.concurrent.atomic.AtomicBoolean(false)
        val dns = object : DnsEventDao by real {
            override suspend fun coverageDaysSince(since: Long): Int =
                real.coverageDaysSince(since).also { late.set(true) }
        }
        inspector.apps = listOf(app("a"))
        val r = runner(dns = dns)
        r.nanoTime = { if (late.get()) Long.MAX_VALUE else NANO }
        scan(r)
        assertEquals(NetworkStatus.TRUNCATED.name, latest().networkStatus)
        assertEquals(1, latest().dnsCoverageDays)
    }

    @Test fun `start on a cancelled scope fails as cancelled and frees the lock`() {
        inspector.apps = listOf(app("a"))
        val r = runner()
        job.cancel()
        assertTrue(r.start())
        runBlocking {
            withTimeout(30_000) { r.progress.first { it is PrivacyScanProgress.Failed } }
            assertEquals(PrivacyScanProgress.Failed(PrivacyScanRunner.CANCELLED), r.progress.value)
            // The handler sets the state, then unlocks: allow it to finish.
            withTimeout(30_000) { while (!r.deleteAll()) delay(10) }
        }
        assertEquals(emptyList<String>(), inspector.inspected)
    }

    private fun seedPrevious(status: NetworkStatus) = runBlocking {
        val dao = db.privacyDao()
        val id = dao.insertScan(
            PrivacyScan(
                startedAt = 1, finishedAt = null, appsTotal = 1, appsInspected = 0, appsPartial = 0, appsFailed = 0,
                registrySize = 3, registrySha256 = "sha-a", dnsWindowStart = 0, dnsCoverageDays = 0,
                usageCoverageFrom = null, networkStatus = NetworkStatus.PENDING.name,
            )
        )
        dao.upsertResults(listOf(PrivacyAppResult(id, "a", 1, "a", false, InspectOutcome.INSPECTED.name, null)))
        dao.finishScan(id, 2, 1, 0, 0, 0, null, status.name)
    }

    @Test fun `a network-only pair is not new when the previous scan's network was not COMPLETE`() {
        seedPrevious(NetworkStatus.TRUNCATED)
        seed(dns("a", "x.flurry.com", 80 * DAY))
        inspector.apps = listOf(app("a"))
        inspector.packages["a"] = setOf("io.other.y")
        scan(runner())
        val net = requireNotNull(evidence("a", FLURRY))
        assertFalse(net.inCode)
        assertFalse(net.newSinceLastScan)
        assertTrue("code evidence keeps its rule", requireNotNull(evidence("a", OTHER)).newSinceLastScan)
    }

    @Test fun `a network-only pair is new when the previous scan's network was COMPLETE`() {
        seedPrevious(NetworkStatus.COMPLETE)
        seed(dns("a", "x.flurry.com", 80 * DAY))
        inspector.apps = listOf(app("a"))
        scan(runner())
        assertTrue(requireNotNull(evidence("a", FLURRY)).newSinceLastScan)
    }

    // --- registry availability ------------------------------------------------------------------

    @Test fun `registryState is the registry's flow and construction triggers the lazy load`() {
        val registry = registryOf(set)
        val r = runner(registry = registry)
        verify(atLeast = 1) { registry.current() }
        assertSame(registry.state, r.registryState)
    }
}
