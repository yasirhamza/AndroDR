package com.androdr.privacy

import com.androdr.data.db.AppDatabase
import com.androdr.data.db.DnsEventDao
import com.androdr.data.db.PrivacyDao
import com.androdr.data.db.RoomTestDb
import com.androdr.data.model.DnsEvent
import com.androdr.data.model.NetworkStatus
import com.androdr.data.model.PrivacyCodeDetail
import com.androdr.data.model.PrivacyDomainDetail
import com.androdr.data.model.PrivacyScan
import com.androdr.data.model.PrivacyTrackerEvidence
import com.androdr.ioc.TrackerRegistry
import com.androdr.privacy.DexPackageReader.ReadBudget
import com.androdr.privacy.model.RegistryState
import com.androdr.privacy.model.Tracker
import com.androdr.privacy.model.TrackerCategory
import com.androdr.privacy.model.TrackerSet
import io.mockk.every
import io.mockk.mockk
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import java.util.concurrent.ConcurrentHashMap

/**
 * The evidence details a scan records (schema 23, spec 2026-11-10 section 4): what is written, what is
 * left out, and when it is deleted. Same fixture as [PrivacyScanRunnerTest], trimmed to what these need.
 */
@RunWith(RobolectricTestRunner::class)
class PrivacyScanRunnerDetailTest {

    private companion object {
        const val DAY = 86_400_000L
        const val NOW = 100 * DAY
        const val FLURRY = 1
        const val ADMOB = 2
        const val OTHER = 3
    }

    private fun tracker(id: Int, prefix: String, suffix: String) = Tracker(
        id = id, name = "T$id", website = "https://t$id.example", categories = setOf(TrackerCategory.ANALYTICS),
        rawCategories = listOf("Analytics"), codePrefixes = listOf(prefix), codeSegments = emptyList(),
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
        @Volatile var onInspect: (InstalledApp) -> Unit = {}

        override fun installedApps(): List<InstalledApp> = apps

        override fun inspect(app: InstalledApp, budget: ReadBudget): AppInspection {
            onInspect(app)
            return AppInspection(app, packages[app.packageName].orEmpty(), InspectOutcome.INSPECTED, null)
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

    private fun app(pkg: String) = InstalledApp(pkg, 1, 10, pkg, false, listOf("/data/app/$pkg/base.apk"))

    private fun runner(dns: DnsEventDao = db.dnsEventDao()): PrivacyScanRunner {
        val registry: TrackerRegistry = mockk {
            every { current() } returns set
            every { state } returns MutableStateFlow(RegistryState.AVAILABLE)
        }
        val usage: UsageIntervalReader = mockk { every { read(any(), any()) } returns null }
        val dao: PrivacyDao = db.privacyDao()
        return PrivacyScanRunner(inspector, registry, dao, dns, usage, scope, db, timelineWriter(db)).also {
            it.clock = { NOW }
            it.nanoTime = { 0L }
            awaitIdle()
        }
    }

    private fun awaitIdle() = runBlocking {
        withTimeout(120_000) {
            while (job.children.any { it.isActive }) job.children.toList().forEach { it.join() }
        }
    }

    private fun scan(r: PrivacyScanRunner) {
        assertTrue(r.start())
        awaitIdle()
    }

    private fun latest(): PrivacyScan = runBlocking { requireNotNull(db.privacyDao().latestCompletedOnce()) }

    private fun evidence(): List<PrivacyTrackerEvidence> = runBlocking { db.privacyDao().evidenceOnce(latest().id) }

    private fun evidence(pkg: String, trackerId: Int) = evidence().singleOrNull {
        it.packageName == pkg && it.trackerId == trackerId
    }

    private fun count(table: String): Int =
        db.query("SELECT COUNT(*) FROM $table", null).use { it.moveToFirst(); it.getInt(0) }

    private fun seed(vararg rows: DnsEvent) = runBlocking { db.dnsEventDao().insertAll(rows.toList()) }

    private fun dns(pkg: String, domain: String, ts: Long) = DnsEvent(
        timestamp = ts, domain = domain, appUid = 10_100, appName = pkg, isBlocked = false, reason = null,
    )

    private fun codeDetail(pkg: String, trackerId: Int) =
        runBlocking { db.privacyDao().codeDetail(latest().id, pkg, trackerId) }

    private fun domainDetail(pkg: String, trackerId: Int) =
        runBlocking { db.privacyDao().domainDetail(latest().id, pkg, trackerId) }

    private fun rowsOfScan(table: String, scanId: Long): Int =
        db.query("SELECT COUNT(*) FROM $table WHERE scanId = $scanId", null).use { it.moveToFirst(); it.getInt(0) }

    @Test fun `a scan records the matching packages of each tracker found in code`() {
        inspector.apps = listOf(app("a"))
        inspector.packages["a"] = setOf("com.flurry.sdk", "com.flurry.android", "com.example.ui")
        scan(runner())
        val row = codeDetail("a", FLURRY).single()
        assertEquals("CODE_PREFIX", row.kind)
        assertEquals("com.flurry", row.signature)
        assertEquals(listOf("com.flurry.android", "com.flurry.sdk"), PrivacyDetailRows.packagesOf(row))
        assertEquals(2, row.packageCount)
    }

    @Test fun `a scan records each looked-up tracker domain`() {
        seed(
            dns("a", "x.flurry.com", 80 * DAY), dns("a", "x.flurry.com", 81 * DAY),
            dns("a", "Y.flurry.com.", 82 * DAY),
        )
        inspector.apps = listOf(app("a"))
        scan(runner())
        val rows = domainDetail("a", FLURRY)
        assertEquals(listOf("x.flurry.com" to 2, "Y.flurry.com." to 1), rows.map { it.domain to it.lookups })
        assertTrue(rows.all { it.kind == "DOMAIN_SUFFIX" && it.signature == "flurry.com" })
        assertEquals(requireNotNull(evidence("a", FLURRY)).lookups, rows.sumOf { it.lookups })
    }

    @Test fun `a scan marks that details were recorded`() {
        inspector.apps = listOf(app("a"))
        scan(runner())
        assertTrue(latest().hasDetails)
    }

    @Test fun `an app that could not be inspected has no code detail`() {
        inspector.apps = listOf(app("a"))
        inspector.packages["a"] = setOf("com.flurry.sdk")
        inspector.onInspect = { throw java.io.IOException("bad zip") }
        scan(runner())
        assertEquals(0, count("privacy_code_detail"))
    }

    @Test fun `a failed network step leaves no domain detail`() {
        seed(dns("a", "ads.doubleclick.net", 80 * DAY))
        val real = db.dnsEventDao()
        val dns = object : DnsEventDao by real {
            override suspend fun coverageDaysSince(since: Long): Int = error("db locked")
        }
        inspector.apps = listOf(app("a"))
        inspector.packages["a"] = setOf("com.flurry.sdk")
        scan(runner(dns = dns))
        assertEquals(NetworkStatus.FAILED.name, latest().networkStatus)
        assertEquals(0, count("privacy_domain_detail"))
        assertEquals(1, count("privacy_code_detail"))
    }

    @Test fun `details of the previous scan are deleted when a newer scan completes`() {
        seed(dns("a", "x.flurry.com", 80 * DAY))
        inspector.apps = listOf(app("a"))
        inspector.packages["a"] = setOf("com.flurry.sdk")
        val r = runner()
        scan(r)
        val first = latest().id
        assertEquals(1, rowsOfScan("privacy_code_detail", first))
        scan(r)
        assertEquals(0, rowsOfScan("privacy_code_detail", first))
        assertEquals(0, rowsOfScan("privacy_domain_detail", first))
        assertEquals(1, rowsOfScan("privacy_code_detail", latest().id))
        assertEquals(1, rowsOfScan("privacy_domain_detail", latest().id))
    }

    @Test fun `detail rows of a scan that never finished are deleted by the next completed scan`() {
        val dao = db.privacyDao()
        val orphan = runBlocking {
            dao.insertScan(
                PrivacyScan(
                    startedAt = 1, finishedAt = null, appsTotal = 1, appsInspected = 0, appsPartial = 0,
                    appsFailed = 0, registrySize = 3, registrySha256 = "sha-a", dnsWindowStart = 0,
                    dnsCoverageDays = 0, usageCoverageFrom = null, networkStatus = NetworkStatus.PENDING.name,
                    hasDetails = true,
                ),
            ).also { id ->
                dao.upsertCodeDetail(
                    listOf(PrivacyCodeDetail(id, "a", FLURRY, "CODE_PREFIX", "com.flurry", 1, "com.flurry.x")),
                )
                dao.upsertDomainDetail(
                    listOf(
                        PrivacyDomainDetail(id, "a", FLURRY, "x.flurry.com", "DOMAIN_SUFFIX", "flurry.com", 1, 1, null,
                            1, 1),
                    ),
                )
            }
        }
        inspector.apps = listOf(app("a"))
        scan(runner())
        assertEquals(0, rowsOfScan("privacy_code_detail", orphan))
        assertEquals(0, rowsOfScan("privacy_domain_detail", orphan))
    }

    @Test fun `Delete privacy results deletes the details`() {
        seed(dns("a", "x.flurry.com", 80 * DAY))
        inspector.apps = listOf(app("a"))
        inspector.packages["a"] = setOf("com.flurry.sdk")
        val r = runner()
        scan(r)
        assertTrue(count("privacy_code_detail") > 0 && count("privacy_domain_detail") > 0)
        assertTrue(runBlocking { r.deleteAll() })
        assertEquals(0, count("privacy_code_detail"))
        assertEquals(0, count("privacy_domain_detail"))
    }

    @Test fun `the trackers found in code are the same with detail recorded`() {
        inspector.apps = listOf(app("a"), app("b"))
        inspector.packages["a"] = setOf("com.flurry.sdk", "com.google.android.gms.ads.AdView", "com.example")
        inspector.packages["b"] = setOf("io.other.x")
        scan(runner())
        assertEquals(
            setOf("a" to FLURRY, "a" to ADMOB, "b" to OTHER),
            evidence().filter { it.inCode }.map { it.packageName to it.trackerId }.toSet(),
        )
        assertEquals(
            setOf("a" to FLURRY, "a" to ADMOB, "b" to OTHER),
            listOf("a", "b").flatMap { p ->
                listOf(FLURRY, ADMOB, OTHER).filter { codeDetail(p, it).isNotEmpty() }.map { p to it }
            }.toSet(),
        )
    }
}
