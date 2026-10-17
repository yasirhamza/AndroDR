package com.androdr.ioc

import com.androdr.data.db.FeedHealthDao
import com.androdr.data.model.FeedHealth
import com.androdr.data.model.Indicator
import com.androdr.data.repo.CveRepository
import com.androdr.sigma.SigmaRule
import com.androdr.sigma.SigmaRuleEngine
import com.androdr.sigma.SigmaRuleFeed
import io.mockk.coEvery
import io.mockk.verify
import io.mockk.every
import io.mockk.coVerify
import io.mockk.mockk
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.advanceUntilIdle
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Guards the shared refresh path (#244). Every entry point — the periodic
 * worker, the pre-scan refresh, and the manual Settings "Update" button — routes
 * through [IntelRefresher.refreshAll], so proving refreshAll records feed_health
 * for every feed proves the manual path records it too. The manual bug was that
 * SettingsViewModel called the updaters directly and wrote no health row; that is
 * now structurally impossible (the updaters are no longer injected there).
 */
@OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)
class IntelRefresherTest {

    private val dao = mockk<FeedHealthDao>(relaxed = true)
    private val recorder = FeedHealthRecorder(dao)

    private val indicatorUpdater = mockk<IndicatorUpdater>()
    private val knownAppUpdater = mockk<KnownAppUpdater>()
    private val publicRepoIocFeed = mockk<PublicRepoIocFeed>()
    // relaxed: refreshPublicRepoIoc calls the Unit refreshCache() on success.
    private val knownAppResolver = mockk<KnownAppResolver>(relaxed = true)
    private val oemPrefixResolver = mockk<OemPrefixResolver>()
    private val brandImpersonationResolver = mockk<BrandImpersonationResolver>()
    private val sigmaRuleFeed = mockk<SigmaRuleFeed>()
    // relaxed: refreshSigmaRules calls the Unit setRemoteRules(...) on success.
    private val sigmaRuleEngine = mockk<SigmaRuleEngine>(relaxed = true)
    // relaxed: refreshCveDatabase logs getActivelyExploitedCount() on success.
    private val cveRepository = mockk<CveRepository>(relaxed = true)

    private fun refresher(indicatorResolver: IndicatorResolver = mockk(relaxed = true)) = IntelRefresher(
        indicatorUpdater, indicatorResolver, knownAppUpdater, publicRepoIocFeed, knownAppResolver,
        oemPrefixResolver, brandImpersonationResolver, sigmaRuleFeed, sigmaRuleEngine,
        cveRepository, recorder,
    )

    private fun allFeedsSucceed() {
        coEvery { indicatorUpdater.update(any()) } returns 100
        coEvery { knownAppUpdater.update() } returns 50
        coEvery { publicRepoIocFeed.update() } returns UpdateResult(written = 200, evicted = 0)
        coEvery { oemPrefixResolver.refresh() } returns 10
        coEvery { brandImpersonationResolver.refresh() } returns 25
        coEvery { sigmaRuleFeed.fetch() } returns listOf(mockk<SigmaRule>(), mockk<SigmaRule>())
        every { sigmaRuleFeed.lastRejected } returns emptyList()
        coEvery { cveRepository.refresh() } returns 5
    }

    @Test
    fun `refreshAll records health for every feed and reports per-feed counts`() = runTest {
        allFeedsSucceed()

        val report = refresher().refreshAll(skipIfRefreshedWithinMs = 0L)

        assertFalse(report.skipped)
        assertEquals(100, report.indicators)
        assertEquals(50, report.knownApps)
        assertEquals(10, report.oemPrefixes)
        assertEquals(25, report.brandRegistry)
        assertEquals(2, report.sigmaRemoteRules)
        assertEquals(5, report.cveReachable)
        assertEquals(150, report.bulkFetchedCount)

        // A success row (lastSuccessAt stamped, streak cleared) for all seven feeds.
        for (feedId in listOf(
            FeedHealthRecorder.FEED_INDICATORS,
            FeedHealthRecorder.FEED_KNOWN_APPS,
            FeedHealthRecorder.FEED_PUBLIC_REPO_IOC,
            FeedHealthRecorder.FEED_OEM_PREFIXES,
            FeedHealthRecorder.FEED_BRAND_REGISTRY,
            FeedHealthRecorder.FEED_SIGMA_RULES,
            FeedHealthRecorder.FEED_CVE,
        )) {
            coVerify {
                dao.upsert(match<FeedHealth> {
                    it.feedId == feedId && it.lastSuccessAt > 0L && it.consecutiveFailures == 0
                })
            }
        }
    }

    @Test
    fun `a single feed failure still records health for the others and does not abort`() = runTest {
        allFeedsSucceed()
        // CVE feed unreachable this run (returns 0 = failure per the empty-is-failure contract).
        coEvery { cveRepository.refresh() } returns 0
        coEvery { dao.get(FeedHealthRecorder.FEED_CVE) } returns null

        val report = refresher().refreshAll(skipIfRefreshedWithinMs = 0L)

        assertEquals(0, report.cveReachable)
        assertEquals(100, report.indicators) // the rest still ran
        // CVE recorded as a failure (streak incremented, no success stamp).
        coVerify {
            dao.upsert(match<FeedHealth> {
                it.feedId == FeedHealthRecorder.FEED_CVE && it.consecutiveFailures == 1
            })
        }
        // A healthy sibling still got its success row.
        coVerify {
            dao.upsert(match<FeedHealth> {
                it.feedId == FeedHealthRecorder.FEED_SIGMA_RULES && it.lastSuccessAt > 0L
            })
        }
    }

    @Test
    fun `skip window returns a skipped report and records nothing`() = runTest {
        allFeedsSucceed()
        val refresher = refresher()
        refresher.refreshAll(skipIfRefreshedWithinMs = 0L) // establishes lastRefreshAt

        val second = refresher.refreshAll(skipIfRefreshedWithinMs = Long.MAX_VALUE)

        assertTrue("second refresh within the window must skip", second.skipped)
        assertEquals(0, second.bulkFetchedCount)
        // The skip must record nothing: only the first refresh's 7 rows exist,
        // so a regressed skip guard that re-ran the feeds would push this past 7.
        coVerify(exactly = 7) { dao.upsert(any()) }
    }

    @Test
    fun `the rules a fetch loaded reach the engine together with the files it rejected`() = runTest {
        // #288: the rejections describe the rule set they were fetched with. Handing
        // them over separately would let a later empty fetch clear them while the
        // engine kept the rule set, and a still-missing rule would read as resolved.
        allFeedsSucceed()
        val rejected = listOf(SigmaRuleFeed.RejectedRuleFile("x.yml", "androdr-950", "unknown field"))
        every { sigmaRuleFeed.lastRejected } returns rejected

        refresher().refreshAll()

        verify { sigmaRuleEngine.setRemoteRules(any(), rejected) }
    }

    // ── One cache rebuild per refresh, after the rules-repo write (plan B1) ──

    @Test
    fun `rows written only by the rules-repo feed are visible when refreshAll returns`() = runTest {
        allFeedsSucceed()
        val fakeDao = FakeIndicatorDao()
        val bundledPackages = mockk<IocDatabase>()
        every { bundledPackages.isKnownBadPackage(any()) } returns null
        val resolver = IndicatorResolver(
            fakeDao, bundledPackages, mockk(relaxed = true), mockk(relaxed = true), mockk(relaxed = true)
        )
        coEvery { publicRepoIocFeed.update() } coAnswers {
            fakeDao.upsertAll(listOf(
                Indicator(type = "package", value = "com.rules.only", family = "RulesFam",
                    source = PublicRepoIocFeed.SOURCE_ID, fetchedAt = 1L),
                Indicator(type = "domain", value = "rules-only.example", family = "RulesFam",
                    source = PublicRepoIocFeed.SOURCE_ID, fetchedAt = 1L),
            ))
            UpdateResult(written = 2, evicted = 0)
        }

        refresher(resolver).refreshAll()

        assertNotNull(resolver.isKnownBadPackage("com.rules.only"))
        assertNotNull(resolver.isKnownBadDomain("rules-only.example"))
    }

    @Test
    fun `refreshAll rebuilds the resolver cache exactly once whatever the rules-repo update did`() = runTest {
        for (result in listOf(
            UpdateResult(written = 5, evicted = 0),
            UpdateResult(written = 0, evicted = 3),
            UpdateResult(written = 0, evicted = 0),
        )) {
            allFeedsSucceed()
            coEvery { publicRepoIocFeed.update() } returns result
            val resolver = mockk<IndicatorResolver>(relaxed = true)

            refresher(resolver).refreshAll()

            coVerify(exactly = 1) { resolver.refreshCache() }
            coVerify { indicatorUpdater.update(refreshCache = false) }
        }
    }

    @Test
    fun `a cancelled refresh still rebuilds the cache once`() = runTest {
        allFeedsSucceed()
        val started = CompletableDeferred<Unit>()
        coEvery { knownAppUpdater.update() } coAnswers { started.complete(Unit); awaitCancellation() }
        val resolver = mockk<IndicatorResolver>(relaxed = true)

        val job = launch(start = CoroutineStart.UNDISPATCHED) { refresher(resolver).refreshAll() }
        advanceUntilIdle()
        started.await()
        job.cancelAndJoin()

        coVerify(exactly = 1) { resolver.refreshCache() }
    }

    @Test
    fun `a failing cache rebuild does not stop the later steps`() = runTest {
        allFeedsSucceed()
        val resolver = mockk<IndicatorResolver>()
        coEvery { resolver.refreshCache() } throws IllegalStateException("boom")

        val report = refresher(resolver).refreshAll()

        assertEquals(5, report.cveReachable)
        assertEquals(10, report.oemPrefixes)
        coVerify { cveRepository.refresh() }
    }
}
