package com.androdr.ioc

import com.androdr.data.db.FeedHealthDao
import com.androdr.data.model.FeedHealth
import com.androdr.data.repo.CveRepository
import com.androdr.sigma.SigmaRule
import com.androdr.sigma.SigmaRuleEngine
import com.androdr.sigma.SigmaRuleFeed
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.mockk
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
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
class IntelRefresherTest {

    private val dao = mockk<FeedHealthDao>(relaxed = true)
    private val recorder = FeedHealthRecorder(dao)

    private val indicatorUpdater = mockk<IndicatorUpdater>()
    private val knownAppUpdater = mockk<KnownAppUpdater>()
    private val publicRepoIocFeed = mockk<PublicRepoIocFeed>()
    // relaxed: refreshPublicRepoIoc calls the Unit refreshCache() on success.
    private val knownAppResolver = mockk<KnownAppResolver>(relaxed = true)
    private val oemPrefixResolver = mockk<OemPrefixResolver>()
    private val sigmaRuleFeed = mockk<SigmaRuleFeed>()
    // relaxed: refreshSigmaRules calls the Unit setRemoteRules(...) on success.
    private val sigmaRuleEngine = mockk<SigmaRuleEngine>(relaxed = true)
    // relaxed: refreshCveDatabase logs getActivelyExploitedCount() on success.
    private val cveRepository = mockk<CveRepository>(relaxed = true)

    private fun refresher() = IntelRefresher(
        indicatorUpdater, knownAppUpdater, publicRepoIocFeed, knownAppResolver,
        oemPrefixResolver, sigmaRuleFeed, sigmaRuleEngine, cveRepository, recorder,
    )

    private fun allFeedsSucceed() {
        coEvery { indicatorUpdater.update() } returns 100
        coEvery { knownAppUpdater.update() } returns 50
        coEvery { publicRepoIocFeed.update() } returns 200
        coEvery { oemPrefixResolver.refresh() } returns 10
        coEvery { sigmaRuleFeed.fetch() } returns listOf(mockk<SigmaRule>(), mockk<SigmaRule>())
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
        assertEquals(2, report.sigmaRemoteRules)
        assertEquals(5, report.cveReachable)
        assertEquals(150, report.bulkFetchedCount)

        // A success row (lastSuccessAt stamped, streak cleared) for all six feeds.
        for (feedId in listOf(
            FeedHealthRecorder.FEED_INDICATORS,
            FeedHealthRecorder.FEED_KNOWN_APPS,
            FeedHealthRecorder.FEED_PUBLIC_REPO_IOC,
            FeedHealthRecorder.FEED_OEM_PREFIXES,
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
        // The skip must record nothing: only the first refresh's 6 rows exist,
        // so a regressed skip guard that re-ran the feeds would push this past 6.
        coVerify(exactly = 6) { dao.upsert(any()) }
    }
}
