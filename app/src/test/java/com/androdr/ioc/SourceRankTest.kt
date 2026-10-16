package com.androdr.ioc

import com.androdr.di.AppModule
import com.androdr.ioc.feeds.HaGeZiTifFeed
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class SourceRankTest {
    @Test
    fun `every feed wired in AppModule is ranked`() {
        val ids = AppModule.provideDomainIocFeeds().map { it.sourceId } +
            AppModule.provideCertHashIocFeeds().map { it.sourceId } +
            AppModule.providePackageIocFeeds().map { it.sourceId }
        assertTrue(ids.isNotEmpty())
        ids.forEach { assertTrue("feed '$it' has no SourceRank entry", SourceRank.isRanked(it)) }
    }

    @Test
    fun `unknown sources rank lowest`() {
        assertTrue(SourceRank.of("unknown") < SourceRank.of(HaGeZiTifFeed.SOURCE_ID))
        assertEquals(0, SourceRank.of("unknown"))
    }

    @Test
    fun `per-collection MVT ids rank as MVT`() {
        assertEquals(SourceRank.MVT_RANK, SourceRank.of("mvt_nso_group_pegasus_indicators_of_compromise"))
    }

    @Test
    fun `rules repo outranks everything`() {
        assertTrue(SourceRank.of(SourceRank.RULES_REPO) > SourceRank.MVT_RANK)
    }
}
