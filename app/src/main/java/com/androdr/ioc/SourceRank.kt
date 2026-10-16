package com.androdr.ioc

import com.androdr.ioc.feeds.HaGeZiTifFeed
import com.androdr.ioc.feeds.MalwareBazaarCertFeed
import com.androdr.ioc.feeds.StalkerwareCertHashFeed
import com.androdr.ioc.feeds.StalkerwareIndicatorsFeed
import com.androdr.ioc.feeds.ThreatFoxDomainFeed

/** Single source of truth for "which feed's attribution wins" for a shared (type, value). */
object SourceRank {
    const val RULES_REPO = "androdr_public_repo"
    const val MVT_PREFIX = "mvt_"
    // Higher wins. Unknown sources rank LOWEST, so an unranked feed can never overwrite a ranked one.
    private val RANKS = mapOf(
        RULES_REPO to 100,
        StalkerwareIndicatorsFeed.SOURCE_ID to 60,            // packages
        StalkerwareCertHashFeed.SOURCE_ID to 60,              // certs
        MalwareBazaarCertFeed.SOURCE_ID to 40,                // certs, below the curated stalkerware certs
        ThreatFoxDomainFeed.SOURCE_ID to 20,
        HaGeZiTifFeed.SOURCE_ID to 10,
    )
    const val MVT_RANK = 80

    fun of(sourceId: String): Int = when {
        sourceId.startsWith(MVT_PREFIX) -> MVT_RANK          // per-collection mvt_<slug> ids
        else -> RANKS[sourceId] ?: 0
    }

    /** Explicit sources ranked above [sourceId] (for the owned-values query) and whether MVT is among them. */
    fun above(sourceId: String): Pair<List<String>, Boolean> =
        RANKS.filterValues { it > of(sourceId) }.keys.toList() to (MVT_RANK > of(sourceId))

    fun isRanked(sourceId: String): Boolean = sourceId.startsWith(MVT_PREFIX) || sourceId in RANKS
}
