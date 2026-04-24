package com.androdr.ioc

import com.androdr.data.db.IndicatorDao
import com.androdr.data.model.Indicator
import com.androdr.data.model.IocEntry
import io.mockk.mockk
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Migration-safety regression for AndroDR issue #117, Phase 3.
 *
 * Phase 3 prunes 13 entries from the rule-repo's `ioc-data/package-names.yml`
 * because they are duplicated in the upstream `stalkerware-indicators`
 * repository that AndroDR's Kotlin [com.androdr.ioc.feeds.StalkerwareIndicatorsFeed]
 * already fetches directly. The invariant that must hold across the prune is:
 *
 *   For every (type, value) present in the `indicators` Room table BEFORE
 *   the prune ships, that same (type, value) is still present AFTER the
 *   next IocUpdateWorker cycle.
 *
 * The `source` column is allowed to change (from `androdr_public_repo` to
 * `stalkerware_indicators`), but the row itself — which is what the runtime
 * matcher keys on — must survive.
 *
 * This test simulates the IocUpdateWorker.doWork() order with a fake
 * IndicatorDao backed by an in-memory map that honors the REPLACE semantics
 * of `@Insert(onConflict=REPLACE)` and the WHERE clause of
 * `deleteStaleEntries(source, olderThan)`.
 *
 * Why a JVM unit test instead of an emulator run:
 *   - `PublicRepoIocFeed` fetches from the upstream rule-repo's `main`
 *     branch over HTTPS at runtime (not from the git submodule pinned in
 *     AndroDR), so checking out the submodule to a feature branch does not
 *     change on-device behavior.
 *   - Phase 3 is still on a feature branch of the rules repo; it has not
 *     been merged into `main`, so no on-device run can observe the
 *     post-prune state until merge.
 *   - The invariant is a property of the upsert / deleteStaleEntries
 *     ordering in IndicatorUpdater + PublicRepoIocFeed, and is fully
 *     exercised here.
 */
class Phase3MigrationSafetyTest {

    /** The 13 package names Phase 3 removes from the rule-repo. */
    private val prunedPackages = listOf(
        "com.ispyoo",
        "com.mxspy",
        "com.spyzee",
        "com.fp.backup",
        "com.lsdroid.cerberus",
        "com.surebrec",
        "update.service.android",
        "core.update.framework",
        "com.cocospy",
        "com.sc.fonemonitor",
        "com.spyic",
        "com.snapchat.trmonap",
        "com.snapch.monabcab"
    )

    @Test
    @Suppress("LongMethod") // End-to-end migration safety scenario — splitting reduces narrative clarity
    fun `all 13 pruned package rows survive the IocUpdateWorker cycle post-prune`() = runTest {
        val dao = FakeIndicatorDao()

        // ── Pre-prune state ──────────────────────────────────────────────────
        // Seed every one of the 13 packages into the DB with source=androdr_public_repo,
        // fetchedAt=oldTime. This represents the state left by a PRE-prune
        // IocUpdateWorker cycle where PublicRepoIocFeed ran last and wrote the
        // `stalkerware-indicators`-origin rows under its own source id (since
        // the REPLACE insert bumps ownership to the last writer).
        val oldTime = 1_000_000_000L
        val preRows = prunedPackages.map { pkg ->
            Indicator(
                type = IndicatorResolver.TYPE_PACKAGE,
                value = pkg,
                name = "PreexistingFamily",
                campaign = "STALKERWARE",
                severity = "CRITICAL",
                description = "Pre-prune entry",
                source = PublicRepoIocFeed.SOURCE_ID, // "androdr_public_repo"
                fetchedAt = oldTime
            )
        }
        dao.upsertAll(preRows)
        val preSnapshot = dao.snapshot()
        assertEquals(
            "Expected 13 seeded rows before cycle",
            13,
            preSnapshot.size
        )

        // ── Post-prune IocUpdateWorker cycle ─────────────────────────────────
        // IocUpdateWorker.doWork() order, per IocUpdateWorker.kt:
        //   1. runAllUpdaters()   -> IndicatorUpdater.update() (Kotlin feeds, incl. Stalkerware)
        //   2. refreshPublicRepoIoc() -> PublicRepoIocFeed.update()

        // Step 1: StalkerwareIndicatorsFeed returns the 13 packages (they are
        // present in the upstream AssoEchap ioc.yaml that this feed mirrors).
        val newTime = oldTime + 1_000_000L
        val stalkerwareFeed = FakeStalkerwareFeed(prunedPackages, newTime)
        val resolver = mockk<IndicatorResolver>(relaxed = true)
        val updater = IndicatorUpdater(
            dao = dao,
            resolver = resolver,
            domainFeeds = emptyList(),
            certHashFeeds = emptyList(),
            packageFeeds = listOf(stalkerwareFeed)
        )
        updater.update()

        // After Step 1: the 13 rows now have source=stalkerware_indicators
        // (REPLACE semantics — the PK (type,value) collision overwrites the
        // previous androdr_public_repo entry).
        val afterStalkerware = dao.snapshot()
        assertEquals(13, afterStalkerware.size)
        afterStalkerware.values.forEach { row ->
            assertEquals(
                "Stalkerware feed should have taken ownership of row ${row.value}",
                "stalkerware_indicators",
                row.source
            )
            assertEquals(newTime, row.fetchedAt)
        }

        // Step 2: Simulate PublicRepoIocFeed.fetchAndUpsertPackages running
        // against the POST-prune rule-repo — the 13 packages are no longer
        // in package-names.yml, so the feed returns an empty indicators list
        // for those packages (or an entirely different, unrelated set; either
        // way, the 13 are absent). The feed then calls
        // deleteStaleEntries(SOURCE_ID="androdr_public_repo", now-1).
        val publicRepoFetchedAt = newTime + 1_000L
        // Post-prune upsert: simulate an unrelated package present in the
        // rule-repo to exercise the upsert path without touching the 13.
        dao.upsertAll(
            listOf(
                Indicator(
                    type = IndicatorResolver.TYPE_PACKAGE,
                    value = "com.unrelated.newentry",
                    name = "Unrelated",
                    campaign = "STALKERWARE",
                    severity = "CRITICAL",
                    description = "Unrelated post-prune entry",
                    source = PublicRepoIocFeed.SOURCE_ID,
                    fetchedAt = publicRepoFetchedAt
                )
            )
        )
        // Mirror PublicRepoIocFeed.fetchAndUpsertPackages: stale-prune own source.
        dao.deleteStaleEntries(PublicRepoIocFeed.SOURCE_ID, publicRepoFetchedAt - 1)

        // ── Invariant check ──────────────────────────────────────────────────
        val postSnapshot = dao.snapshot()

        // Every (type, value) in preSnapshot must still be present in postSnapshot.
        val prePairs = preSnapshot.keys
        val postPairs = postSnapshot.keys
        val missing = prePairs - postPairs
        assertTrue(
            "Migration-safety invariant violated — missing (type,value) tuples: $missing",
            missing.isEmpty()
        )

        // Spot-check each of the 13 pruned packages explicitly.
        prunedPackages.forEach { pkg ->
            val key = IndicatorResolver.TYPE_PACKAGE to pkg
            val row = postSnapshot[key]
            assertTrue(
                "Pruned package $pkg was deleted by post-prune cycle — regression",
                row != null
            )
            // The row should now be owned by the stalkerware feed.
            assertEquals(
                "Pruned package $pkg should have migrated to stalkerware_indicators source",
                "stalkerware_indicators",
                row!!.source
            )
        }
    }

    @Test
    fun `deleteStaleEntries only targets its own source id`() = runTest {
        // Direct sanity test on the fake dao's WHERE semantics — the
        // invariant hinges on this: delete targets (source=X AND fetchedAt<Y),
        // so a stalkerware_indicators row is immune to the
        // androdr_public_repo stale-prune.
        val dao = FakeIndicatorDao()
        val oldTime = 1_000L
        dao.upsertAll(
            listOf(
                Indicator(
                    type = "package", value = "com.stalker.a", name = "", campaign = "",
                    severity = "CRITICAL", description = "",
                    source = "stalkerware_indicators", fetchedAt = oldTime
                ),
                Indicator(
                    type = "package", value = "com.publicrepo.a", name = "", campaign = "",
                    severity = "CRITICAL", description = "",
                    source = "androdr_public_repo", fetchedAt = oldTime
                )
            )
        )

        // Run the PublicRepoIocFeed-style stale prune with a new cutoff.
        dao.deleteStaleEntries("androdr_public_repo", oldTime + 1000)

        val remaining = dao.snapshot()
        assertEquals(1, remaining.size)
        assertEquals(
            "stalkerware_indicators",
            remaining[("package" to "com.stalker.a")]!!.source
        )
    }

    // ── Fakes ──────────────────────────────────────────────────────────────

    /**
     * In-memory IndicatorDao honoring only the operations IndicatorUpdater +
     * PublicRepoIocFeed exercise: upsertAll (REPLACE semantics keyed by
     * (type,value)) and deleteStaleEntries(source, olderThan).
     */
    private class FakeIndicatorDao : IndicatorDao {
        private val store: MutableMap<Pair<String, String>, Indicator> = mutableMapOf()

        fun snapshot(): Map<Pair<String, String>, Indicator> = store.toMap()

        override suspend fun upsertAll(entries: List<Indicator>) {
            entries.forEach { store[it.type to it.value] = it }
        }

        override suspend fun deleteStaleEntries(source: String, olderThan: Long) {
            val victims = store.entries
                .filter { it.value.source == source && it.value.fetchedAt < olderThan }
                .map { it.key }
            victims.forEach { store.remove(it) }
        }

        override suspend fun lookup(type: String, value: String): Indicator? =
            store[type to value]

        override suspend fun getAllByType(type: String): List<Indicator> =
            store.values.filter { it.type == type }

        override suspend fun getValuesByType(type: String): List<String> =
            store.values.filter { it.type == type }.map { it.value }

        override suspend fun getAll(): List<Indicator> = store.values.toList()

        override suspend fun count(): Int = store.size

        override suspend fun countByType(type: String): Int =
            store.values.count { it.type == type }

        override suspend fun lastFetchTime(source: String): Long? =
            store.values.filter { it.source == source }.maxOfOrNull { it.fetchedAt }

        override suspend fun lastFetchTimeGlobal(): Long? =
            store.values.maxOfOrNull { it.fetchedAt }

        override suspend fun allSources(): List<String> =
            store.values.map { it.source }.distinct().sorted()
    }

    /**
     * Minimal IocFeed fake that simulates StalkerwareIndicatorsFeed returning
     * a fixed list of package names.
     */
    private class FakeStalkerwareFeed(
        private val packages: List<String>,
        private val fetchedAt: Long
    ) : IocFeed {
        override val sourceId: String = "stalkerware_indicators"

        override suspend fun fetch(): List<IocEntry> = packages.map { pkg ->
            IocEntry(
                packageName = pkg,
                name = "StalkerFamily",
                category = "STALKERWARE",
                severity = "CRITICAL",
                description = "Stalkerware — see AssoEchap/stalkerware-indicators",
                source = sourceId,
                fetchedAt = fetchedAt
            )
        }
    }
}
