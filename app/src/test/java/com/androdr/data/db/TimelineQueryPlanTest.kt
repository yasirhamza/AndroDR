package com.androdr.data.db

import androidx.sqlite.db.SimpleSQLiteQuery
import com.androdr.data.model.TelemetrySource
import com.androdr.data.model.TimelineRowEntity
import com.androdr.data.store.StoreFixture
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

/**
 * T1 query plans (spec §6, §9): for every filter shape and every page direction, each Timeline arm
 * walks an index in its order — no `USE TEMP B-TREE` and no full table scan — and no statement
 * uses OFFSET. Counts never sort either.
 */
@RunWith(RobolectricTestRunner::class)
class TimelineQueryPlanTest {
    private val f = StoreFixture()

    @After fun tearDown() = f.close()

    private fun plan(sql: TimelineSql): List<String> = f.db.openHelper.readableDatabase
        .query(SimpleSQLiteQuery("EXPLAIN QUERY PLAN ${sql.sql}", sql.args.toTypedArray()))
        .use { c -> buildList { while (c.moveToNext()) add(c.getString(c.getColumnIndexOrThrow("detail"))) } }

    /**
     * A plan line that reads a whole table rather than an index range or an index in order. Reading
     * back a `LIMIT`ed arm's co-routine (`SCAN (subquery-N)`) or the count's constant row is bounded.
     */
    private fun fullScan(line: String): Boolean {
        val t = line.replace(Regex("^[|`\\s-]+"), "")
        return t.startsWith("SCAN") && !t.contains("USING INDEX") && !t.contains("USING COVERING INDEX") &&
            !t.startsWith("SCAN (subquery") && t != "SCAN CONSTANT ROW"
    }

    private val shapes: Map<String, TimelineFilter> = buildMap {
        val bases = mapOf(
            "all" to TimelineFilter(),
            "scan" to TimelineFilter(scanId = 7L),
            "package" to TimelineFilter(packageName = "com.x"),
            "source" to TimelineFilter(source = IMPORT),
            "scan+package+source" to TimelineFilter(scanId = 7L, packageName = "com.x", source = IMPORT),
            "package+source" to TimelineFilter(packageName = "com.x", source = IMPORT),
        )
        for ((name, base) in bases) {
            put(name, base)
            put("$name+range", base.copy(from = 1_000L, to = 9_000L))
            put("$name+levels", base.copy(levels = setOf("HIGH", "critical")))
            put("$name+findings", base.copy(findingsAndEvidenceOnly = true))
            // C5 search: a contains-match filters the shape's ordered index walk.
            put("$name+search", base.copy(query = SEARCH))
            put("$name+search+range", base.copy(query = SEARCH, from = 1_000L, to = 9_000L))
            put("$name+search+levels", base.copy(query = SEARCH, levels = setOf("HIGH")))
            put("$name+search+findings", base.copy(query = SEARCH, findingsAndEvidenceOnly = true))
        }
    }

    private val keys = listOf(
        TimelineKey(5_000L, TimelineRowEntity.ROW, 42L),
        TimelineKey(5_000L, TimelineRowEntity.FACT, 42L),
    )

    private fun statements(): List<Pair<String, TimelineSql>> = buildList {
        for ((name, filter) in shapes) {
            for (direction in TimelineDirection.entries) {
                add("$name $direction null" to TimelineQueries.page(filter, null, direction, 100))
                for (key in keys) add("$name $direction $key" to TimelineQueries.page(filter, key, direction, 100))
            }
        }
    }

    @Test
    fun `every page arm of every shape walks an index without sorting`() {
        val all = statements()
        assertTrue("built ${all.size}", all.size > 200)
        val bad = all.mapNotNull { (name, sql) ->
            val p = plan(sql)
            val sorts = p.filter { "TEMP B-TREE" in it }
            val scans = p.filter(::fullScan)
            if (sorts.isEmpty() && scans.isEmpty()) null else "$name:\n${sql.sql}\n${p.joinToString("\n")}"
        }
        assertTrue(bad.joinToString("\n\n"), bad.isEmpty())
    }

    /** Q1 for the Timeline's built SQL (the source gate sees only `@Query` strings). */
    @Test
    fun `every built statement applies the visibility rules`() {
        val all = statements().map { it.second } + shapes.values.map { TimelineQueries.count(it) }
        val bad = all.filter { q ->
            val rowsOk = "FROM forensic_timeline r" !in q.sql || VisibleRow.SQL in q.sql
            val factsOk = "telemetry_record f" !in q.sql || VisibleFact.SQL in q.sql ||
                (CompleteScan.SQL in q.sql && "JOIN ScanResult s ON s.id = o.scanId" in q.sql)
            !(rowsOk && factsOk)
        }
        assertTrue(bad.joinToString("\n") { it.sql }, bad.isEmpty())
    }

    /** UNION ALL matches columns by position: both arms must select the same columns in the same order. */
    @Test
    fun `both arms of every page select the same columns in the same order`() {
        val alias = Regex("""\bAS (\w+)""")
        for ((name, sql) in statements()) {
            val arms = sql.sql.split(" UNION ALL ").map { arm ->
                alias.findAll(arm.removePrefix("SELECT * FROM (").substringBefore(" FROM "))
                    .map { it.groupValues[1] }.toList()
            }
            assertTrue("$name: $arms", arms.first().size == 15)
            assertTrue("$name: $arms", arms.all { it == arms.first() })
        }
    }

    @Test
    fun `fact arms use the shape's index`() {
        fun factPlan(filter: TimelineFilter) = plan(TimelineQueries.page(filter, null, TimelineDirection.FROM, 10))
        assertTrue(factPlan(TimelineFilter()).any { "index_telemetry_record_eventTime" in it })
        assertTrue(factPlan(TimelineFilter(packageName = "p"))
            .any { "index_telemetry_record_packageName_eventTime" in it })
        assertTrue(factPlan(TimelineFilter(scanId = 1L)).any { "index_scan_record_scanId_eventTime" in it })
    }

    /**
     * C5: the search shape's plan. A contains-match (`%q%`) cannot use an index, so each arm of a
     * searched page must walk exactly the index its unsearched shape walks (the query only filters
     * that ordered walk, never trades it for another index and a sort), and every LIKE escapes.
     */
    @Test
    fun `the search shape walks the same index as its base shape, and every LIKE escapes`() {
        for ((name, base) in shapes.filterKeys { "search" !in it }) {
            for (direction in TimelineDirection.entries) {
                for (key in listOf(null) + keys) {
                    val plain = plan(TimelineQueries.page(base, key, direction, 100))
                    val searched = plan(TimelineQueries.page(base.copy(query = SEARCH), key, direction, 100))
                    assertEquals("$name $direction $key", plain, searched)
                }
            }
            // A searched count walks the indexes the unsearched count walks (search adds no scan or
            // sort); it reads the searched columns from the row, so a covering index becomes a plain one.
            fun walk(sql: TimelineSql) = plan(sql).map { it.replace("USING COVERING INDEX", "USING INDEX") }
            assertEquals("$name count", walk(TimelineQueries.count(base)),
                walk(TimelineQueries.count(base.copy(query = SEARCH))))
        }
        val searched = shapes.filterKeys { "search" in it }.values
        val sqls = searched.map { TimelineQueries.page(it, null, TimelineDirection.FROM, 100).sql } +
            searched.map { TimelineQueries.count(it).sql }
        for (sql in sqls) {
            val likes = Regex("""LIKE \?( ESCAPE '\\')?""").findAll(sql).toList()
            assertTrue(sql, likes.isNotEmpty() && likes.all { it.groupValues[1].isNotEmpty() })
        }
    }

    @Test
    fun `counts never sort, and no statement uses OFFSET`() {
        val counts = shapes.values.map { TimelineQueries.count(it) }
        val sorting = counts.filter { c -> plan(c).any { "TEMP B-TREE" in it } }
        assertTrue(sorting.joinToString("\n") { it.sql }, sorting.isEmpty())
        val offsets = (statements().map { it.second } + counts).filter { "OFFSET" in it.sql.uppercase() }
        assertTrue(offsets.isEmpty())
    }

    private companion object {
        val IMPORT = TelemetrySource.BUGREPORT_IMPORT

        /** A query holding both LIKE wildcards and the escape character. */
        const val SEARCH = "ov%er_la\\y"
    }
}
