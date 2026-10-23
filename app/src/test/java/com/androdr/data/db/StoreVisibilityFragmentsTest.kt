package com.androdr.data.db

import com.androdr.data.model.SignalMember
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** The shared visibility/pin SQL fragments use their documented fixed aliases and named constants. */
class StoreVisibilityFragmentsTest {

    private val factFragments =
        listOf(PinnedFact.SQL, PinnedFact.UNOBSERVED, VisibleFact.SQL, VisibleFact.PINNED_ORPHAN)

    @Test
    fun `fact fragments refer to the fact only through the fixed alias`() {
        for (sql in factFragments) {
            assertFalse(sql, sql.contains("telemetry_record.id"))
            assertTrue(sql, sql.contains("${PinnedFact.ALIAS}.id"))
        }
    }

    @Test
    fun `the signal pin uses the fact kind constant`() {
        assertTrue(PinnedFact.SQL.contains("m.kind = ${SignalMember.KIND_FACT} "))
    }

    @Test
    fun `row fragment uses its fixed alias for every column`() {
        for (col in listOf("persistent", "scanResultId")) {
            assertTrue(VisibleRow.SQL.contains("${VisibleRow.ALIAS}.$col"))
        }
    }
}
