package com.androdr.cellular

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class RadioStateStoreTest {

    @Test
    fun `first observation has no previous values`() {
        val d = RadioStateStore().record(tac = 100, rat = "LTE", atMillis = 0L)
        assertNull(d.previousTac)
        assertNull(d.previousRat)
        assertFalse(d.tacChanged)
        assertFalse(d.ratChanged)
        assertEquals(0, d.tacChangesLast5m)
    }

    @Test
    fun `tac change is reported and counted`() {
        val store = RadioStateStore()
        store.record(100, "LTE", 0L)
        val d = store.record(101, "LTE", 1_000L)
        assertEquals(100, d.previousTac)
        assertTrue(d.tacChanged)
        assertEquals(1, d.tacChangesLast5m)
    }

    @Test
    fun `changes outside the window are dropped`() {
        val store = RadioStateStore(windowMillis = 300_000L)
        store.record(100, "LTE", 0L)
        store.record(101, "LTE", 1_000L)
        val d = store.record(102, "LTE", 400_000L)
        assertEquals(1, d.tacChangesLast5m)
    }

    @Test
    fun `churn accumulates within the window`() {
        val store = RadioStateStore()
        store.record(100, "LTE", 0L)
        store.record(101, "LTE", 1_000L)
        store.record(102, "LTE", 2_000L)
        val d = store.record(103, "LTE", 3_000L)
        assertEquals(3, d.tacChangesLast5m)
    }

    @Test
    fun `rat downgrade is reported without a tac change`() {
        val store = RadioStateStore()
        store.record(100, "LTE", 0L)
        val d = store.record(100, "GSM", 1_000L)
        assertEquals("LTE", d.previousRat)
        assertTrue(d.ratChanged)
        assertFalse(d.tacChanged)
    }

    @Test
    fun `a null tac is a real value and transitions to and from it count`() {
        val store = RadioStateStore()
        store.record(100, "LTE", 0L)
        val toNull = store.record(null, "LTE", 1_000L)
        assertTrue("100 -> null is a change", toNull.tacChanged)
        val fromNull = store.record(100, "LTE", 2_000L)
        assertTrue("null -> 100 is a change", fromNull.tacChanged)
        assertEquals(2, fromNull.tacChangesLast5m)
    }
}
