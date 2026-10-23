package com.androdr.ioc

import androidx.work.NetworkType
import com.androdr.data.db.IndicatorDao
import io.mockk.coEvery
import io.mockk.mockk
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test

class IndicatorRefreshOnEmptyTest {
    private val dao = mockk<IndicatorDao>()

    @Test
    fun `empty table enqueues once`() = runTest {
        coEvery { dao.count() } returns 0
        var calls = 0
        IndicatorRefreshOnEmpty.maybeEnqueue(dao) { calls++ }
        assertEquals(1, calls)
    }

    @Test
    fun `non-empty table does not enqueue`() = runTest {
        coEvery { dao.count() } returns 5
        var calls = 0
        IndicatorRefreshOnEmpty.maybeEnqueue(dao) { calls++ }
        assertEquals(0, calls)
    }

    @Test
    fun `request is not expedited and requires a network`() {
        val spec = IndicatorRefreshOnEmpty.buildEmptyTableRefreshRequest().workSpec
        assertFalse(spec.expedited)
        assertEquals(NetworkType.CONNECTED, spec.constraints.requiredNetworkType)
    }
}
