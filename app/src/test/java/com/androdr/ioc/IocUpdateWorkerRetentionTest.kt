package com.androdr.ioc

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.work.ListenableWorker
import androidx.work.WorkerParameters
import com.androdr.data.repo.ScanRepository
import com.androdr.data.repo.TimelineRowDeleter
import com.androdr.data.store.StoreFixture
import com.androdr.data.store.TelemetryRetention
import com.androdr.sigma.SigmaRuleEngine
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.coVerifyOrder
import io.mockk.mockk
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

/** Spec §5.1 Retention: the 12 h IOC worker runs retention after the IOC fetch. */
@RunWith(RobolectricTestRunner::class)
class IocUpdateWorkerRetentionTest {
    private val f = StoreFixture()
    private val refresher = mockk<IntelRefresher>(relaxed = true)
    private val retention = mockk<TelemetryRetention>(relaxed = true)

    @After fun tearDown() = f.close()

    private fun worker() = IocUpdateWorker(
        ApplicationProvider.getApplicationContext<Context>(), mockk<WorkerParameters>(relaxed = true),
        refresher, mockk<SigmaRuleEngine>(relaxed = true), mockk<ScanRepository>(relaxed = true), f.db,
        TimelineRowDeleter(f.db.forensicTimelineEventDao(), f.store, f.db.signalMemberDao()), retention,
    )

    @Test
    fun `retention runs after the IOC fetch`() = runBlocking {
        assertEquals(ListenableWorker.Result.success(), worker().doWork())
        coVerifyOrder {
            refresher.refreshAll(any())
            retention.run(any())
        }
    }

    /** Review m2: storage upkeep does not depend on the network fetch succeeding. */
    @Test
    fun `retention still runs when the IOC fetch fails, and the fetch is retried`() = runBlocking {
        coEvery { refresher.refreshAll(any()) } throws java.io.IOException("offline")
        assertEquals(ListenableWorker.Result.retry(), worker().doWork())
        coVerify { retention.run(any()) }
    }

    /** Review m1: a stopped worker is cancelled, never turned into a retry. */
    @Test
    fun `cancellation of the fetch propagates`() {
        coEvery { refresher.refreshAll(any()) } throws CancellationException("stopped")
        assertTrue(runCatching { runBlocking { worker().doWork() } }.exceptionOrNull() is CancellationException)
    }

    @Test
    fun `a failed retention pass does not fail or retry the IOC update`() = runBlocking {
        coEvery { retention.run(any()) } throws IllegalStateException("batch failed")
        assertEquals(ListenableWorker.Result.success(), worker().doWork())
    }
}
