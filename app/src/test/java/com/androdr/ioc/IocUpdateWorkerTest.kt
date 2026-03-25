package com.androdr.ioc

import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.mockk
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.fail
import org.junit.Test

class IocUpdateWorkerTest {

    private val remoteIocUpdater: RemoteIocUpdater = mockk()
    private val domainIocUpdater: DomainIocUpdater = mockk()

    @Test
    fun `doWork calls both remoteIocUpdater and domainIocUpdater`() = runTest {
        coEvery { remoteIocUpdater.update() } returns 10
        coEvery { domainIocUpdater.update() } returns 20

        // Call the shared logic directly (extracted to internal fun for testability)
        val total = runBothUpdaters(remoteIocUpdater, domainIocUpdater)

        assertEquals(30, total)
        coVerify { remoteIocUpdater.update() }
        coVerify { domainIocUpdater.update() }
    }

    @Test
    fun `runBothUpdaters propagates exception when updater throws`() = runTest {
        coEvery { remoteIocUpdater.update() } throws RuntimeException("network error")
        coEvery { domainIocUpdater.update() } returns 5

        try {
            runBothUpdaters(remoteIocUpdater, domainIocUpdater)
            fail("Expected RuntimeException to be thrown")
        } catch (e: RuntimeException) {
            assertEquals("network error", e.message)
        }
    }
}
