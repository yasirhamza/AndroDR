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
    private val knownAppUpdater:  KnownAppUpdater  = mockk()

    @Test
    fun `runAllUpdaters calls all three updaters and sums counts`() = runTest {
        coEvery { remoteIocUpdater.update() } returns 10
        coEvery { domainIocUpdater.update() } returns 20
        coEvery { knownAppUpdater.update()  } returns 15

        val total = runAllUpdaters(remoteIocUpdater, domainIocUpdater, knownAppUpdater)

        assertEquals(45, total)
        coVerify { remoteIocUpdater.update() }
        coVerify { domainIocUpdater.update() }
        coVerify { knownAppUpdater.update()  }
    }

    @Test
    fun `runAllUpdaters propagates exception when updater throws`() = runTest {
        coEvery { remoteIocUpdater.update() } throws RuntimeException("network error")
        coEvery { domainIocUpdater.update() } returns 5
        coEvery { knownAppUpdater.update()  } returns 15

        try {
            runAllUpdaters(remoteIocUpdater, domainIocUpdater, knownAppUpdater)
            fail("Expected RuntimeException to be thrown")
        } catch (e: RuntimeException) {
            assertEquals("network error", e.message)
        }
    }
}
