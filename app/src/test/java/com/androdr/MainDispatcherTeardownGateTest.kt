package com.androdr

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * Final review item 12: a test that sets `Dispatchers.Main` to a real thread (an executor through
 * `asCoroutineDispatcher`) must stop everything that can touch Main before `resetMain()`. A view
 * model coroutine still running on that thread, or resuming into Main from a store thread, while
 * `resetMain()` swaps the delegate makes kotlinx-coroutines-test throw "Dispatchers.Main is used
 * concurrently with setting it" (seen once in CI in TelemetrySettingsViewModelTest's tearDown).
 *
 * The rule, checked on the source: such a file joins its view models' jobs (`cancelAndJoin`),
 * waits for its executor (`awaitTermination`), and calls `resetMain()` only after both.
 */
class MainDispatcherTeardownGateTest {

    private fun testDir(): File = listOf(File("src/test"), File("app/src/test")).first { it.isDirectory }

    @Test
    fun `every real-thread Main test joins its coroutines and stops its executor before resetMain`() {
        val self = "${MainDispatcherTeardownGateTest::class.simpleName}.kt"
        val files = testDir().walkTopDown().filter { it.isFile && it.extension == "kt" && it.name != self }.toList()
        val realMain = files.filter { realThreadMain(it.readText()) }
        assertTrue("the known real-thread Main test is found",
            realMain.any { it.name == "TelemetrySettingsViewModelTest.kt" })
        val problems = realMain.mapNotNull { f -> teardownProblem(f.readText())?.let { "${f.name}: $it" } }
        assertEquals(emptyList<String>(), problems)
    }

    @Test
    fun `the rule rejects the old tearDown and accepts the ordered one`() {
        val setUp = "Dispatchers.setMain(main.asCoroutineDispatcher())\n"
        val old = setUp + "created.forEach { it.viewModelScope.cancel() }\nDispatchers.resetMain()\nmain.shutdownNow()\n"
        assertEquals("cancels without joining its coroutines", teardownProblem(old))
        val noWait = setUp + "job.cancelAndJoin()\nDispatchers.resetMain()\nmain.shutdown()\n"
        assertEquals("does not wait for its executor to stop", teardownProblem(noWait))
        val early = setUp + "job.cancelAndJoin()\nDispatchers.resetMain()\nmain.awaitTermination(1, SECONDS)\n"
        assertEquals("resets Main before its coroutines and executor have stopped", teardownProblem(early))
        val good = setUp + "job.cancelAndJoin()\nmain.awaitTermination(1, SECONDS)\nDispatchers.resetMain()\n"
        assertNull(teardownProblem(good))
    }

    private companion object {
        fun realThreadMain(src: String) = Regex("""setMain\([^)]*asCoroutineDispatcher""").containsMatchIn(src)

        fun teardownProblem(src: String): String? {
            val join = src.indexOf("cancelAndJoin(")
            val await = src.indexOf("awaitTermination(")
            val reset = src.lastIndexOf("resetMain()")
            return when {
                join < 0 -> "cancels without joining its coroutines"
                await < 0 -> "does not wait for its executor to stop"
                reset < join || reset < await -> "resets Main before its coroutines and executor have stopped"
                else -> null
            }
        }
    }
}
