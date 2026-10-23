package com.androdr.ui.security

import android.app.Activity
import android.content.Intent
import androidx.activity.ComponentActivity
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows.shadowOf

/** Keyguard-intent path (API 26-29) of [PlatformCredentialUi]; the BiometricPrompt path is on-device only. */
@RunWith(RobolectricTestRunner::class)
class PlatformCredentialUiTest {
    private val intent = Intent("androdr.test.CONFIRM")

    @Test fun `RESULT_OK resolves true and later results do not replay`() = runBlocking {
        val activity = Robolectric.buildActivity(ComponentActivity::class.java).setup().get()
        val ui = PlatformCredentialUi(activity)
        val first = async(Dispatchers.Unconfined, CoroutineStart.UNDISPATCHED) { ui.launchConfirmIntent(intent) }
        val request = shadowOf(activity).nextStartedActivityForResult
        shadowOf(activity).receiveResult(request.intent, Activity.RESULT_OK, Intent())
        assertTrue(first.await())

        // A second confirmation must wait for its own result, not inherit the first one.
        val second = async(Dispatchers.Unconfined, CoroutineStart.UNDISPATCHED) { ui.launchConfirmIntent(intent) }
        assertFalse("second confirmation must not complete from the first result", second.isCompleted)
        val request2 = shadowOf(activity).nextStartedActivityForResult
        shadowOf(activity).receiveResult(request2.intent, Activity.RESULT_CANCELED, null)
        assertEquals(false, second.await())
    }

    @Test fun `RESULT_CANCELED resolves false`() = runBlocking {
        val activity = Robolectric.buildActivity(ComponentActivity::class.java).setup().get()
        val job = async(Dispatchers.Unconfined, CoroutineStart.UNDISPATCHED) {
            PlatformCredentialUi(activity).launchConfirmIntent(intent)
        }
        val request = shadowOf(activity).nextStartedActivityForResult
        shadowOf(activity).receiveResult(request.intent, Activity.RESULT_CANCELED, null)
        assertEquals(false, job.await())
    }

    @Test fun `activity destroyed before the result resolves false never true`() = runBlocking {
        val controller = Robolectric.buildActivity(ComponentActivity::class.java).setup()
        val activity = controller.get()
        val job = async(Dispatchers.Unconfined, CoroutineStart.UNDISPATCHED) {
            PlatformCredentialUi(activity).launchConfirmIntent(intent)
        }
        assertFalse(job.isCompleted)
        controller.pause().stop().destroy() // what a configuration change does to the old activity
        assertEquals(false, job.await())
    }

    @Test fun `already destroyed activity resolves false immediately`() = runBlocking {
        val controller = Robolectric.buildActivity(ComponentActivity::class.java).setup()
        val activity = controller.get()
        controller.pause().stop().destroy()
        assertEquals(false, PlatformCredentialUi(activity).launchConfirmIntent(intent))
    }
}
