package com.androdr.ui.dashboard

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import com.androdr.R
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

/**
 * Final review M2: the close-alert dialog promised "You will be asked for your screen lock" on a
 * device with no secure lock, where the close goes through as `NoSecureLock` with no prompt. The
 * prompt is now promised only on a secure device; the body itself makes no lock promise.
 */
@RunWith(RobolectricTestRunner::class)
class CloseAlertDialogCopyTest {
    private val context: Context = ApplicationProvider.getApplicationContext()

    @Test
    fun `the dialog promises a screen-lock prompt only when the device has a secure lock`() {
        val secure = context.getString(closeLockSentence(secure = true))
        val insecure = context.getString(closeLockSentence(secure = false))
        assertTrue(secure, secure.contains("asked for your screen lock"))
        assertFalse("no prompt is promised without a lock: $insecure", insecure.contains("will be asked"))
        assertTrue(insecure, insecure.contains("No screen lock is set"))
        for (count in listOf(1, 2)) {
            val body = context.resources.getQuantityString(R.plurals.alerts_close_dialog_body, count, count)
            assertFalse("the body never promises the lock itself: $body", body.contains("screen lock"))
        }
    }
}
