package com.androdr.ui.security

import android.app.Application
import android.content.ComponentName
import android.os.SystemClock
import android.view.MotionEvent
import android.view.View
import androidx.activity.ComponentActivity
import androidx.compose.foundation.layout.Column
import androidx.compose.material3.Text
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalView
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.test.core.app.ApplicationProvider
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.RuleChain
import org.junit.rules.TestRule
import org.junit.runner.RunWith
import org.junit.runners.model.Statement
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows.shadowOf

@RunWith(RobolectricTestRunner::class)
class ProtectedButtonTest {
    private val composeRule = createComposeRule()
    private val rule get() = composeRule

    // ui-test-manifest (which declares ComponentActivity) is debug-only; register the host activity
    // so the same test also runs in the release unit-test variant.
    private val registerHostActivity = TestRule { base, _ ->
        object : Statement() {
            override fun evaluate() {
                val app = ApplicationProvider.getApplicationContext<Application>()
                shadowOf(app.packageManager)
                    .addActivityIfNotPresent(ComponentName(app.packageName, ComponentActivity::class.java.name))
                base.evaluate()
            }
        }
    }

    @get:Rule val chain: RuleChain = RuleChain.outerRule(registerHostActivity).around(composeRule)

    // --- pure predicate ---

    @Test fun `obscured flag is detected on every api`() {
        for (sdk in listOf(26, 28, 29, 35)) {
            assertTrue("sdk $sdk", isObscuredTouch(MotionEvent.FLAG_WINDOW_IS_OBSCURED, sdk))
        }
    }

    @Test fun `partially obscured flag counts only from api 29`() {
        val f = MotionEvent.FLAG_WINDOW_IS_PARTIALLY_OBSCURED
        assertFalse(isObscuredTouch(f, 28))
        assertTrue(isObscuredTouch(f, 29))
        assertTrue(isObscuredTouch(f, 35))
    }

    @Test fun `unflagged touch is not obscured`() {
        assertFalse(isObscuredTouch(0, 35))
    }

    // --- real dispatch ---

    private fun dispatchTap(host: View, x: Float, y: Float, flags: Int) {
        val t = SystemClock.uptimeMillis()
        for ((i, action) in listOf(MotionEvent.ACTION_DOWN, MotionEvent.ACTION_UP).withIndex()) {
            val ev = MotionEvent.obtain(t + i * 50L, t + i * 50L, action, x, y, 0)
            // No public/hidden Java setter exists on API 35; the window manager sets the flag through
            // the native event, so do the same (Robolectric native-backed MotionEvent).
            val ptr = MotionEvent::class.java.getDeclaredField("mNativePtr").apply { isAccessible = true }.getLong(ev)
            MotionEvent::class.java
                .getDeclaredMethod("nativeSetFlags", Long::class.javaPrimitiveType, Int::class.javaPrimitiveType)
                .apply { isAccessible = true }
                .invoke(null, ptr, flags)
            check(ev.flags == flags) { "flags not applied" }
            host.dispatchTouchEvent(ev)
            ev.recycle()
        }
        rule.waitForIdle()
    }

    private fun centreOf(tag: String): Pair<Float, Float> {
        val b = rule.onNodeWithTag(tag).fetchSemanticsNode().boundsInRoot
        return b.center.x to b.center.y
    }

    @Test fun `obscured touch does not fire onClick but normal touches do`() {
        var host: View? = null
        var clicks = 0
        rule.setContent {
            host = LocalView.current
            ProtectedButton(onClick = { clicks++ }, modifier = Modifier.testTag("btn")) { Text("Close") }
        }
        rule.waitForIdle()
        val (x, y) = centreOf("btn")

        dispatchTap(host!!, x, y, MotionEvent.FLAG_WINDOW_IS_OBSCURED)
        assertEquals("obscured tap must be dropped", 0, clicks)
        dispatchTap(host!!, x, y, MotionEvent.FLAG_WINDOW_IS_PARTIALLY_OBSCURED)
        assertEquals("partially obscured tap must be dropped (api 35)", 0, clicks)

        dispatchTap(host!!, x, y, 0)
        assertEquals("plain dispatched tap fires", 1, clicks)
        rule.onNodeWithTag("btn").performClick()
        assertEquals("semantic click fires", 2, clicks)
    }

    @Test fun `disposing one of two buttons leaves the other protected`() {
        var host: View? = null
        var showA by mutableStateOf(true)
        var clicksB = 0
        rule.setContent {
            host = LocalView.current
            Column {
                if (showA) ProtectedButton(onClick = {}, modifier = Modifier.testTag("a")) { Text("A") }
                ProtectedButton(onClick = { clicksB++ }, modifier = Modifier.testTag("b")) { Text("B") }
            }
        }
        rule.waitForIdle()
        showA = false
        rule.waitForIdle()
        val (x, y) = centreOf("b")
        dispatchTap(host!!, x, y, MotionEvent.FLAG_WINDOW_IS_OBSCURED)
        assertEquals(0, clicksB)
        dispatchTap(host!!, x, y, 0)
        assertEquals(1, clicksB)
    }

    @Test fun `two buttons disposed in either order leave host view state untouched`() {
        var host: View? = null
        var showA by mutableStateOf(true)
        var showB by mutableStateOf(true)
        rule.setContent {
            host = LocalView.current
            if (showA) ProtectedButton(onClick = {}) { Text("A") }
            if (showB) ProtectedButton(onClick = {}) { Text("B") }
        }
        rule.waitForIdle()
        val original = host!!.filterTouchesWhenObscured
        showA = false
        rule.waitForIdle()
        showB = false
        rule.waitForIdle()
        assertEquals(original, host!!.filterTouchesWhenObscured)
        showB = true
        showA = true
        rule.waitForIdle()
        showB = false
        rule.waitForIdle()
        showA = false
        rule.waitForIdle()
        assertEquals(original, host!!.filterTouchesWhenObscured)
    }
}
