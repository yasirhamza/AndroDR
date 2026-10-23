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

    /** Sets MotionEvent flags via the native event (no Java setter on API 35), as the window manager does. */
    private fun MotionEvent.withFlags(flags: Int): MotionEvent {
        val ptr = MotionEvent::class.java.getDeclaredField("mNativePtr").apply { isAccessible = true }.getLong(this)
        MotionEvent::class.java
            .getDeclaredMethod("nativeSetFlags", Long::class.javaPrimitiveType, Int::class.javaPrimitiveType)
            .apply { isAccessible = true }
            .invoke(null, ptr, flags)
        check(this.flags == flags) { "flags not applied" }
        return this
    }

    private fun dispatchTap(host: View, x: Float, y: Float, flags: Int) =
        dispatchGesture(host, x, y, listOf(MotionEvent.ACTION_DOWN to flags, MotionEvent.ACTION_UP to flags))

    /** Dispatches one gesture; each step is (action, flags) so a gesture can mix clean and obscured events. */
    private fun dispatchGesture(host: View, x: Float, y: Float, steps: List<Pair<Int, Int>>) {
        val t = SystemClock.uptimeMillis()
        for ((i, step) in steps.withIndex()) {
            val (action, flags) = step
            // MOVE shifts a little: Compose drops moves that change nothing.
            val px = if (action == MotionEvent.ACTION_MOVE) x + 2f else x
            val ev = MotionEvent.obtain(t, t + i * 50L, action, px, y, 0)
            ev.withFlags(flags)
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

    private fun clicksAfter(vararg steps: Pair<Int, Int>): Int {
        var host: View? = null
        var clicks = 0
        rule.setContent {
            host = LocalView.current
            ProtectedButton(onClick = { clicks++ }, modifier = Modifier.testTag("btn")) { Text("Close") }
        }
        rule.waitForIdle()
        val (x, y) = centreOf("btn")
        dispatchGesture(host!!, x, y, steps.toList())
        return clicks
    }

    private val down = MotionEvent.ACTION_DOWN
    private val move = MotionEvent.ACTION_MOVE
    private val up = MotionEvent.ACTION_UP
    private val obscured = MotionEvent.FLAG_WINDOW_IS_OBSCURED

    @Test fun `clean down then obscured up does not click`() {
        assertEquals(0, clicksAfter(down to 0, up to obscured))
    }

    @Test fun `obscured down then clean up does not click`() {
        assertEquals(0, clicksAfter(down to obscured, up to 0))
    }

    @Test fun `clean down obscured move clean up does not click`() {
        assertEquals(0, clicksAfter(down to 0, move to obscured, up to 0))
    }

    @Test fun `clean down clean up clicks once`() {
        assertEquals(1, clicksAfter(down to 0, up to 0))
    }

    @Test fun `taint resets at the next down`() {
        assertEquals(1, clicksAfter(down to obscured, up to obscured, down to 0, up to 0))
    }

    @Test fun `wrapper layout sets the platform obscured-touch filter and cancels the child on taint`() {
        val ctx = ApplicationProvider.getApplicationContext<Application>()
        val layout = ObscuredTouchFilterLayout(ctx)
        assertTrue(layout.filterTouchesWhenObscured)
        val child = RecordingView(ctx)
        layout.addView(child)
        val exactly = View.MeasureSpec.makeMeasureSpec(100, View.MeasureSpec.EXACTLY)
        layout.measure(exactly, exactly)
        layout.layout(0, 0, 100, 100)
        fun ev(action: Int) = MotionEvent.obtain(0, 0, action, 1f, 1f, 0)
        layout.dispatchTouchEvent(ev(MotionEvent.ACTION_DOWN))
        val obscuredMove = ev(MotionEvent.ACTION_MOVE).withFlags(MotionEvent.FLAG_WINDOW_IS_PARTIALLY_OBSCURED)
        layout.dispatchTouchEvent(obscuredMove)
        layout.dispatchTouchEvent(ev(MotionEvent.ACTION_UP))
        assertEquals(listOf(MotionEvent.ACTION_DOWN, MotionEvent.ACTION_CANCEL), child.actions)
    }

    private class RecordingView(context: Application) : View(context) {
        val actions = mutableListOf<Int>()
        override fun onTouchEvent(event: MotionEvent): Boolean {
            actions += event.actionMasked
            return true
        }
    }
}
