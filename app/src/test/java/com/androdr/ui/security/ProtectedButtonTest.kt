package com.androdr.ui.security

import com.androdr.ui.registerHostActivity
import android.app.Application
import android.os.SystemClock
import android.view.MotionEvent
import android.view.View
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.width
import androidx.compose.material3.Text
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalView
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.test.assertCountEquals
import androidx.compose.ui.test.assertHasClickAction
import androidx.compose.ui.test.assertIsEnabled
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.hasClickAction
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.onNodeWithContentDescription
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.unit.dp
import androidx.test.core.app.ApplicationProvider
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.RuleChain
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

@RunWith(RobolectricTestRunner::class)
class ProtectedButtonTest {
    private val composeRule = createComposeRule()
    private val rule get() = composeRule

    @get:Rule val chain: RuleChain = RuleChain.outerRule(registerHostActivity()).around(composeRule)

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

    // --- semantics and layout ---

    @Test fun `exposed to accessibility as one clickable enabled control carrying its label`() {
        rule.setContent { ProtectedButton(onClick = {}) { Text("Close") } }
        rule.onNodeWithText("Close").assertHasClickAction().assertIsEnabled()
        rule.onAllNodesWithText("Close").assertCountEquals(1)
        rule.onAllNodes(hasClickAction()).assertCountEquals(1)
    }

    @Test fun `content description in the content is exposed on the clickable control`() {
        rule.setContent {
            ProtectedButton(onClick = {}) { Text("X", Modifier.semantics { contentDescription = "Close alert" }) }
        }
        rule.onNodeWithContentDescription("Close alert").assertHasClickAction()
    }

    @Test fun `disabled button does not click and enabling it later does`() {
        var host: View? = null
        var enabled by mutableStateOf(false)
        var clicks = 0
        rule.setContent {
            host = LocalView.current
            ProtectedButton(onClick = { clicks++ }, enabled = enabled, modifier = Modifier.testTag("btn")) {
                Text("Close")
            }
        }
        rule.onNodeWithText("Close").assertIsNotEnabled()
        val (x, y) = centreOf("btn")
        dispatchTap(host!!, x, y, 0)
        assertEquals("disabled button must not click", 0, clicks)

        enabled = true
        rule.waitForIdle()
        rule.onNodeWithText("Close").assertIsEnabled()
        dispatchTap(host!!, x, y, 0)
        assertEquals(1, clicks)
    }

    @Test fun `the newest onClick passed on recomposition is the one invoked`() {
        var host: View? = null
        var second by mutableStateOf(false)
        var firstClicks = 0
        var secondClicks = 0
        rule.setContent {
            host = LocalView.current
            val onClick: () -> Unit = if (second) ({ secondClicks++ }) else ({ firstClicks++ })
            ProtectedButton(onClick = onClick, modifier = Modifier.testTag("btn")) { Text("Close") }
        }
        rule.waitForIdle()
        second = true
        rule.waitForIdle()
        val (x, y) = centreOf("btn")
        dispatchTap(host!!, x, y, 0)
        assertEquals(0, firstClicks)
        assertEquals(1, secondClicks)
    }

    @Test fun `caller test tag lands on a findable node with the button's bounds`() {
        rule.setContent {
            ProtectedButton(onClick = {}, modifier = Modifier.testTag("btn")) { Text("Close") }
        }
        val wrapper = rule.onNodeWithTag("btn").fetchSemanticsNode().boundsInWindow
        val button = rule.onNodeWithText("Close", useUnmergedTree = false).fetchSemanticsNode().boundsInWindow
        assertEquals(wrapper, button)
    }

    @Test fun `fill-width button has no dead zone at the wrapper edge`() {
        var host: View? = null
        var clicks = 0
        rule.setContent {
            host = LocalView.current
            Column(Modifier.width(300.dp)) {
                ProtectedButton(onClick = { clicks++ }, modifier = Modifier.fillMaxWidth().testTag("btn")) {
                    Text("Close")
                }
            }
        }
        rule.waitForIdle()
        val b = rule.onNodeWithTag("btn").fetchSemanticsNode().boundsInRoot
        dispatchTap(host!!, b.right - 3f, b.center.y, 0)
        assertEquals("tap near the right edge of a fill-width button must click", 1, clicks)
        dispatchTap(host!!, b.left + 3f, b.center.y, 0)
        assertEquals(2, clicks)
    }

    @Test fun `button without a size modifier stays wrap-content`() {
        rule.setContent {
            Column(Modifier.width(300.dp).testTag("col")) {
                ProtectedButton(onClick = {}, modifier = Modifier.testTag("btn")) { Text("Close") }
            }
        }
        val w = rule.onNodeWithTag("btn").fetchSemanticsNode().boundsInRoot.width
        val col = rule.onNodeWithTag("col").fetchSemanticsNode().boundsInRoot.width
        assertTrue("width $w should be well under column width $col", w < col / 2f)
    }

    @Test fun `clean system cancel then a fresh tap clicks once`() {
        assertEquals(1, clicksAfter(down to 0, MotionEvent.ACTION_CANCEL to 0, down to 0, up to 0))
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
