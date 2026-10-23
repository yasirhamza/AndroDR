package com.androdr.ui.security

import android.app.Application
import android.content.ComponentName
import android.view.View
import androidx.activity.ComponentActivity
import androidx.compose.material3.Text
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.platform.LocalView
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.test.core.app.ApplicationProvider
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.rules.RuleChain
import org.junit.rules.TestRule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows.shadowOf

@RunWith(RobolectricTestRunner::class)
class ProtectedButtonTest {
    private val composeRule = createComposeRule()
    private val rule get() = composeRule

    // ui-test-manifest (which declares ComponentActivity) is debug-only; register the host activity
    // so the same test also runs in the release unit-test variant.
    private val registerHostActivity = TestRule { base, _ ->
        object : org.junit.runners.model.Statement() {
            override fun evaluate() {
                val app = ApplicationProvider.getApplicationContext<Application>()
                shadowOf(app.packageManager)
                    .addActivityIfNotPresent(ComponentName(app.packageName, ComponentActivity::class.java.name))
                base.evaluate()
            }
        }
    }

    @get:Rule val chain: RuleChain = RuleChain.outerRule(registerHostActivity).around(composeRule)

    @Test fun `host view filters obscured touches while ProtectedButton is composed`() {
        var host: View? = null
        rule.setContent {
            host = LocalView.current
            ProtectedButton(onClick = {}) { Text("Close") }
        }
        rule.waitForIdle()
        assertTrue(host!!.filterTouchesWhenObscured)
    }

    @Test fun `host view is not filtered without ProtectedButton`() {
        var host: View? = null
        rule.setContent {
            host = LocalView.current
            Text("plain")
        }
        rule.waitForIdle()
        assertFalse(host!!.filterTouchesWhenObscured)
    }

    @Test fun `previous filter value is restored on leaving composition`() {
        var host: View? = null
        var show by mutableStateOf(true)
        rule.setContent {
            host = LocalView.current
            if (show) ProtectedButton(onClick = {}) { Text("Close") }
        }
        rule.waitForIdle()
        assertTrue(host!!.filterTouchesWhenObscured)
        show = false
        rule.waitForIdle()
        assertFalse(host!!.filterTouchesWhenObscured)
    }
}
