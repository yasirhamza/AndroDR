package com.androdr.ui

import android.app.Application
import android.content.ComponentName
import androidx.activity.ComponentActivity
import androidx.test.core.app.ApplicationProvider
import org.junit.rules.TestRule
import org.junit.runners.model.Statement
import org.robolectric.Shadows.shadowOf

/**
 * Registers the Compose host activity before a Robolectric Compose test runs. ui-test-manifest
 * (which declares ComponentActivity) is debug-only, so without this the same test fails in the
 * release unit-test variant. Use as the outer rule around the compose rule:
 * `RuleChain.outerRule(registerHostActivity()).around(composeRule)`.
 */
fun registerHostActivity(): TestRule = TestRule { base, _ ->
    object : Statement() {
        override fun evaluate() {
            val app = ApplicationProvider.getApplicationContext<Application>()
            shadowOf(app.packageManager)
                .addActivityIfNotPresent(ComponentName(app.packageName, ComponentActivity::class.java.name))
            base.evaluate()
        }
    }
}
