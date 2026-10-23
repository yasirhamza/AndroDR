package com.androdr.ui.security

import androidx.compose.foundation.layout.RowScope
import androidx.compose.material3.Button
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalView

/**
 * A [Button] for protected actions (closing an alert, audited deletion). While it is composed the
 * host view drops touches delivered while another window covers it (`filterTouchesWhenObscured`),
 * which blunts tapjacking overlays. The previous value is restored when it leaves composition.
 *
 * Limits: accessibility clicks (`performClick` from an accessibility service) bypass touch
 * filtering. The device credential ([ConfirmCredential]) is the real control; this is a
 * defence-in-depth layer only.
 */
@Composable
fun ProtectedButton(
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    enabled: Boolean = true,
    content: @Composable RowScope.() -> Unit,
) {
    val view = LocalView.current
    DisposableEffect(view) {
        val previous = view.filterTouchesWhenObscured
        view.filterTouchesWhenObscured = true
        onDispose { view.filterTouchesWhenObscured = previous }
    }
    Button(onClick = onClick, modifier = modifier, enabled = enabled, content = content)
}
