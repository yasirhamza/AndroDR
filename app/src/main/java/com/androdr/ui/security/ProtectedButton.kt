package com.androdr.ui.security

import android.os.Build
import android.view.MotionEvent
import androidx.compose.foundation.layout.RowScope
import androidx.compose.material3.Button
import androidx.compose.runtime.Composable
import androidx.compose.ui.ExperimentalComposeUiApi
import androidx.compose.ui.Modifier
import androidx.compose.ui.input.pointer.pointerInteropFilter

/** `MotionEvent.FLAG_WINDOW_IS_PARTIALLY_OBSCURED` (0x2), API 29+; local copy because `sdkInt` is injected. */
private const val FLAG_PARTIALLY_OBSCURED = 0x2

/**
 * True when the platform marked [flags] as delivered while another window covers ours:
 * `FLAG_WINDOW_IS_OBSCURED` (any API) or `FLAG_WINDOW_IS_PARTIALLY_OBSCURED` (API 29+ only).
 */
internal fun isObscuredTouch(flags: Int, sdkInt: Int): Boolean {
    if (flags and MotionEvent.FLAG_WINDOW_IS_OBSCURED != 0) return true
    return sdkInt >= Build.VERSION_CODES.Q && flags and FLAG_PARTIALLY_OBSCURED != 0
}

/**
 * A [Button] for protected actions (closing an alert, audited deletion). Every touch the platform
 * flags as obscured by another window is consumed before the button sees it, so a tapjacking
 * overlay cannot trigger [onClick].
 *
 * Filtering is per event and per button: there is no shared mutable state, so any number of
 * instances can enter and leave composition in any order (a host-view flag saved and restored per
 * instance would be corrupted by that). It also works inside a Dialog or Popup, whose window has
 * its own view. Unlike a global `filterTouchesWhenObscured`, the rest of the screen stays live.
 *
 * Limits: accessibility clicks (`performClick` from an accessibility service) are not touch
 * events and bypass this. The device credential ([ConfirmCredential]) is the real control; this is
 * a defence-in-depth layer only.
 */
@OptIn(ExperimentalComposeUiApi::class)
@Composable
fun ProtectedButton(
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    enabled: Boolean = true,
    content: @Composable RowScope.() -> Unit,
) {
    Button(
        onClick = onClick,
        modifier = modifier.pointerInteropFilter { event -> isObscuredTouch(event.flags, Build.VERSION.SDK_INT) },
        enabled = enabled,
        content = content,
    )
}
