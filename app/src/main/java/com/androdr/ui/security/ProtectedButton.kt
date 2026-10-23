package com.androdr.ui.security

import android.content.Context
import android.os.Build
import android.view.MotionEvent
import android.widget.FrameLayout
import androidx.compose.foundation.layout.RowScope
import androidx.compose.material3.Button
import androidx.compose.runtime.Composable
import androidx.compose.runtime.rememberCompositionContext
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.ComposeView
import androidx.compose.ui.viewinterop.AndroidView

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
 * A view group that drops every obscured touch before its child sees it. Sets the platform
 * `filterTouchesWhenObscured` (which covers `FLAG_WINDOW_IS_OBSCURED`) and also rejects
 * `FLAG_WINDOW_IS_PARTIALLY_OBSCURED` on API 29+, which the platform filter does not check.
 *
 * Dropping single events is not enough: a clean DOWN, a dropped (obscured) MOVE or UP and a later
 * clean UP would still complete a click. So the first obscured event of a gesture cancels the
 * child's gesture (ACTION_CANCEL, sent straight to the child) and every later event is dropped
 * until the next ACTION_DOWN.
 */
internal class ObscuredTouchFilterLayout(context: Context) : FrameLayout(context) {
    private var tainted = false

    init {
        filterTouchesWhenObscured = true
    }

    override fun dispatchTouchEvent(ev: MotionEvent): Boolean {
        if (ev.actionMasked == MotionEvent.ACTION_DOWN) tainted = false
        if (!tainted && isObscuredTouch(ev.flags, Build.VERSION.SDK_INT)) {
            tainted = true
            if (ev.actionMasked != MotionEvent.ACTION_DOWN) cancelChildGesture(ev)
        }
        return !tainted && super.dispatchTouchEvent(ev)
    }

    private fun cancelChildGesture(ev: MotionEvent) {
        val cancel = MotionEvent.obtain(ev)
        cancel.action = MotionEvent.ACTION_CANCEL
        getChildAt(0)?.dispatchTouchEvent(cancel)
        cancel.recycle()
    }
}

/**
 * A button for protected actions (closing an alert, audited deletion). The Compose [Button] is
 * hosted in its own child view with obscured-touch filtering ([ObscuredTouchFilterLayout]), the
 * platform's standard anti-tapjacking mechanism. The view system drops each flagged event at that
 * view, so a gesture in which any DOWN, MOVE or UP is obscured never completes a click, even when
 * an overlay appears between a clean DOWN and the UP.
 *
 * The filter is per control and there is no shared host-view state, so any number of instances can
 * enter and leave composition in any order. It also works in a Dialog or Popup, whose window has
 * its own view. The rest of the screen stays live. No reflection: nothing here depends on library
 * internals, so R8 minification cannot break it.
 *
 * Layout: [modifier] sizes the wrapper view; the button inside is wrap-content. The content shares
 * the caller's composition locals (theme) through the parent composition context.
 *
 * Limits: accessibility clicks (`performClick` from an accessibility service) are not touch
 * events and bypass this. The device credential ([ConfirmCredential]) is the real control; this is
 * a defence-in-depth layer only.
 */
@Composable
fun ProtectedButton(
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    enabled: Boolean = true,
    content: @Composable RowScope.() -> Unit,
) {
    val currentOnClick = rememberUpdatedState(onClick)
    val currentEnabled = rememberUpdatedState(enabled)
    val currentContent = rememberUpdatedState(content)
    val parent = rememberCompositionContext()
    AndroidView(
        modifier = modifier,
        factory = { context ->
            ObscuredTouchFilterLayout(context).apply {
                addView(
                    ComposeView(context).apply {
                        setParentCompositionContext(parent)
                        setContent {
                            Button(
                                onClick = { currentOnClick.value() },
                                enabled = currentEnabled.value,
                                content = currentContent.value,
                            )
                        }
                    },
                )
            }
        },
    )
}
