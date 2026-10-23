package com.androdr.ui.security

import android.os.Build
import android.view.MotionEvent
import androidx.compose.foundation.layout.RowScope
import androidx.compose.material3.Button
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.input.pointer.PointerEvent
import androidx.compose.ui.input.pointer.PointerEventPass
import androidx.compose.ui.input.pointer.PointerInputScope
import androidx.compose.ui.input.pointer.pointerInput

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
 * A [Button] for protected actions (closing an alert, audited deletion). If any touch of a
 * gesture (DOWN, MOVE or UP) is flagged as obscured by another window, the whole gesture is
 * cancelled before the button sees it, so a tapjacking overlay cannot trigger [onClick], even one
 * that appears between a clean DOWN and the UP.
 *
 * Filtering is per gesture and per button: there is no shared mutable state, so any number of
 * instances can enter and leave composition in any order (a host-view flag saved and restored per
 * instance would be corrupted by that). It also works inside a Dialog or Popup, whose window has
 * its own view. Unlike a global `filterTouchesWhenObscured`, the rest of the screen stays live.
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
    Button(
        onClick = onClick,
        modifier = modifier.pointerInput(Unit) { dropObscuredGestures() },
        enabled = enabled,
        content = content,
    )
}

/**
 * Runs on the Initial pass, before the button's own click handling. A gesture is tainted as soon
 * as any of its events is obscured; from then until the next fresh DOWN every change is consumed,
 * so the button sees a cancelled press and `onClick` never fires.
 */
private suspend fun PointerInputScope.dropObscuredGestures() {
    awaitPointerEventScope {
        var tainted = false
        while (true) {
            val event = awaitPointerEvent(PointerEventPass.Initial)
            if (event.changes.none { it.previousPressed } && event.changes.any { it.pressed }) tainted = false
            val flags = rawFlags(event)
            if (flags == null || isObscuredTouch(flags, Build.VERSION.SDK_INT)) tainted = true
            if (tainted) event.changes.forEach { it.consume() }
        }
    }
}

/**
 * The raw `MotionEvent.getFlags()` of [event]. Compose 1.7 exposes the event only through an
 * internal accessor (public in bytecode), so it is read reflectively. Returns null when it cannot
 * be read, and the caller then treats the gesture as obscured (fail closed). `ProtectedButtonTest`
 * dispatches real flagged events, so a Compose upgrade that moves the accessor fails the build.
 */
private fun rawFlags(event: PointerEvent): Int? = runCatching {
    (MOTION_EVENT_GETTER.invoke(event) as? MotionEvent)?.flags
}.getOrNull()

private val MOTION_EVENT_GETTER by lazy {
    PointerEvent::class.java.getMethod("getMotionEvent\$ui_release")
}
