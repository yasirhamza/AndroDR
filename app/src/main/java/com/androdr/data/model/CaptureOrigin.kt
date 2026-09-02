package com.androdr.data.model

/** How a cellular observation reached the emitter. */
enum class CaptureOrigin {
    /** One-shot read of the current cell list when the monitor armed. */
    PRIME,

    /** Delivered by the platform's TelephonyCallback on change. */
    CALLBACK,
}
