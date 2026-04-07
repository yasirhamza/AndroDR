package com.androdr.data.model

data class TimelineEvent(
    val timestamp: Long,
    val source: String,
    val category: String,
    val description: String,
    val severity: String,
    /**
     * Optional package identifier the event is about. Used by the
     * bug-report post-processing dedup pass in ScanOrchestrator to
     * drop raw module-emitted TimelineEvents when a SIGMA finding has
     * already been produced for the same `(packageName, timestamp)`
     * tuple — preventing the Timeline from showing a raw "com.X used
     * CAMERA" row next to a "Camera Access" finding row with the
     * identical time, which reads as a duplicate to the user.
     *
     * Modules that don't know a package leave this null and are never
     * deduped against findings.
     */
    val packageName: String? = null
)
