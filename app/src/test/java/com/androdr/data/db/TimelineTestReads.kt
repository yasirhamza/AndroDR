package com.androdr.data.db

import com.androdr.data.model.ForensicTimelineEvent

/**
 * Every visible `forensic_timeline` row, oldest id first — a test convenience over the keyset read
 * [ForensicTimelineEventDao.visibleAfter] (production code streams; the capped `getAllForExport`
 * read is gone, spec §5.5).
 */
internal suspend fun ForensicTimelineEventDao.getAllForExport(): List<ForensicTimelineEvent> {
    val out = ArrayList<ForensicTimelineEvent>()
    var after = 0L
    while (true) {
        val page = visibleAfter(after, BATCH)
        out += page
        if (page.size < BATCH) return out
        after = page.last().id
    }
}

private const val BATCH = 500
