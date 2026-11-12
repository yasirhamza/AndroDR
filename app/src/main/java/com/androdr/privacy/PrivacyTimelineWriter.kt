package com.androdr.privacy

import com.androdr.data.db.ForensicTimelineEventDao
import com.androdr.data.model.ForensicTimelineEvent
import com.androdr.data.repo.TimelineRowDeleter
import javax.inject.Inject
import javax.inject.Singleton

/**
 * The privacy scan's only way into the Timeline (spec 2026-11-10 §5.4–5.5). Each call must run inside the
 * caller's Room transaction (the scan's completion, or "Delete privacy results"), so the entries change
 * together with the results they describe. Removal goes through [TimelineRowDeleter], like every Timeline
 * delete. It takes no security-scan lock: the entries belong to no security scan and pin no stored record.
 */
@Singleton
class PrivacyTimelineWriter @Inject constructor(
    private val dao: ForensicTimelineEventDao,
    private val deleter: TimelineRowDeleter,
) {
    /** Replaces the previous privacy scan's entries with [entries]. */
    suspend fun replace(entries: List<ForensicTimelineEvent>) {
        deleter.privacyRows()
        dao.insertAll(entries)
    }

    /** Removes every privacy entry ("Delete privacy results"). */
    suspend fun clear() = deleter.privacyRows()
}
