package com.androdr.privacy

import com.androdr.data.db.AppDatabase
import com.androdr.data.repo.TimelineRowDeleter
import io.mockk.mockk

/**
 * A [PrivacyTimelineWriter] over [db] for runner tests that have no telemetry store. Privacy entries pin no
 * stored record, so their deletes release nothing and a relaxed store stands in.
 */
internal fun timelineWriter(db: AppDatabase) = PrivacyTimelineWriter(
    db.forensicTimelineEventDao(),
    TimelineRowDeleter(db.forensicTimelineEventDao(), mockk(relaxed = true), db.signalMemberDao()),
)
