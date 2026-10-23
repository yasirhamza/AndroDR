package com.androdr.data.db

import androidx.room.Database
import androidx.room.RoomDatabase
import androidx.room.TypeConverters
import com.androdr.data.model.CveEntity
import com.androdr.data.model.DnsEvent
import com.androdr.data.model.EventWatermark
import com.androdr.data.model.FeedHealth
import com.androdr.data.model.ForensicTimelineEvent
import com.androdr.data.model.Indicator
import com.androdr.data.model.RecordBody
import com.androdr.data.model.ScanObservation
import com.androdr.data.model.ScanResult
import com.androdr.data.model.SignalMember
import com.androdr.data.model.TelemetryFact

@Database(
    entities = [
        ScanResult::class, DnsEvent::class, KnownAppDbEntry::class,
        CveEntity::class, ForensicTimelineEvent::class, Indicator::class,
        FeedHealth::class, RecordBody::class, TelemetryFact::class, ScanObservation::class,
        EventWatermark::class, SignalMember::class
    ],
    version = 20,
    exportSchema = true
)
@TypeConverters(Converters::class)
@Suppress("TooManyFunctions") // one accessor per DAO, as Room requires
abstract class AppDatabase : RoomDatabase() {

    abstract fun scanResultDao(): ScanResultDao

    abstract fun scanWriteDao(): ScanWriteDao

    abstract fun dnsEventDao(): DnsEventDao

    abstract fun knownAppEntryDao(): KnownAppEntryDao

    abstract fun cveDao(): CveDao

    abstract fun forensicTimelineEventDao(): ForensicTimelineEventDao

    abstract fun indicatorDao(): IndicatorDao

    abstract fun feedHealthDao(): FeedHealthDao

    abstract fun recordBodyDao(): RecordBodyDao

    abstract fun telemetryFactDao(): TelemetryFactDao

    abstract fun scanObservationDao(): ScanObservationDao

    abstract fun eventWatermarkDao(): EventWatermarkDao

    abstract fun signalMemberDao(): SignalMemberDao

    abstract fun telemetryReadDao(): TelemetryReadDao

    abstract fun atomDao(): AtomDao

    abstract fun signalMemberBackfillDao(): SignalMemberBackfillDao
}
