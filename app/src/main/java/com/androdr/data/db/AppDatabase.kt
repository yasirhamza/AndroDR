package com.androdr.data.db

import androidx.room.Database
import androidx.room.RoomDatabase
import androidx.room.TypeConverters
import com.androdr.data.model.DnsEvent
import com.androdr.data.model.CveEntity
import com.androdr.data.model.ForensicTimelineEvent
import com.androdr.data.model.Indicator
import com.androdr.data.model.ScanResult

@Database(
    entities = [
        ScanResult::class, DnsEvent::class, KnownAppDbEntry::class,
        CveEntity::class, ForensicTimelineEvent::class, Indicator::class
    ],
    version = 11,
    exportSchema = false
)
@TypeConverters(Converters::class)
abstract class AppDatabase : RoomDatabase() {

    abstract fun scanResultDao(): ScanResultDao

    abstract fun dnsEventDao(): DnsEventDao

    abstract fun knownAppEntryDao(): KnownAppEntryDao

    abstract fun cveDao(): CveDao

    abstract fun forensicTimelineEventDao(): ForensicTimelineEventDao

    abstract fun indicatorDao(): IndicatorDao
}
