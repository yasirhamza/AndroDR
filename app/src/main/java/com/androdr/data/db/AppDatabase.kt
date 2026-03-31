package com.androdr.data.db

import androidx.room.Database
import androidx.room.RoomDatabase
import androidx.room.TypeConverters
import com.androdr.data.model.DnsEvent
import com.androdr.data.model.DomainIocEntry
import com.androdr.data.model.IocEntry
import com.androdr.data.model.CertHashIocEntry
import com.androdr.data.model.CveEntity
import com.androdr.data.model.ForensicTimelineEvent
import com.androdr.data.model.ScanResult

@Database(
    entities = [
        ScanResult::class, DnsEvent::class, IocEntry::class,
        DomainIocEntry::class, KnownAppDbEntry::class, CertHashIocEntry::class,
        CveEntity::class, ForensicTimelineEvent::class
    ],
    version = 8,
    exportSchema = false
)
@TypeConverters(Converters::class)
abstract class AppDatabase : RoomDatabase() {

    abstract fun scanResultDao(): ScanResultDao

    abstract fun dnsEventDao(): DnsEventDao

    abstract fun iocEntryDao(): IocEntryDao

    abstract fun domainIocEntryDao(): DomainIocEntryDao

    abstract fun knownAppEntryDao(): KnownAppEntryDao

    abstract fun certHashIocEntryDao(): CertHashIocEntryDao

    abstract fun cveDao(): CveDao

    abstract fun forensicTimelineEventDao(): ForensicTimelineEventDao
}
