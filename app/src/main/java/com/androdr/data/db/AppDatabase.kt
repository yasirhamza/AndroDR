package com.androdr.data.db

import androidx.room.Database
import androidx.room.RoomDatabase
import androidx.room.TypeConverters
import com.androdr.data.model.DnsEvent
import com.androdr.data.model.DomainIocEntry
import com.androdr.data.model.IocEntry
import com.androdr.data.model.CertHashIocEntry
import com.androdr.data.model.ScanResult

@Database(
    entities = [
        ScanResult::class, DnsEvent::class, IocEntry::class,
        DomainIocEntry::class, KnownAppDbEntry::class, CertHashIocEntry::class
    ],
    version = 5,
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
}
