package com.androdr.data.db

import androidx.room.Database
import androidx.room.RoomDatabase
import androidx.room.TypeConverters
import com.androdr.data.model.DnsEvent
import com.androdr.data.model.DomainIocEntry
import com.androdr.data.model.IocEntry
import com.androdr.data.model.ScanResult

@Database(
    entities = [ScanResult::class, DnsEvent::class, IocEntry::class, DomainIocEntry::class],
    version = 3,
    exportSchema = false
)
@TypeConverters(Converters::class)
abstract class AppDatabase : RoomDatabase() {

    abstract fun scanResultDao(): ScanResultDao

    abstract fun dnsEventDao(): DnsEventDao

    abstract fun iocEntryDao(): IocEntryDao

    abstract fun domainIocEntryDao(): DomainIocEntryDao
}
