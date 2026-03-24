package com.androdr.data.db

import androidx.room.Database
import androidx.room.RoomDatabase
import androidx.room.TypeConverters
import com.androdr.data.model.DnsEvent
import com.androdr.data.model.IocEntry
import com.androdr.data.model.ScanResult

@Database(
    entities = [ScanResult::class, DnsEvent::class, IocEntry::class],
    version = 2,
    exportSchema = false
)
@TypeConverters(Converters::class)
abstract class AppDatabase : RoomDatabase() {

    abstract fun scanResultDao(): ScanResultDao

    abstract fun dnsEventDao(): DnsEventDao

    abstract fun iocEntryDao(): IocEntryDao
}
