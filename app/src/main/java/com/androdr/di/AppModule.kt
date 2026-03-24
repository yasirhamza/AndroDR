package com.androdr.di

import android.content.Context
import androidx.room.Room
import com.androdr.data.db.AppDatabase
import com.androdr.data.db.DnsEventDao
import com.androdr.data.db.IocEntryDao
import com.androdr.data.db.MIGRATION_1_2
import com.androdr.data.db.ScanResultDao
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.android.qualifiers.ApplicationContext
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton

@Module
@InstallIn(SingletonComponent::class)
object AppModule {

    @Provides
    @Singleton
    fun provideDatabase(@ApplicationContext ctx: Context): AppDatabase =
        Room.databaseBuilder(ctx, AppDatabase::class.java, "androdr.db")
            .addMigrations(MIGRATION_1_2)
            .build()

    @Provides
    fun provideScanResultDao(db: AppDatabase): ScanResultDao = db.scanResultDao()

    @Provides
    fun provideDnsEventDao(db: AppDatabase): DnsEventDao = db.dnsEventDao()

    @Provides
    fun provideIocEntryDao(db: AppDatabase): IocEntryDao = db.iocEntryDao()
}
