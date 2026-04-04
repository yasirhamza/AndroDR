package com.androdr.di

import android.content.Context
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.preferencesDataStore
import androidx.room.Room
import com.androdr.data.db.AppDatabase
import com.androdr.data.db.CveDao
import com.androdr.data.db.DnsEventDao
import com.androdr.data.db.ForensicTimelineEventDao
import com.androdr.data.db.IndicatorDao
import com.androdr.data.db.KnownAppEntryDao
import com.androdr.data.db.MIGRATION_1_2
import com.androdr.data.db.MIGRATION_2_3
import com.androdr.data.db.MIGRATION_3_4
import com.androdr.data.db.MIGRATION_4_5
import com.androdr.data.db.MIGRATION_5_6
import com.androdr.data.db.MIGRATION_6_7
import com.androdr.data.db.MIGRATION_7_8
import com.androdr.data.db.MIGRATION_8_9
import com.androdr.data.db.MIGRATION_9_10
import com.androdr.data.db.MIGRATION_10_11
import com.androdr.data.db.ScanResultDao
import com.androdr.ioc.CertHashIocFeed
import com.androdr.ioc.DomainIocFeed
import com.androdr.ioc.IocFeed
import com.androdr.ioc.KnownAppFeed
import com.androdr.ioc.feeds.HaGeZiTifFeed
import com.androdr.ioc.feeds.MalwareBazaarCertFeed
import com.androdr.ioc.feeds.MvtIndicatorsFeed
import com.androdr.ioc.feeds.PlexusKnownAppFeed
import com.androdr.ioc.feeds.StalkerwareIndicatorsFeed
import com.androdr.ioc.feeds.ThreatFoxDomainFeed
import com.androdr.ioc.feeds.UadKnownAppFeed
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.android.qualifiers.ApplicationContext
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton

private val Context.settingsDataStore: DataStore<Preferences>
    by preferencesDataStore(name = "androdr_settings")

@Module
@InstallIn(SingletonComponent::class)
object AppModule {

    @Provides
    @Singleton
    fun provideDatabase(@ApplicationContext ctx: Context): AppDatabase =
        Room.databaseBuilder(ctx, AppDatabase::class.java, "androdr.db")
            .addMigrations(
                MIGRATION_1_2, MIGRATION_2_3, MIGRATION_3_4, MIGRATION_4_5,
                MIGRATION_5_6, MIGRATION_6_7, MIGRATION_7_8, MIGRATION_8_9,
                MIGRATION_9_10, MIGRATION_10_11
            )
            .fallbackToDestructiveMigrationOnDowngrade()
            .build()

    @Provides
    fun provideScanResultDao(db: AppDatabase): ScanResultDao = db.scanResultDao()

    @Provides
    fun provideDnsEventDao(db: AppDatabase): DnsEventDao = db.dnsEventDao()

    @Provides
    fun provideKnownAppEntryDao(db: AppDatabase): KnownAppEntryDao = db.knownAppEntryDao()

    @Provides
    fun provideCveDao(db: AppDatabase): CveDao = db.cveDao()

    @Provides
    fun provideForensicTimelineEventDao(db: AppDatabase): ForensicTimelineEventDao =
        db.forensicTimelineEventDao()

    @Provides
    fun provideIndicatorDao(db: AppDatabase): IndicatorDao = db.indicatorDao()

    @Provides
    @Singleton
    fun provideDomainIocFeeds(): @JvmSuppressWildcards List<DomainIocFeed> = listOf(
        MvtIndicatorsFeed(),
        ThreatFoxDomainFeed(),
        HaGeZiTifFeed()
    )

    @Provides
    @Singleton
    fun provideKnownAppFeeds(): @JvmSuppressWildcards List<KnownAppFeed> =
        listOf(UadKnownAppFeed(), PlexusKnownAppFeed())

    @Provides
    @Singleton
    fun provideCertHashIocFeeds(): @JvmSuppressWildcards List<CertHashIocFeed> =
        listOf(MalwareBazaarCertFeed())

    @Provides
    @Singleton
    fun providePackageIocFeeds(): @JvmSuppressWildcards List<IocFeed> =
        listOf(StalkerwareIndicatorsFeed())

    @Provides
    @Singleton
    fun provideSettingsDataStore(@ApplicationContext ctx: Context): DataStore<Preferences> =
        ctx.settingsDataStore
}
