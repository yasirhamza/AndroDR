package com.androdr.di

import com.androdr.data.db.AppDatabase
import com.androdr.data.db.PrivacyDao
import com.androdr.privacy.ApkPackageInspector
import com.androdr.privacy.AppInspector
import dagger.Binds
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent

@Module
@InstallIn(SingletonComponent::class)
abstract class PrivacyModule {
    @Binds
    abstract fun appInspector(impl: ApkPackageInspector): AppInspector

    companion object {
        @Provides
        fun privacyDao(db: AppDatabase): PrivacyDao = db.privacyDao()
    }
}
