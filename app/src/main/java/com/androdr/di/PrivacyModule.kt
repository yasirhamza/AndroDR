package com.androdr.di

import com.androdr.privacy.ApkPackageInspector
import com.androdr.privacy.AppInspector
import dagger.Binds
import dagger.Module
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent

@Module
@InstallIn(SingletonComponent::class)
abstract class PrivacyModule {
    @Binds
    abstract fun appInspector(impl: ApkPackageInspector): AppInspector
}
