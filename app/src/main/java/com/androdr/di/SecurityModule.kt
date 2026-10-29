package com.androdr.di

import android.app.KeyguardManager
import android.content.Context
import com.androdr.ui.security.DeviceSecurity
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.android.qualifiers.ApplicationContext
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton

@Module
@InstallIn(SingletonComponent::class)
object SecurityModule {

    /** The lock-screen check closing an alert re-runs before honouring "no secure lock" (spec §5.4). */
    @Provides
    @Singleton
    fun provideDeviceSecurity(@ApplicationContext ctx: Context): DeviceSecurity =
        DeviceSecurity.of(ctx.getSystemService(KeyguardManager::class.java))
}
