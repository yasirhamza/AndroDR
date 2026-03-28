package com.androdr.di

import com.androdr.scanner.bugreport.AccessibilityModule
import com.androdr.scanner.bugreport.BugreportModule
import com.androdr.scanner.bugreport.LegacyScanModule
import dagger.Binds
import dagger.Module
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import dagger.multibindings.IntoSet

@Module
@InstallIn(SingletonComponent::class)
abstract class BugreportModuleBindings {
    @Binds @IntoSet abstract fun legacy(m: LegacyScanModule): BugreportModule
    @Binds @IntoSet abstract fun accessibility(m: AccessibilityModule): BugreportModule
}
