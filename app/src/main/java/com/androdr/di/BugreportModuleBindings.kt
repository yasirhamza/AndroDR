package com.androdr.di

import com.androdr.scanner.bugreport.AccessibilityModule
import com.androdr.scanner.bugreport.ActivityModule
import com.androdr.scanner.bugreport.AdbKeysModule
import com.androdr.scanner.bugreport.AppOpsModule
import com.androdr.scanner.bugreport.BatteryDailyModule
import com.androdr.scanner.bugreport.BugreportModule
import com.androdr.scanner.bugreport.DbInfoModule
import com.androdr.scanner.bugreport.LegacyScanModule
import com.androdr.scanner.bugreport.PlatformCompatModule
import com.androdr.scanner.bugreport.ReceiverModule
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
    @Binds @IntoSet abstract fun receivers(m: ReceiverModule): BugreportModule
    @Binds @IntoSet abstract fun appOps(m: AppOpsModule): BugreportModule
    @Binds @IntoSet abstract fun batteryDaily(m: BatteryDailyModule): BugreportModule
    @Binds @IntoSet abstract fun activity(m: ActivityModule): BugreportModule
    @Binds @IntoSet abstract fun adbKeys(m: AdbKeysModule): BugreportModule
    @Binds @IntoSet abstract fun platformCompat(m: PlatformCompatModule): BugreportModule
    @Binds @IntoSet abstract fun dbInfo(m: DbInfoModule): BugreportModule
}
