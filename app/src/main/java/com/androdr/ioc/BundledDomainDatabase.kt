package com.androdr.ioc

import android.content.Context
import com.androdr.data.model.Indicator
import dagger.hilt.android.qualifiers.ApplicationContext
import javax.inject.Inject
import javax.inject.Singleton

/** Bundled known-bad domains for cold start. Loading is filled in by Task B3. */
@Singleton
open class BundledDomainDatabase @Inject constructor(
    @Suppress("UnusedPrivateProperty") @ApplicationContext private val context: Context
) {
    open fun lookup(domain: String): Indicator? = null
}
