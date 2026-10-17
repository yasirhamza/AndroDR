package com.androdr.ioc

import com.androdr.data.model.Indicator

/** What an IOC match names. */
data class IocAttribution(val family: String, val category: String, val campaignKey: String,
                          val source: String, val reference: String)

/** Null for rows that name nothing, e.g. the bloom placeholder isKnownBadDomain returns. */
fun Indicator.attribution(): IocAttribution? = family.takeIf { it.isNotBlank() }?.let {
    IocAttribution(it, category, campaignKey, source, reference.ifBlank { "feed:$source#$it" })
}
