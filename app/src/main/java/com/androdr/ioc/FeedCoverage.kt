package com.androdr.ioc

/**
 * What the indicator table held at scan start. [rulesRepoLoaded] (`androdr_public_repo`)
 * and [mvtLoaded] (`mvt_*`) are the only sources that carry campaign keys.
 */
data class FeedCoverage(val rows: Int, val rulesRepoLoaded: Boolean, val mvtLoaded: Boolean)
