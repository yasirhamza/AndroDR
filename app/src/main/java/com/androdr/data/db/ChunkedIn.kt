package com.androdr.data.db

/** SQLite's default bound-variable limit is 999 on API 26; stay safely below it. */
private const val MAX_CHUNK = 900

/**
 * Runs a list-bound query (`WHERE x IN (:keys)`) in chunks of at most [size] distinct keys and
 * concatenates the results in key order. Every `@Query` that takes a List/Collection must be
 * called through this (enforced by SqlCompatibilityGateTest).
 */
suspend fun <K, R> chunkedIn(
    keys: Collection<K>,
    size: Int = MAX_CHUNK,
    query: suspend (List<K>) -> List<R>
): List<R> {
    require(size in 1..MAX_CHUNK) { "chunk size must be in 1..$MAX_CHUNK, was $size" }
    val out = ArrayList<R>()
    for (chunk in keys.distinct().chunked(size)) out += query(chunk)
    return out
}

/** Like [chunkedIn] for statements with no result (e.g. `DELETE ... WHERE x IN (:keys)`). */
suspend fun <K> chunkedEach(
    keys: Collection<K>,
    size: Int = MAX_CHUNK,
    action: suspend (List<K>) -> Unit
) {
    require(size in 1..MAX_CHUNK) { "chunk size must be in 1..$MAX_CHUNK, was $size" }
    for (chunk in keys.distinct().chunked(size)) action(chunk)
}
