package com.androdr.reporting

import com.androdr.data.db.ServiceSummary
import com.androdr.data.store.DecodedRecord

/**
 * The telemetry a report reads: one scan's own stored observations, nothing else (spec §7). The
 * report used to print `ScanOrchestrator`'s last-scan caches, so an older scan's report showed the
 * newest scan's apps. [com.androdr.data.store.TelemetryReader] is the production source; every
 * read is scoped by the scan id and sees only `COMPLETE` scans.
 */
interface StoredTelemetrySource {
    /** The services [scanId] stored records for, with their counts, ordered by service. */
    suspend fun services(scanId: Long): List<ServiceSummary>

    /** Streams [scanId]'s records of [service] in ordinal order, a batch at a time. */
    suspend fun forEach(scanId: Long, service: String, block: suspend (DecodedRecord) -> Unit)

    /**
     * The latest exact event time among [scanId]'s records no later than [notAfter], or null when
     * none has one. The bound keeps a record with a bogus future time (a corrupt line, a clock set
     * ahead) from becoming the import's reference time.
     */
    suspend fun latestEventTime(scanId: Long, notAfter: Long): Long?
}
