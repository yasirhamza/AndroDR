package com.androdr.data.model

import androidx.room.Entity
import androidx.room.PrimaryKey

/**
 * Content-addressed telemetry body (spec §5.1). [hash] is a 16-byte h128 of the canonical JSON;
 * [encoding] 0 = plain JSON, 1 = Deflate with the preset dictionary [dictVersion]; [rawBytes] is
 * the inflated size. A plain class: it holds `ByteArray`s, which data-class equality would compare
 * by identity.
 */
@Entity(tableName = "record_body")
class RecordBody(
    @PrimaryKey val hash: ByteArray,
    val encoding: Int,
    val dictVersion: Int,
    val body: ByteArray,
    val rawBytes: Int,
)
