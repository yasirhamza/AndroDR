package com.androdr.ioc

import com.androdr.data.model.CertHashIocEntry

interface CertHashIocFeed {
    val sourceId: String
    suspend fun fetch(): List<CertHashIocEntry>
}
