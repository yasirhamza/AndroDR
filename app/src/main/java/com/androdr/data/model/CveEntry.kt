package com.androdr.data.model

data class CveEntry(
    val cveId: String,
    val severity: String,
    val description: String,
    val patchLevel: String,
    val isActivelyExploited: Boolean
)
