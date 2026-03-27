package com.androdr.data.model

enum class RiskLevel(val score: Int) {
    CRITICAL(4),
    HIGH(3),
    MEDIUM(2),
    LOW(1)
}
