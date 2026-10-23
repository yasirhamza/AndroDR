package com.androdr.data.model

/** An alert stays [OPEN] from its opening finding until a person closes it (spec §5.4 Lifecycle). */
enum class AlertStatus { OPEN, CLOSED }
