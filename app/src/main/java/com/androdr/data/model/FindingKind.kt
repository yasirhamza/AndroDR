package com.androdr.data.model

/**
 * What a stored finding is (spec §5.4 Kind): [ALERT] when its matched record is an event fact (it
 * belongs to a lasting `alert`), [STATE] otherwise — a finding on a snapshot record, or a
 * correlation finding. State findings are current only while the latest live scan triggers them.
 */
enum class FindingKind { STATE, ALERT }
