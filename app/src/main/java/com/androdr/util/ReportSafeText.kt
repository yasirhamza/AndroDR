package com.androdr.util

/** Longest a feed-controlled string may be once it reaches a report line. */
const val MAX_REPORT_TEXT_CHARS = 64

/**
 * Reduces a feed-controlled string to printable ASCII, then caps its length.
 *
 * Printable-ASCII-only is not cosmetic. Reports are strictly ASCII (enforced by
 * `ReportFormatterTest`) and rendered one entry per line, so CR/LF inside a rule
 * title, id or lookup name would otherwise inject lines that read as additional
 * report content -- a forged section in a document sent to a responder. Rules
 * arrive from a feed, and custom rule URLs ship without a hash manifest by
 * design, so neither field is trustworthy.
 *
 * Shared so that every path writing feed text into a report applies the same
 * rule: one surface with two trust policies is the inconsistency that gets
 * copied.
 */
fun reportSafe(value: String, max: Int = MAX_REPORT_TEXT_CHARS): String =
    value.filter { it in ' '..'~' }.take(max)
