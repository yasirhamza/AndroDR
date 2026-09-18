#!/usr/bin/env bash
# Assert a scanned report against a scenario's .patterns file.
#
# Usage: check-patterns.sh <report-file> <patterns-file>
#
# Each non-blank, non-comment line is one assertion, matched literally (grep -F):
#
#   Sideloaded Application     the report MUST contain this
#   !OVERALL RISK: HIGH        the report must NOT contain this
#   # anything                 comment, ignored
#
# The `!` form is what makes a benign baseline expressible. Before it the harness
# could only assert presence, so every scenario was an attack and over-escalation
# on a clean device — #332 — was not a question the suite could ask.
#
# Exits 0 when every assertion holds, 1 otherwise, printing one line per failure.
set -uo pipefail

report="${1:-}"
patterns="${2:-}"

if [ -z "$report" ] || [ -z "$patterns" ]; then
    echo "  usage: check-patterns.sh <report-file> <patterns-file>"
    exit 1
fi

if [ ! -f "$report" ]; then
    echo "  Could not read report — no file at $report"
    exit 1
fi

if [ ! -f "$patterns" ]; then
    echo "  No patterns file: $patterns"
    exit 1
fi

fail=0
while IFS= read -r line || [ -n "$line" ]; do
    # Strip a trailing CR so a CRLF-edited patterns file still matches.
    line="${line%$'\r'}"
    [ -z "$line" ] && continue
    case "$line" in
        '#'*)
            continue
            ;;
        '!'*)
            forbidden="${line#!}"
            [ -z "$forbidden" ] && continue
            if grep -qF -- "$forbidden" "$report"; then
                echo "  UNEXPECTED: forbidden pattern present: '$forbidden'"
                fail=1
            fi
            ;;
        *)
            if ! grep -qF -- "$line" "$report"; then
                echo "  MISS: pattern not found: '$line'"
                fail=1
            fi
            ;;
    esac
done < "$patterns"

exit "$fail"
