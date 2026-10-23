#!/usr/bin/env bash
# Assert a scanned report against a scenario's .patterns file.
#
# Usage: check-patterns.sh <report-file> <patterns-file>
#
# Each non-blank, non-comment line is one assertion, matched literally (grep -F):
#
#   Sideloaded Application     the report MUST contain this
#   !OVERALL RISK: HIGH        the report must NOT contain this
#   ~\[MATCHED\].*evil\.com      some line MUST match this extended regex (grep -E)
#   !~\[MATCHED\].*fake\.net     no line may match this extended regex
#   @<anchor> => <required>    record-scoped: at least one record has a line matching the
#                              <anchor> regex, and every such record has a line matching
#                              <required>
#   !@<anchor> => <forbidden>  record-scoped: no record with an <anchor> line has a line
#                              matching <forbidden>
#   # anything                 comment, ignored
#
# The regex forms exist because a literal match cannot tie two facts to one
# line: "fake.net appears" and "[MATCHED] appears" both hold when fake.net is an
# [ALLOWED] row and some other domain matched.
#
# The record-scoped forms exist because the report prints each stored telemetry record as
# one block -- a header line `  [n] captured ...` followed by its own `     key: value`
# lines -- so a record's facts (a file's path and whether it exists, a domain and the
# tunnel's reason) are on separate lines of one block. A block ends at the next header or
# at the first line that is not a field line.
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

# Prints "<records with an anchor line> <of those, records with a target line>".
record_scan() {
    ANCHOR="$1" TARGET="$2" awk '
        BEGIN { a = ENVIRON["ANCHOR"]; t = ENVIRON["TARGET"] }
        function close_block() { if (inb && ha) { anchored++; if (ht) hit++ }; inb = 0; ha = 0; ht = 0 }
        /^  \[[0-9]+\] captured / { close_block(); inb = 1 }
        inb && !/^  \[[0-9]+\] captured / && !/^     / { close_block() }
        inb { if ($0 ~ a) ha = 1; if ($0 ~ t) ht = 1 }
        END { close_block(); print anchored + 0, hit + 0 }
    ' "$report"
}

fail=0
while IFS= read -r line || [ -n "$line" ]; do
    # Strip a trailing CR so a CRLF-edited patterns file still matches.
    line="${line%$'\r'}"
    [ -z "$line" ] && continue
    case "$line" in
        '#'*)
            continue
            ;;
        '!@'*)
            spec="${line:2}"
            if [[ "$spec" != *" => "* ]]; then
                echo "  MALFORMED: record-scoped assertion needs '<anchor> => <regex>': '$line'"
                fail=1
                continue
            fi
            anchor="${spec%% => *}"
            target="${spec#* => }"
            read -r anchored hit < <(record_scan "$anchor" "$target")
            if [ "$hit" -gt 0 ]; then
                echo "  UNEXPECTED: a record matching '$anchor' has a line matching '$target'"
                fail=1
            fi
            ;;
        '@'*)
            spec="${line:1}"
            if [[ "$spec" != *" => "* ]]; then
                echo "  MALFORMED: record-scoped assertion needs '<anchor> => <regex>': '$line'"
                fail=1
                continue
            fi
            anchor="${spec%% => *}"
            target="${spec#* => }"
            read -r anchored hit < <(record_scan "$anchor" "$target")
            if [ "$anchored" -eq 0 ]; then
                echo "  MISS: no record matches '$anchor'"
                fail=1
            elif [ "$hit" -lt "$anchored" ]; then
                echo "  MISS: a record matching '$anchor' has no line matching '$target'"
                fail=1
            fi
            ;;
        '!~'*)
            forbidden_re="${line:2}"
            [ -z "$forbidden_re" ] && continue
            if grep -qE -- "$forbidden_re" "$report"; then
                echo "  UNEXPECTED: forbidden regex matched: '$forbidden_re'"
                fail=1
            fi
            ;;
        '~'*)
            required_re="${line:1}"
            [ -z "$required_re" ] && continue
            if ! grep -qE -- "$required_re" "$report"; then
                echo "  MISS: regex not matched: '$required_re'"
                fail=1
            fi
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
