#!/usr/bin/env bash
# One guided-mode assertion (run.sh's category walkthrough).
#
# Usage: guided-check.sh <report-file> <pattern> [roadmap-issue]
#
# Every sigil means exactly what it means to check-patterns.sh (the non-guided path),
# which evaluates the pattern. Prints one result line and exits:
#   0  satisfied
#   2  not satisfied, but the scenario has a roadmap issue (expected fail)
#   1  not satisfied, or MALFORMED. A pattern that cannot be evaluated is a broken
#      guard: it is never excused as an expected fail.
set -uo pipefail

report="${1:-}"
pattern="${2:-}"
roadmap="${3:-}"
here="$(cd "$(dirname "$0")" && pwd)"

case "$pattern" in
    '!'*) label="absent: ${pattern#!}" ;;
    *) label="$pattern" ;;
esac

one_pattern=$(mktemp)
printf '%s\n' "$pattern" > "$one_pattern"
check_out=$(bash "$here/check-patterns.sh" "$report" "$one_pattern" 2>&1)
status=$?
rm -f "$one_pattern"

if [[ "$check_out" == *MALFORMED* ]]; then
    echo "    ✗ \"$label\" MALFORMED"
    echo "$check_out" | sed 's/^/      /'
    exit 1
fi
if [ "$status" -eq 0 ]; then
    echo "    ✓ \"$label\""
    exit 0
fi
if [ -n "$roadmap" ] && [ "$roadmap" != "None" ]; then
    echo "    ○ \"$label\" (expected fail — roadmap #$roadmap)"
    exit 2
fi
echo "    ✗ \"$label\" MISS"
exit 1
