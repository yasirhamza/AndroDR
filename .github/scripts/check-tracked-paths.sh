#!/usr/bin/env bash
# Outbound-leak guard: fail if any TRACKED file matches a denylisted
# local-state/sensitive path. gitleaks scans content; this catches whole
# state dirs / keystores that contain no classic secret pattern.
set -euo pipefail

DENYLIST="${1:-.github/tracked-path-denylist.txt}"
fail=0
while IFS= read -r pattern || [ -n "$pattern" ]; do
  pattern="${pattern%$'\r'}"
  pattern="${pattern%"${pattern##*[![:space:]]}"}"
  case "$pattern" in ''|'#'*) continue ;; esac
  matches=$(git ls-files -- ":(glob,icase)$pattern")
  if [ -n "$matches" ]; then
    echo "DENYLISTED tracked path(s) matching '$pattern':" >&2
    echo "$matches" >&2
    fail=1
  fi
done < "$DENYLIST"

if [ "$fail" -ne 0 ]; then
  echo "FAIL: sensitive/local-state paths are tracked." >&2
  echo "Untrack with 'git rm --cached <path>' and keep them in .gitignore." >&2
  exit 1
fi
echo "PASS: no tracked file matches the denylist"
