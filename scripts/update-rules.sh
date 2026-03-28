#!/usr/bin/env bash
# update-rules.sh — Launch the AI-powered SIGMA rule update pipeline via Claude Code
#
# Usage:
#   ./scripts/update-rules.sh full                       # Check all feeds
#   ./scripts/update-rules.sh source stalkerware          # Check one feed
#   ./scripts/update-rules.sh threat "Sturnus trojan"     # Research a specific threat
#
# Valid source IDs: abusech, asb, nvd, amnesty, citizenlab, stalkerware, attack

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

usage() {
    cat <<EOF
Usage: $(basename "$0") <mode> [argument]

Modes:
  full                     Check all 7 threat intel feeds
  source <id>              Check a single feed
  threat "<name>"          Research a specific threat

Valid source IDs:
  abusech      abuse.ch (ThreatFox, MalwareBazaar, URLhaus)
  asb          Android Security Bulletins
  nvd          NVD/NIST CVE database
  amnesty      AmnestyTech/investigations
  citizenlab   Citizen Lab malware-indicators
  stalkerware  stalkerware-indicators
  attack       MITRE ATT&CK Mobile

Examples:
  $(basename "$0") full
  $(basename "$0") source stalkerware
  $(basename "$0") source asb
  $(basename "$0") threat "Anatsa banking trojan"
  $(basename "$0") threat "CVE-2025-48633"
EOF
    exit 1
}

VALID_SOURCES="abusech asb nvd amnesty citizenlab stalkerware attack"

mode="${1:-}"
[ -z "$mode" ] && usage

case "$mode" in
    full)
        prompt="/update-rules full"
        ;;
    source)
        source_id="${2:-}"
        [ -z "$source_id" ] && { echo "Error: source mode requires a feed ID"; usage; }
        if ! echo "$VALID_SOURCES" | grep -qw "$source_id"; then
            echo "Error: unknown source '$source_id'"
            echo "Valid sources: $VALID_SOURCES"
            exit 1
        fi
        prompt="/update-rules source $source_id"
        ;;
    threat)
        threat_name="${2:-}"
        [ -z "$threat_name" ] && { echo "Error: threat mode requires a threat name"; usage; }
        prompt="/update-rules threat \"$threat_name\""
        ;;
    -h|--help|help)
        usage
        ;;
    *)
        echo "Error: unknown mode '$mode'"
        usage
        ;;
esac

echo "Starting AI rule update pipeline: $prompt"
echo "Working directory: $SCRIPT_DIR"
echo "---"

cd "$SCRIPT_DIR"
exec claude --print "$prompt"
