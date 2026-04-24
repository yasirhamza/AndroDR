#!/usr/bin/env bash
# Deploy cloudflare-worker.js to the live Cloudflare Worker.
#
# Prereqs:
#   - cloudflare-worker.js is in sync with docs/PRIVACY_POLICY.md
#     (re-render first if you just edited the markdown:
#       python3 scripts/render_privacy.py docs/PRIVACY_POLICY.md cloudflare-worker.js)
#   - CLOUDFLARE_API_TOKEN is set (Workers Scripts: Edit permission)
#   - CLOUDFLARE_ACCOUNT_ID is set
#
# Why not wrangler? wrangler requires Node 20+ and a wrangler.toml. This
# script uses the Cloudflare API directly so it runs in any environment
# with curl and python3 (for the JSON response parse).

set -euo pipefail

: "${CLOUDFLARE_API_TOKEN:?Set CLOUDFLARE_API_TOKEN before running}"
: "${CLOUDFLARE_ACCOUNT_ID:?Set CLOUDFLARE_ACCOUNT_ID before running}"

SCRIPT_NAME="${WORKER_SCRIPT_NAME:-androdr}"
WORKER_FILE="${WORKER_FILE:-cloudflare-worker.js}"

if [[ ! -f "$WORKER_FILE" ]]; then
  echo "error: $WORKER_FILE not found (run from repo root)" >&2
  exit 1
fi

echo "Deploying $WORKER_FILE to Cloudflare Worker '$SCRIPT_NAME'…"

response=$(
  curl -sS -X PUT \
    "https://api.cloudflare.com/client/v4/accounts/${CLOUDFLARE_ACCOUNT_ID}/workers/scripts/${SCRIPT_NAME}" \
    -H "Authorization: Bearer ${CLOUDFLARE_API_TOKEN}" \
    -F "metadata={\"main_module\":\"${WORKER_FILE}\"};type=application/json" \
    -F "${WORKER_FILE}=@${WORKER_FILE};type=application/javascript+module"
)

python3 - "$response" <<'PY'
import json, sys
data = json.loads(sys.argv[1])
if not data.get("success"):
    print("deploy failed:", file=sys.stderr)
    print(json.dumps(data.get("errors", []), indent=2), file=sys.stderr)
    sys.exit(1)
result = data.get("result") or {}
print(f"ok: deployed script '{result.get('id', '?')}' at {result.get('modified_on', '?')}")
PY
