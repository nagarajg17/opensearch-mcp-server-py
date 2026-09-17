#!/bin/bash
# Load the Cedar schema and policies into a running cedar-agent.
#
# Only schema + policies are loaded at startup. Entity data (the principal, its
# roles, and the role hierarchy) is supplied INLINE on each authorization request
# by the MCP server, so the agent's data store is intentionally left empty.
# Existing policies/data are cleared first so a new schema won't fail validation
# against stale policies. Usage: ./cedar/load.sh [CEDAR_AGENT_URL]
set -uo pipefail
A="${1:-http://localhost:8180}"
DIR="$(cd "$(dirname "$0")" && pwd)"
put() { curl -sf -o /dev/null -w "  $1: %{http_code}\n" -X PUT -H 'Content-Type: application/json' -d "$3" "$A/v1/$2"; }
putf() { curl -sf -o /dev/null -w "  $1: %{http_code}\n" -X PUT -H 'Content-Type: application/json' -d @"$4" "$A/v1/$2"; }

echo "Clearing existing policies/data..."
put "clear policies" policies '[]'
put "clear data"     data     '[]'
echo "Loading schema..."
putf "schema"   schema   schema   "$DIR/schema.json"
echo "Loading policies..."
putf "policies" policies policies "$DIR/policies.json"
echo "Done (data store intentionally empty; entities sent inline per request)."
