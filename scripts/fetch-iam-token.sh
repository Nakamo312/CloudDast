#!/usr/bin/env bash
set -euo pipefail

project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$project_dir"

if [[ -f .env ]]; then
  set -a
  # shellcheck disable=SC1091
  source .env
  set +a
fi

: "${CLOUD_DAST_IAM_TOKEN_COMMAND:?set CLOUD_DAST_IAM_TOKEN_COMMAND in .env}"
: "${IAM_TOKEN_FILE:?set IAM_TOKEN_FILE in .env}"

output_dir="$(dirname "$IAM_TOKEN_FILE")"
mkdir -p "$output_dir"
umask 077
temporary="$(mktemp "$output_dir/.iam-token.XXXXXX")"
trap 'rm -f "$temporary"' EXIT

# The command is intentionally local user configuration. Its stdout is the only
# value written; stderr and the token itself are never printed by this script.
token="$(bash -lc "$CLOUD_DAST_IAM_TOKEN_COMMAND")"
if [[ -z "$token" || "$token" == *[[:space:]]* ]]; then
  echo "IAM token command returned invalid output" >&2
  exit 1
fi

printf '%s\n' "$token" > "$temporary"
chmod 600 "$temporary"
mv "$temporary" "$IAM_TOKEN_FILE"
trap - EXIT
echo "IAM token refreshed at $IAM_TOKEN_FILE" >&2
