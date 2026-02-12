#!/bin/bash
# =============================================================================
# claw-proxy-client.sh — Credential proxy client for use INSIDE the Nono sandbox
#
# This script is installed as a symlink for tools that need credentials.
# Example: /usr/local/bin/gh -> /path/to/claw-proxy-client.sh
#
# When the agent calls "gh repo list", this script:
#   1. Detects it was called as "gh" (via $0)
#   2. Signs the request with the shared HMAC secret
#   3. Sends it to the claw-proxy daemon via Unix socket
#   4. Streams stdout/stderr back to the caller
#
# Requirements: socat (for Unix socket communication), jq (for JSON)
# =============================================================================

set -euo pipefail

# Configuration
SOCKET_PATH="/tmp/claw-proxy.sock"
AUTH_FILE="/tmp/claw-proxy.auth"

# Detect which tool we were called as (basename of $0)
TOOL_NAME="$(basename "$0")"

# Check dependencies
if ! command -v socat &>/dev/null; then
    echo "ERROR: socat not found. Install with: brew install socat" >&2
    exit 127
fi

if ! command -v jq &>/dev/null; then
    echo "ERROR: jq not found. Install with: brew install jq" >&2
    exit 127
fi

# Check auth file
if [ ! -f "$AUTH_FILE" ]; then
    echo "ERROR: Auth file not found at $AUTH_FILE. Is claw-proxy daemon running?" >&2
    exit 1
fi

# Read shared secret
SECRET=$(cat "$AUTH_FILE")

# Build the request payload
TIMESTAMP=$(python3 -c "import time; print(time.time())")
NONCE=$(openssl rand -hex 8)

# Build args as JSON array
ARGS_JSON=$(printf '%s\n' "$@" | jq -R . | jq -s .)

# Build canonical payload for HMAC
PAYLOAD=$(jq -n -c \
    --arg tool "$TOOL_NAME" \
    --argjson args "$ARGS_JSON" \
    --argjson ts "$TIMESTAMP" \
    --arg nonce "$NONCE" \
    '{args: $args, nonce: $nonce, timestamp: $ts, tool: $tool}')

# Sign with HMAC-SHA256
SIGNATURE=$(echo -n "$PAYLOAD" | openssl dgst -sha256 -hmac "$SECRET" | awk '{print $NF}')

# Build full message
MESSAGE=$(jq -n -c \
    --argjson payload "$PAYLOAD" \
    --arg signature "$SIGNATURE" \
    '{payload: $payload, signature: $signature}')

# Send via Unix socket and capture response
RESPONSE=$(echo "$MESSAGE" | socat -t10 - UNIX-CONNECT:"$SOCKET_PATH")

# Parse response
STDOUT=$(echo "$RESPONSE" | jq -r '.stdout // empty')
STDERR=$(echo "$RESPONSE" | jq -r '.stderr // empty')
EXITCODE=$(echo "$RESPONSE" | jq -r '.returncode // 1')
ERROR=$(echo "$RESPONSE" | jq -r '.error // empty')

# Output
if [ -n "$STDOUT" ]; then
    echo "$STDOUT"
fi

if [ -n "$STDERR" ]; then
    echo "$STDERR" >&2
fi

if [ -n "$ERROR" ]; then
    echo "claw-proxy: $ERROR" >&2
fi

exit "${EXITCODE}"
