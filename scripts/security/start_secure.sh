#!/bin/bash
# =============================================================================
# start_secure.sh — Master startup script for OpenClaw Secure Deployment
#
# This is the ONLY script you need to run. It:
#   1. Verifies all dependencies are installed
#   2. Starts Ollama (local LLM server)
#   3. Starts claw-proxy daemon (credential proxy)
#   4. Creates symlinks for proxied tools
#   5. Loads essential credentials from Keychain into env
#   6. Launches OpenClaw Gateway inside the Nono sandbox
#
# Usage:
#   chmod +x start_secure.sh
#   ./start_secure.sh
#
# To stop everything:
#   ./start_secure.sh stop
# =============================================================================

set -euo pipefail

# ---- Configuration ----
ACCOUNT="openclaw-runner"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROXY_SCRIPT="$SCRIPT_DIR/claw-proxy.py"
CLIENT_SCRIPT="$SCRIPT_DIR/claw-proxy-client.sh"
PROXY_BIN_DIR="/usr/local/bin"   # Where symlinks go (must be in sandbox PATH)
OPENCLAW_DIR="$HOME/.openclaw"

# ---- Colors ----
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log()  { echo -e "${GREEN}✅${NC} $1"; }
warn() { echo -e "${YELLOW}⚠️${NC}  $1"; }
fail() { echo -e "${RED}❌${NC} $1"; exit 1; }
info() { echo -e "${BLUE}ℹ️${NC}  $1"; }

# ---- Stop command ----
if [ "${1:-}" = "stop" ]; then
    echo ""
    echo "🛑 Stopping OpenClaw Secure Environment..."
    python3 "$PROXY_SCRIPT" stop 2>/dev/null || true
    pkill -f "openclaw gateway" 2>/dev/null || true
    log "Environment stopped."
    exit 0
fi

# ---- Banner ----
echo ""
echo "╔══════════════════════════════════════════════════════╗"
echo "║   🔒 OpenClaw Secure Startup — Zero Trust Mode      ║"
echo "╚══════════════════════════════════════════════════════╝"
echo ""

# ---- Step 1: Verify Dependencies ----
info "Checking dependencies..."

check_cmd() {
    if command -v "$1" &>/dev/null; then
        log "$1 found: $(command -v "$1")"
    else
        fail "$1 not found. Install with: $2"
    fi
}

check_cmd "nono"       "brew tap lukehinds/nono && brew install nono"
check_cmd "ollama"     "https://ollama.com"
check_cmd "node"       "fnm install 22 && fnm use 22"
check_cmd "python3"    "System Python should be available on macOS"
check_cmd "socat"      "brew install socat"
check_cmd "jq"         "brew install jq"
check_cmd "openclaw"   "npm install -g openclaw or build from fork"

echo ""

# ---- Step 2: Start Ollama ----
info "Checking Ollama..."
if pgrep -x "ollama" >/dev/null 2>&1; then
    log "Ollama already running"
else
    warn "Ollama not running. Starting..."
    ollama serve &>/dev/null &
    sleep 2
    if pgrep -x "ollama" >/dev/null 2>&1; then
        log "Ollama started"
    else
        fail "Failed to start Ollama"
    fi
fi

# Verify model is available
if ollama list 2>/dev/null | grep -q "qwen"; then
    log "Qwen model found in Ollama"
else
    warn "No Qwen model found. Run: ollama pull qwen2.5:32b-instruct-q4_k_m"
fi
echo ""

# ---- Step 3: Start claw-proxy daemon ----
info "Starting credential proxy daemon..."

# Check if already running
if python3 "$PROXY_SCRIPT" status 2>/dev/null | grep -q "running"; then
    log "claw-proxy daemon already running"
else
    python3 "$PROXY_SCRIPT" daemon &>/dev/null &
    sleep 1
    if python3 "$PROXY_SCRIPT" status 2>/dev/null | grep -q "running"; then
        log "claw-proxy daemon started"
    else
        fail "Failed to start claw-proxy daemon"
    fi
fi
echo ""

# ---- Step 4: Install symlinks for proxied tools ----
info "Setting up tool symlinks..."

install_symlink() {
    local tool="$1"
    local target="$PROXY_BIN_DIR/$tool"

    if [ -L "$target" ] && [ "$(readlink "$target")" = "$CLIENT_SCRIPT" ]; then
        log "$tool symlink already configured"
    elif [ -f "$target" ] && [ ! -L "$target" ]; then
        # Backup the real binary
        local backup="$target.real"
        if [ ! -f "$backup" ]; then
            warn "Backing up real $tool to $backup"
            sudo mv "$target" "$backup"
        fi
        sudo ln -sf "$CLIENT_SCRIPT" "$target"
        log "$tool → claw-proxy-client (real binary backed up)"
    else
        sudo ln -sf "$CLIENT_SCRIPT" "$target"
        log "$tool → claw-proxy-client"
    fi
}

# Only proxy tools that actually need credentials
# gh needs GH_TOKEN — proxy it
install_symlink "gh"

echo ""

# ---- Step 5: Load essential credentials into env ----
info "Loading credentials from Keychain..."

load_keychain() {
    local service="$1"
    local var_name="$2"
    local value
    value=$(security find-generic-password -a "$ACCOUNT" -s "$service" -w 2>/dev/null) || true
    if [ -n "$value" ]; then
        export "$var_name"="$value"
        log "Loaded $var_name from Keychain"
    else
        warn "$var_name not found in Keychain (service: $service)"
    fi
}

# These env vars are needed by OpenClaw directly (not proxied tools)
load_keychain "openclaw/OPENROUTER_API_KEY"    "OPENROUTER_API_KEY"
load_keychain "openclaw/ANTHROPIC_API_KEY"      "ANTHROPIC_API_KEY"
load_keychain "openclaw/GEMINI_API_KEY"         "GEMINI_API_KEY"
load_keychain "openclaw/OPENAI_API_KEY"         "OPENAI_API_KEY"
load_keychain "openclaw/TAVILY_API_KEY"         "TAVILY_API_KEY"
load_keychain "openclaw/BRAVE_API_KEY"          "BRAVE_API_KEY"
load_keychain "openclaw/GATEWAY_TOKEN"          "OPENCLAW_GATEWAY_TOKEN"
load_keychain "openclaw/TELEGRAM_BOT_TOKEN"     "TELEGRAM_BOT_TOKEN"
load_keychain "openclaw/DISCORD_BOT_TOKEN"      "DISCORD_BOT_TOKEN"
load_keychain "openclaw/ELEVENLABS_API_KEY"     "ELEVENLABS_API_KEY"
load_keychain "openclaw/DEEPGRAM_API_KEY"       "DEEPGRAM_API_KEY"

echo ""

# ---- Step 6: Launch OpenClaw in Nono Sandbox ----
info "Launching OpenClaw Gateway in Nono Sandbox..."
echo ""
echo "╔══════════════════════════════════════════════════════╗"
echo "║   🦀 Agent launching in sandboxed environment...    ║"
echo "║                                                      ║"
echo "║   Sandbox: Nono (Apple Seatbelt kernel enforcement)  ║"
echo "║   Credentials: macOS Keychain → env injection        ║"
echo "║   Tool proxy: claw-proxy daemon (Unix socket)        ║"
echo "║   Blocked: system.run, camera, screen, sms           ║"
echo "║                                                      ║"
echo "║   Press Ctrl+C to stop                               ║"
echo "╚══════════════════════════════════════════════════════╝"
echo ""

# Build the nono command
nono run \
    --allow "$OPENCLAW_DIR" \
    --allow /tmp/claw-proxy.sock \
    --allow /tmp/claw-proxy.auth \
    --read /System/Library/Fonts \
    --read /usr/lib \
    --read /usr/local/bin \
    --env OPENROUTER_API_KEY \
    --env ANTHROPIC_API_KEY \
    --env GEMINI_API_KEY \
    --env OPENAI_API_KEY \
    --env TAVILY_API_KEY \
    --env BRAVE_API_KEY \
    --env OPENCLAW_GATEWAY_TOKEN \
    --env TELEGRAM_BOT_TOKEN \
    --env DISCORD_BOT_TOKEN \
    --env ELEVENLABS_API_KEY \
    --env DEEPGRAM_API_KEY \
    --env PATH \
    --env HOME \
    --env USER \
    --env SHELL \
    --env TERM \
    -- openclaw gateway
