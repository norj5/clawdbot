#!/bin/bash
# =============================================================================
# setup_keychain.sh — Store OpenClaw credentials in macOS Keychain
#
# Run this script ONCE when setting up the Mac Studio.
# It will prompt for each API key and store it securely in Keychain.
# The claw-proxy daemon reads from Keychain at runtime — no .env files.
#
# Usage: ./setup_keychain.sh
# =============================================================================

set -euo pipefail

ACCOUNT="openclaw-runner"

echo ""
echo "🔐  OpenClaw Credential Setup (macOS Keychain)"
echo "================================================"
echo ""
echo "This will store your API keys in macOS Keychain (Secure Enclave)."
echo "They will NEVER be written to disk as plain text."
echo "Press Enter to skip any key you don't need."
echo ""

# ---- Helper ----
store_key() {
    local service="$1"
    local label="$2"
    local value="$3"

    if [ -z "$value" ]; then
        echo "   ⏭️  Skipped $label"
        return
    fi

    # Delete old entry if exists
    security delete-generic-password -a "$ACCOUNT" -s "$service" 2>/dev/null || true

    # Store new
    security add-generic-password \
        -a "$ACCOUNT" \
        -s "$service" \
        -l "$label" \
        -w "$value"

    echo "   ✅  Stored $label → Keychain service '$service'"
}

# ---- Collect keys ----

echo "── Core LLM Providers ──"
read -rsp "  OpenRouter API Key: " OPENROUTER_KEY; echo
store_key "openclaw/OPENROUTER_API_KEY" "OpenRouter API Key" "$OPENROUTER_KEY"

read -rsp "  Anthropic API Key (Claude): " ANTHROPIC_KEY; echo
store_key "openclaw/ANTHROPIC_API_KEY" "Anthropic API Key" "$ANTHROPIC_KEY"

read -rsp "  Gemini API Key: " GEMINI_KEY; echo
store_key "openclaw/GEMINI_API_KEY" "Gemini API Key" "$GEMINI_KEY"

read -rsp "  OpenAI API Key: " OPENAI_KEY; echo
store_key "openclaw/OPENAI_API_KEY" "OpenAI API Key" "$OPENAI_KEY"

echo ""
echo "── Tools & Search ──"
read -rsp "  Tavily API Key (web search): " TAVILY_KEY; echo
store_key "openclaw/TAVILY_API_KEY" "Tavily API Key" "$TAVILY_KEY"

read -rsp "  Brave Search API Key: " BRAVE_KEY; echo
store_key "openclaw/BRAVE_API_KEY" "Brave Search API Key" "$BRAVE_KEY"

read -rsp "  Firecrawl API Key: " FIRECRAWL_KEY; echo
store_key "openclaw/FIRECRAWL_API_KEY" "Firecrawl API Key" "$FIRECRAWL_KEY"

echo ""
echo "── Developer Tools ──"
read -rsp "  GitHub Token (gh CLI): " GH_KEY; echo
store_key "openclaw/GH_TOKEN" "GitHub Token" "$GH_KEY"

echo ""
echo "── Channels (optional) ──"
read -rsp "  Telegram Bot Token: " TELEGRAM_KEY; echo
store_key "openclaw/TELEGRAM_BOT_TOKEN" "Telegram Bot Token" "$TELEGRAM_KEY"

read -rsp "  Discord Bot Token: " DISCORD_KEY; echo
store_key "openclaw/DISCORD_BOT_TOKEN" "Discord Bot Token" "$DISCORD_KEY"

echo ""
echo "── Voice & Media (optional) ──"
read -rsp "  ElevenLabs API Key: " ELEVENLABS_KEY; echo
store_key "openclaw/ELEVENLABS_API_KEY" "ElevenLabs API Key" "$ELEVENLABS_KEY"

read -rsp "  Deepgram API Key: " DEEPGRAM_KEY; echo
store_key "openclaw/DEEPGRAM_API_KEY" "Deepgram API Key" "$DEEPGRAM_KEY"

echo ""
echo "── Gateway Authentication ──"
echo "  Generating a secure gateway token..."
GW_TOKEN=$(openssl rand -hex 32)
store_key "openclaw/GATEWAY_TOKEN" "OpenClaw Gateway Token" "$GW_TOKEN"
echo "   ✅  Gateway token generated and stored"
echo "   📋  Your gateway token (copy for openclaw.json): $GW_TOKEN"

echo ""
echo "================================================"
echo "✅  All credentials stored in macOS Keychain!"
echo ""
echo "To verify, run:"
echo "  security find-generic-password -a $ACCOUNT -s 'openclaw/OPENROUTER_API_KEY' -w"
echo ""
echo "To list all stored keys:"
echo "  security dump-keychain | grep openclaw/"
echo ""
