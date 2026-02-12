#!/bin/bash
# =============================================================================
# verify_security.sh — Verify OpenClaw Secure Deployment
#
# Run this after start_secure.sh to confirm everything is properly configured.
# Each check outputs PASS ✅ or FAIL ❌.
#
# Usage: ./verify_security.sh
# =============================================================================

set -uo pipefail

ACCOUNT="openclaw-runner"
PASSED=0
FAILED=0

pass() { echo -e "  ✅ PASS: $1"; ((PASSED++)); }
fail() { echo -e "  ❌ FAIL: $1"; ((FAILED++)); }

echo ""
echo "╔══════════════════════════════════════════════════════╗"
echo "║   🔍 OpenClaw Security Verification                 ║"
echo "╚══════════════════════════════════════════════════════╝"
echo ""

# ---- 1. Nono Installed ----
echo "── Sandbox (Nono) ──"
if command -v nono &>/dev/null; then
    pass "Nono installed: $(nono --version 2>&1 | head -1)"
else
    fail "Nono not installed"
fi

# ---- 2. Ollama Running ----
echo "── LLM Server (Ollama) ──"
if pgrep -x "ollama" >/dev/null 2>&1; then
    pass "Ollama process running"
else
    fail "Ollama not running"
fi

if curl -s http://127.0.0.1:11434/api/tags >/dev/null 2>&1; then
    MODEL_COUNT=$(curl -s http://127.0.0.1:11434/api/tags | jq '.models | length' 2>/dev/null || echo 0)
    pass "Ollama API responding ($MODEL_COUNT models loaded)"
else
    fail "Ollama API not responding on localhost:11434"
fi

# ---- 3. claw-proxy Daemon ----
echo "── Credential Proxy (claw-proxy) ──"
if [ -f /tmp/claw-proxy.pid ]; then
    PID=$(cat /tmp/claw-proxy.pid)
    if kill -0 "$PID" 2>/dev/null; then
        pass "claw-proxy daemon running (PID $PID)"
    else
        fail "claw-proxy PID file exists but process is dead"
    fi
else
    fail "claw-proxy daemon not running"
fi

if [ -S /tmp/claw-proxy.sock ]; then
    pass "Unix socket exists: /tmp/claw-proxy.sock"
else
    fail "Unix socket not found"
fi

if [ -f /tmp/claw-proxy.auth ]; then
    pass "Auth file exists: /tmp/claw-proxy.auth"
else
    fail "Auth file not found"
fi

# ---- 4. Keychain Credentials ----
echo "── Credentials (Keychain) ──"
check_keychain() {
    local service="$1"
    local label="$2"
    if security find-generic-password -a "$ACCOUNT" -s "$service" -w >/dev/null 2>&1; then
        pass "$label stored in Keychain"
    else
        fail "$label NOT in Keychain (service: $service)"
    fi
}

check_keychain "openclaw/GATEWAY_TOKEN"       "Gateway Token"
check_keychain "openclaw/OPENROUTER_API_KEY"  "OpenRouter API Key"

# ---- 5. No Plaintext Secrets ----
echo "── Plaintext Secret Detection ──"
if [ -f "$HOME/.openclaw/.env" ]; then
    if grep -qE "(API_KEY|TOKEN|SECRET|PASSWORD)=.+" "$HOME/.openclaw/.env" 2>/dev/null; then
        fail "Plaintext secrets found in ~/.openclaw/.env — DELETE THIS FILE"
    else
        pass "~/.openclaw/.env exists but has no secrets"
    fi
else
    pass "No .env file found (good)"
fi

# Check for secrets in openclaw.json
if [ -f "$HOME/.openclaw/openclaw.json" ]; then
    if grep -qE "sk-|sk-or-|sk-ant-|xoxb-" "$HOME/.openclaw/openclaw.json" 2>/dev/null; then
        fail "API keys found in openclaw.json — use Keychain instead"
    else
        pass "No API keys in openclaw.json"
    fi
fi

# ---- 6. Hardened Configuration ----
echo "── Configuration (openclaw.json) ──"
if [ -f "$HOME/.openclaw/openclaw.json" ]; then
    if jq -e '.gateway.nodes.denyCommands' "$HOME/.openclaw/openclaw.json" >/dev/null 2>&1; then
        DENIED=$(jq '.gateway.nodes.denyCommands | length' "$HOME/.openclaw/openclaw.json")
        pass "denyCommands configured ($DENIED commands blocked)"
        if jq -e '.gateway.nodes.denyCommands | index("system.run")' "$HOME/.openclaw/openclaw.json" >/dev/null 2>&1; then
            pass "system.run is BLOCKED"
        else
            fail "system.run is NOT blocked — add it to denyCommands"
        fi
    else
        fail "No denyCommands in openclaw.json"
    fi
else
    fail "openclaw.json not found"
fi

# ---- 7. Network ----
echo "── Network (Tailscale) ──"
if command -v tailscale &>/dev/null; then
    if tailscale status >/dev/null 2>&1; then
        pass "Tailscale connected"
    else
        fail "Tailscale installed but not connected"
    fi
else
    fail "Tailscale not installed"
fi

# ---- 8. Tool Symlinks ----
echo "── Tool Proxy Symlinks ──"
if [ -L "/usr/local/bin/gh" ]; then
    TARGET=$(readlink "/usr/local/bin/gh")
    if echo "$TARGET" | grep -q "claw-proxy-client"; then
        pass "gh → claw-proxy-client"
    else
        fail "gh symlink points to: $TARGET (expected claw-proxy-client)"
    fi
else
    fail "gh is not a symlink (not proxied)"
fi

# ---- Summary ----
echo ""
echo "════════════════════════════════"
echo "  Results: $PASSED passed, $FAILED failed"
echo "════════════════════════════════"
if [ "$FAILED" -eq 0 ]; then
    echo ""
    echo "  🟢 ALL CHECKS PASSED — System is secure"
else
    echo ""
    echo "  🔴 $FAILED issues need attention"
fi
echo ""
