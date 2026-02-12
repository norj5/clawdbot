#!/bin/bash
# ============================================================================
# lock_identity.sh — Protect critical OpenClaw files from self-modification
# ============================================================================
# Uses macOS chflags uchg (user immutable flag) + strict permissions to make
# identity and config files immutable. Even root-level processes cannot modify
# these files without explicitly removing the flag first.
#
# Usage:
#   ./lock_identity.sh              # Lock all critical files
#   ./lock_identity.sh --unlock     # Unlock for admin maintenance
#   ./lock_identity.sh --status     # Check lock status
# ============================================================================

set -euo pipefail

# ─── Configuration ──────────────────────────────────────────────────────────
# Paths relative to the OpenClaw workspace. Adjust WORKSPACE_ROOT as needed.
WORKSPACE_ROOT="${OPENCLAW_WORKSPACE:-$HOME/.openclaw}"
AGENT_DIR="${OPENCLAW_AGENT_DIR:-$WORKSPACE_ROOT}"

# Critical identity files (the bot's "soul" — must never be edited by the bot)
IDENTITY_FILES=(
    "$AGENT_DIR/SOUL.md"
    "$AGENT_DIR/SOUL.txt"
    "$AGENT_DIR/identity.md"
)

# Critical config files (control-plane — if edited, the bot could escalate)
CONFIG_FILES=(
    "$WORKSPACE_ROOT/openclaw.json"
    "$WORKSPACE_ROOT/openclaw-hardened.json"
)

# Dangerous files that should never exist (block creation with a directory)
BLOCK_FILES=(
    "$AGENT_DIR/SOUL_EVIL.md"
    "$AGENT_DIR/SOUL_EVIL.txt"
)

# ─── Colors ─────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

ok()   { echo -e "  ${GREEN}✓${NC} $1"; }
warn() { echo -e "  ${YELLOW}⚠${NC} $1"; }
fail() { echo -e "  ${RED}✗${NC} $1"; }
info() { echo -e "  ${BLUE}ℹ${NC} $1"; }

# ─── Lock Functions ─────────────────────────────────────────────────────────

lock_file() {
    local file="$1"
    if [[ ! -f "$file" ]]; then
        warn "File not found (skipping): $file"
        return 0
    fi

    # Set read-only permissions (owner read only)
    chmod 444 "$file"

    # Set macOS user-immutable flag (kernel-level protection)
    chflags uchg "$file"

    ok "Locked: $file"
}

unlock_file() {
    local file="$1"
    if [[ ! -f "$file" ]]; then
        warn "File not found (skipping): $file"
        return 0
    fi

    # Remove immutable flag first (required before chmod)
    chflags nouchg "$file"

    # Restore write permission for owner
    chmod 644 "$file"

    ok "Unlocked: $file"
}

check_file() {
    local file="$1"
    if [[ ! -f "$file" ]]; then
        info "Not present: $file"
        return 0
    fi

    # Check if immutable flag is set
    local flags
    flags=$(ls -lO "$file" 2>/dev/null | awk '{print $5}')
    if echo "$flags" | grep -q "uchg"; then
        ok "LOCKED (uchg): $file"
    else
        # Check if at least read-only
        if [[ ! -w "$file" ]]; then
            warn "Read-only but NOT immutable: $file"
        else
            fail "WRITABLE — NOT PROTECTED: $file"
        fi
    fi
}

block_dangerous_files() {
    for blocked in "${BLOCK_FILES[@]}"; do
        if [[ -f "$blocked" ]]; then
            fail "DANGER: $blocked exists as a file! Removing."
            rm -f "$blocked"
        fi

        if [[ ! -d "$blocked" ]]; then
            # Create a directory with the same name to prevent file creation
            mkdir -p "$blocked"
            chmod 000 "$blocked"
            chflags uchg "$blocked"
            ok "Blocked: $blocked (directory barrier created)"
        else
            ok "Already blocked: $blocked"
        fi
    done
}

unblock_dangerous_files() {
    for blocked in "${BLOCK_FILES[@]}"; do
        if [[ -d "$blocked" ]]; then
            chflags nouchg "$blocked"
            chmod 755 "$blocked"
            rmdir "$blocked" 2>/dev/null || true
            ok "Unblocked: $blocked"
        fi
    done
}

# ─── Main ───────────────────────────────────────────────────────────────────

ACTION="${1:-lock}"

echo ""
echo "═══════════════════════════════════════════════════"
echo " OpenClaw Identity & Config Protection"
echo "═══════════════════════════════════════════════════"
echo ""

case "$ACTION" in
    --unlock|unlock)
        echo -e "${YELLOW}🔓 UNLOCKING files for admin maintenance${NC}"
        echo ""

        echo "Identity files:"
        for f in "${IDENTITY_FILES[@]}"; do
            unlock_file "$f"
        done

        echo ""
        echo "Config files:"
        for f in "${CONFIG_FILES[@]}"; do
            unlock_file "$f"
        done

        echo ""
        echo "Dangerous file blockers:"
        unblock_dangerous_files

        echo ""
        echo -e "${YELLOW}⚠  Files are now WRITABLE. Run '$0' again to re-lock.${NC}"
        ;;

    --status|status)
        echo -e "${BLUE}🔍 Checking protection status${NC}"
        echo ""

        echo "Identity files:"
        for f in "${IDENTITY_FILES[@]}"; do
            check_file "$f"
        done

        echo ""
        echo "Config files:"
        for f in "${CONFIG_FILES[@]}"; do
            check_file "$f"
        done

        echo ""
        echo "Dangerous file blockers:"
        for blocked in "${BLOCK_FILES[@]}"; do
            if [[ -d "$blocked" ]]; then
                ok "BLOCKED: $blocked (directory barrier)"
            elif [[ -f "$blocked" ]]; then
                fail "DANGER: $blocked exists as writable file!"
            else
                warn "Not blocked: $blocked (no barrier — will be created on lock)"
            fi
        done
        ;;

    lock|"")
        echo -e "${GREEN}🔒 LOCKING critical files${NC}"
        echo ""

        echo "Identity files:"
        for f in "${IDENTITY_FILES[@]}"; do
            lock_file "$f"
        done

        echo ""
        echo "Config files:"
        for f in "${CONFIG_FILES[@]}"; do
            lock_file "$f"
        done

        echo ""
        echo "Blocking dangerous files:"
        block_dangerous_files

        echo ""
        echo -e "${GREEN}✅ All critical files are now IMMUTABLE.${NC}"
        echo -e "   The bot cannot modify its identity or config."
        echo -e "   To unlock for maintenance: ${BLUE}$0 --unlock${NC}"
        ;;

    *)
        echo "Usage: $0 [lock|--unlock|--status]"
        exit 1
        ;;
esac

echo ""
