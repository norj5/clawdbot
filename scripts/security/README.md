# 🔒 OpenClaw Security Toolkit

Custom security implementation for running OpenClaw in a Zero Trust environment on macOS.

## Architecture

```
┌─────────────────────────────────────────────┐
│         Nono Sandbox (Seatbelt)             │
│                                             │
│   OpenClaw Agent                            │
│     ↓                                       │
│   /usr/local/bin/gh → claw-proxy-client.sh  │
│     ↓                                       │
│   Signs request (HMAC-SHA256)               │
│     ↓                                       │
└─────┤ Unix Socket ├─────────────────────────┘
      │
┌─────┴──────────────────────────────────────┐
│   claw-proxy.py (daemon, OUTSIDE sandbox)  │
│     ↓                                      │
│   Verifies HMAC + checks blocked args      │
│     ↓                                      │
│   Reads credential from macOS Keychain     │
│     ↓                                      │
│   Executes real binary with token injected │
│     ↓                                      │
│   Returns stdout/stderr to sandbox         │
└────────────────────────────────────────────┘
```

## Quick Start

```bash
# 1. Store your credentials (one time)
./setup_keychain.sh

# 2. Start everything
./start_secure.sh

# 3. Verify security (in another terminal)
./verify_security.sh
```

## Files

| File | Purpose |
|---|---|
| `claw-proxy.py` | Credential proxy daemon (Python, zero deps) |
| `claw-proxy-client.sh` | Client inside sandbox (symlinked as `gh`, etc.) |
| `claw-proxy-config.json` | Tool definitions and blocked arguments |
| `setup_keychain.sh` | Interactive credential bootstrapping |
| `start_secure.sh` | Master startup (Ollama → Proxy → Nono) |
| `verify_security.sh` | Automated security checks |
| `openclaw-hardened.json` | Hardened `openclaw.json` template |

## Requirements

- macOS (Apple Silicon recommended)
- [Nono](https://github.com/lukehinds/nono) (`brew tap lukehinds/nono && brew install nono`)
- Python 3 (system)
- `socat` (`brew install socat`)
- `jq` (`brew install jq`)
- [Ollama](https://ollama.com)
