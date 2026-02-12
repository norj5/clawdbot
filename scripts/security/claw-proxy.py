#!/usr/bin/env python3
"""
claw-proxy: Credential proxy daemon for OpenClaw on macOS.

Runs OUTSIDE the Nono sandbox. Receives signed requests via Unix socket,
reads credentials from macOS Keychain (Secure Enclave), executes the real
tool with credentials injected, and streams results back.

Architecture:
    [Agent in sandbox] --Unix socket + HMAC--> [claw-proxy daemon] --> [Keychain]
                                                       |
                                                       v
                                                  [Real binary]
                                                       |
                                                  stdout/stderr
                                                       |
                                               back to sandbox

Usage:
    # Start daemon (outside sandbox)
    python3 claw-proxy.py daemon --config config.yaml

    # Or with defaults
    python3 claw-proxy.py daemon

License: MIT
"""

import argparse
import hashlib
import hmac
import json
import logging
import os
import signal
import socket
import subprocess
import sys
import time
import threading
from pathlib import Path

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SOCKET_PATH = "/tmp/claw-proxy.sock"
AUTH_FILE = "/tmp/claw-proxy.auth"       # HMAC shared secret (read by client)
PID_FILE = "/tmp/claw-proxy.pid"
LOG_FILE = os.path.expanduser("~/.openclaw/claw-proxy.log")
KEYCHAIN_ACCOUNT = "openclaw-runner"     # macOS Keychain account name
HMAC_TOLERANCE_SECONDS = 30             # Reject requests older than this
MAX_MESSAGE_SIZE = 1024 * 64            # 64KB max per request

# Default tool configurations
DEFAULT_TOOLS = {
    "gh": {
        "binary": "/usr/bin/gh",
        "keychain_key": "openclaw/GH_TOKEN",
        "env_var": "GH_TOKEN",
        "blocked_args": [
            "repo delete", "repo archive", "auth logout",
            "ssh-key add", "ssh-key delete", "secret set",
            "api -X DELETE", "api -X PUT",
        ],
    },
    "curl": {
        "binary": "/usr/bin/curl",
        "keychain_key": None,
        "env_var": None,
        "blocked_args": [
            "--upload-file", "-T",
            "--data-binary @/",
        ],
    },
}

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

def setup_logging(verbose: bool = False):
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[
            logging.FileHandler(LOG_FILE),
            logging.StreamHandler(sys.stderr),
        ],
    )

log = logging.getLogger("claw-proxy")

# ---------------------------------------------------------------------------
# macOS Keychain integration
# ---------------------------------------------------------------------------

def keychain_read(service: str, account: str = KEYCHAIN_ACCOUNT) -> str | None:
    """Read a secret from macOS Keychain using the `security` command."""
    try:
        result = subprocess.run(
            [
                "security", "find-generic-password",
                "-a", account,
                "-s", service,
                "-w",
            ],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode == 0:
            return result.stdout.strip()
        log.warning("Keychain lookup failed for %s: %s", service, result.stderr.strip())
        return None
    except Exception as e:
        log.error("Keychain error for %s: %s", service, e)
        return None


def keychain_store(service: str, secret: str, account: str = KEYCHAIN_ACCOUNT) -> bool:
    """Store a secret in macOS Keychain."""
    subprocess.run(
        ["security", "delete-generic-password", "-a", account, "-s", service],
        capture_output=True, timeout=5,
    )
    result = subprocess.run(
        [
            "security", "add-generic-password",
            "-a", account,
            "-s", service,
            "-w", secret,
        ],
        capture_output=True, text=True, timeout=5,
    )
    return result.returncode == 0

# ---------------------------------------------------------------------------
# HMAC authentication
# ---------------------------------------------------------------------------

def generate_shared_secret() -> str:
    """Generate a cryptographically random shared secret for HMAC."""
    return hashlib.sha256(os.urandom(64)).hexdigest()


def sign_request(secret: str, payload: dict) -> str:
    """Create HMAC-SHA256 signature for a request payload."""
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hmac.new(secret.encode(), canonical.encode(), hashlib.sha256).hexdigest()


def verify_request(secret: str, payload: dict, signature: str) -> bool:
    """Verify HMAC-SHA256 signature and check timestamp freshness."""
    ts = payload.get("timestamp", 0)
    if abs(time.time() - ts) > HMAC_TOLERANCE_SECONDS:
        log.warning("Request too old: %.1f seconds", abs(time.time() - ts))
        return False

    expected = sign_request(secret, payload)
    return hmac.compare_digest(expected, signature)

# ---------------------------------------------------------------------------
# Argument blocking
# ---------------------------------------------------------------------------

def check_blocked_args(tool_config: dict, args: list[str]) -> str | None:
    """Check if any arguments match blocked patterns. Returns reason or None."""
    args_str = " ".join(args)
    for pattern in tool_config.get("blocked_args", []):
        if pattern in args_str:
            return f"Blocked argument pattern: '{pattern}'"
    return None

# ---------------------------------------------------------------------------
# Tool execution
# ---------------------------------------------------------------------------

def execute_tool(tool_name: str, args: list[str], tools_config: dict) -> dict:
    config = tools_config.get(tool_name)
    if not config:
        return {"stdout": "", "stderr": f"Unknown tool: {tool_name}", "returncode": 1}

    blocked = check_blocked_args(config, args)
    if blocked:
        log.warning("BLOCKED: %s %s \u2014 %s", tool_name, args, blocked)
        return {
            "stdout": "",
            "stderr": f"\ud83d\udeab claw-proxy: {blocked}",
            "returncode": 126,
        }

    binary = config.get("binary", f"/usr/bin/{tool_name}")
    if not os.path.isfile(binary):
        which = subprocess.run(["which", tool_name], capture_output=True, text=True)
        if which.returncode == 0:
            binary = which.stdout.strip()
        else:
            return {"stdout": "", "stderr": f"Binary not found: {binary}", "returncode": 127}

    env = os.environ.copy()
    keychain_key = config.get("keychain_key")
    env_var = config.get("env_var")

    if keychain_key and env_var:
        credential = keychain_read(keychain_key)
        if credential:
            env[env_var] = credential
            log.info("Injected %s from Keychain for %s", env_var, tool_name)
        else:
            log.warning("No credential found in Keychain for %s", keychain_key)

    for extra_env in config.get("extra_env", []):
        key = extra_env.get("key")
        kc_service = extra_env.get("keychain_key")
        if key and kc_service:
            val = keychain_read(kc_service)
            if val:
                env[key] = val

    cmd = [binary] + args
    log.info("EXECUTE: %s", " ".join(cmd))

    try:
        result = subprocess.run(
            cmd, env=env, capture_output=True, text=True,
            timeout=120,
        )
        return {
            "stdout": result.stdout,
            "stderr": result.stderr,
            "returncode": result.returncode,
        }
    except subprocess.TimeoutExpired:
        return {"stdout": "", "stderr": "claw-proxy: command timed out (120s)", "returncode": 124}
    except Exception as e:
        return {"stdout": "", "stderr": f"claw-proxy: execution error: {e}", "returncode": 1}

# ---------------------------------------------------------------------------
# Unix socket daemon
# ---------------------------------------------------------------------------

class ProxyDaemon:
    def __init__(self, socket_path: str, shared_secret: str, tools_config: dict):
        self.socket_path = socket_path
        self.shared_secret = shared_secret
        self.tools_config = tools_config
        self.running = False
        self._seen_nonces: dict[str, float] = {}

    def _cleanup_nonces(self):
        cutoff = time.time() - HMAC_TOLERANCE_SECONDS * 2
        self._seen_nonces = {
            k: v for k, v in self._seen_nonces.items() if v > cutoff
        }

    def handle_client(self, conn: socket.socket):
        try:
            raw = b""
            while True:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                raw += chunk
                if len(raw) > MAX_MESSAGE_SIZE:
                    conn.sendall(json.dumps({
                        "error": "Message too large"
                    }).encode())
                    return
                if b"\n" in raw:
                    break

            if not raw:
                return

            msg = json.loads(raw.decode().strip())
            signature = msg.get("signature", "")
            payload = msg.get("payload", {})

            if not verify_request(self.shared_secret, payload, signature):
                log.warning("REJECTED: Invalid HMAC signature")
                response = {"error": "Authentication failed", "returncode": 403}
                conn.sendall((json.dumps(response) + "\n").encode())
                return

            nonce = payload.get("nonce", "")
            if nonce in self._seen_nonces:
                log.warning("REJECTED: Replay detected (nonce=%s)", nonce[:8])
                response = {"error": "Replay detected", "returncode": 403}
                conn.sendall((json.dumps(response) + "\n").encode())
                return
            self._seen_nonces[nonce] = time.time()
            self._cleanup_nonces()

            tool = payload.get("tool", "")
            args = payload.get("args", [])

            log.info("REQUEST: tool=%s args=%s", tool, args)
            result = execute_tool(tool, args, self.tools_config)

            conn.sendall((json.dumps(result) + "\n").encode())

        except json.JSONDecodeError:
            log.error("Invalid JSON from client")
            conn.sendall(json.dumps({"error": "Invalid JSON"}).encode())
        except Exception as e:
            log.error("Client handler error: %s", e)
        finally:
            conn.close()

    def start(self):
        if os.path.exists(self.socket_path):
            os.unlink(self.socket_path)

        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(self.socket_path)
        os.chmod(self.socket_path, 0o600)
        server.listen(5)
        server.settimeout(1.0)

        self.running = True

        with open(PID_FILE, "w") as f:
            f.write(str(os.getpid()))

        log.info("claw-proxy daemon started on %s (PID %d)", self.socket_path, os.getpid())
        log.info("Tools configured: %s", list(self.tools_config.keys()))

        def shutdown(signum, frame):
            log.info("Shutting down (signal %d)...", signum)
            self.running = False

        signal.signal(signal.SIGTERM, shutdown)
        signal.signal(signal.SIGINT, shutdown)

        while self.running:
            try:
                conn, _ = server.accept()
                t = threading.Thread(target=self.handle_client, args=(conn,), daemon=True)
                t.start()
            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    log.error("Accept error: %s", e)

        server.close()
        if os.path.exists(self.socket_path):
            os.unlink(self.socket_path)
        if os.path.exists(PID_FILE):
            os.unlink(PID_FILE)
        log.info("Daemon stopped.")

# ---------------------------------------------------------------------------
# Configuration loading
# ---------------------------------------------------------------------------

def load_config(config_path: str | None) -> dict:
    if config_path and os.path.isfile(config_path):
        with open(config_path) as f:
            if config_path.endswith((".yaml", ".yml")):
                log.warning("YAML config requires PyYAML. Use JSON for zero dependencies.")
                return DEFAULT_TOOLS
            return json.load(f)
    return DEFAULT_TOOLS

# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def cmd_daemon(args):
    setup_logging(args.verbose)
    tools_config = load_config(args.config)

    if args.secret:
        secret = args.secret
    else:
        secret = generate_shared_secret()

    with open(AUTH_FILE, "w") as f:
        f.write(secret)
    os.chmod(AUTH_FILE, 0o644)
    log.info("Shared secret written to %s", AUTH_FILE)

    daemon = ProxyDaemon(
        socket_path=args.socket or SOCKET_PATH,
        shared_secret=secret,
        tools_config=tools_config,
    )
    daemon.start()


def cmd_status(args):
    if os.path.exists(PID_FILE):
        with open(PID_FILE) as f:
            pid = f.read().strip()
        try:
            os.kill(int(pid), 0)
            print(f"\u2705 claw-proxy daemon running (PID {pid})")
            print(f"   Socket: {SOCKET_PATH}")
            print(f"   Auth file: {AUTH_FILE}")
        except (OSError, ValueError):
            print("\u26a0\ufe0f  PID file exists but daemon is not running")
    else:
        print("\u274c claw-proxy daemon is not running")


def cmd_stop(args):
    if os.path.exists(PID_FILE):
        with open(PID_FILE) as f:
            pid = int(f.read().strip())
        try:
            os.kill(pid, signal.SIGTERM)
            print(f"\ud83d\uded1 Sent SIGTERM to daemon (PID {pid})")
        except OSError as e:
            print(f"\u26a0\ufe0f  Could not stop daemon: {e}")
    else:
        print("\u274c No daemon PID file found")


def cmd_test(args):
    setup_logging(False)

    if not os.path.exists(AUTH_FILE):
        print("\u274c No auth file found. Is the daemon running?")
        sys.exit(1)

    with open(AUTH_FILE) as f:
        secret = f.read().strip()

    payload = {
        "tool": args.tool,
        "args": args.tool_args,
        "timestamp": time.time(),
        "nonce": hashlib.sha256(os.urandom(16)).hexdigest()[:16],
    }
    signature = sign_request(secret, payload)
    message = json.dumps({"payload": payload, "signature": signature}) + "\n"

    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.connect(SOCKET_PATH)
    sock.sendall(message.encode())

    response = b""
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            break
        response += chunk

    sock.close()
    result = json.loads(response.decode())

    if result.get("stdout"):
        print(result["stdout"], end="")
    if result.get("stderr"):
        print(result["stderr"], end="", file=sys.stderr)
    sys.exit(result.get("returncode", 0))


def main():
    parser = argparse.ArgumentParser(
        prog="claw-proxy",
        description="Credential proxy daemon \u2014 keeps secrets out of the sandbox.",
    )
    sub = parser.add_subparsers(dest="command")

    p_daemon = sub.add_parser("daemon", help="Start the proxy daemon")
    p_daemon.add_argument("-c", "--config", help="Path to tool config file (JSON)")
    p_daemon.add_argument("-s", "--socket", help=f"Socket path (default: {SOCKET_PATH})")
    p_daemon.add_argument("--secret", help="HMAC shared secret (auto-generated if omitted)")
    p_daemon.add_argument("-v", "--verbose", action="store_true")
    p_daemon.set_defaults(func=cmd_daemon)

    p_status = sub.add_parser("status", help="Check daemon status")
    p_status.set_defaults(func=cmd_status)

    p_stop = sub.add_parser("stop", help="Stop the daemon")
    p_stop.set_defaults(func=cmd_stop)

    p_test = sub.add_parser("test", help="Send a test request")
    p_test.add_argument("tool", help="Tool name (e.g., gh)")
    p_test.add_argument("tool_args", nargs="*", help="Tool arguments")
    p_test.set_defaults(func=cmd_test)

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(1)

    args.func(args)


if __name__ == "__main__":
    main()
