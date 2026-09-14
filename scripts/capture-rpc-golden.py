#!/usr/bin/env python3
"""Capture golden request/response pairs from a throwaway KeyLease daemon.

Creates a temporary vault + client + broad grant, starts `keylease serve
--start-locked` on a temporary socket, drives a fixed sequence of RPC calls
over the Unix socket, and writes sanitized pairs to test-vectors/rpc/golden/.

Secrets (client token, master password, revealed field values) are replaced
with "<redacted-...>" placeholders before anything is written to the repo.
Recorded ids (vault/group/item) stay real because requests and responses
within one file refer to each other.

Usage: scripts/capture-rpc-golden.py [path-to-keylease-binary]
       (defaults to target/debug/keylease; run `cargo build -p keylease-cli`
       first)
"""

from __future__ import annotations

import fcntl
import json
import os
import pty
import select
import socket
import subprocess
import sys
import tempfile
import termios
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
OUT_DIR = REPO / "test-vectors" / "rpc" / "golden"
PASSWORD = "golden capture password"
PLACEHOLDER_TOKEN = "<redacted-client-token>"
PLACEHOLDER_PASSWORD = "<redacted-master-password>"
PLACEHOLDER_SECRET = "<redacted-secret>"

GRANT_ACTIONS = ",".join(
    [
        "entry:create",
        "entry:delete",
        "entry:move",
        "entry:read_fields",
        "entry:read_metadata",
        "entry:read_secret",
        "entry:read_username",
        "entry:search",
        "entry:update",
        "entry:update_protected_fields",
        "entry:update_standard_fields",
        "entry:update_totp",
        "group:create",
        "group:delete",
        "group:update",
        "project:create",
        "project:list",
        "content:create",
        "content:read",
        "content:review",
        "content:search",
        "content:set_access",
        "content:update",
        "connection:add",
        "connection:disconnect",
        "connection:enroll",
        "connection:list",
        "connection:refresh",
        "connection:revoke",
        "connection:test",
        "connection:unenroll",
        "approval:decide",
        "approval:list",
        "audit:query",
        "migration:apply",
        "migration:rollback",
    ]
)


def run(cli: list[str], **kwargs) -> dict:
    proc = subprocess.run(cli, capture_output=True, text=True, **kwargs)
    if proc.returncode != 0:
        raise SystemExit(
            f"command failed: {cli}\nstdout={proc.stdout}\nstderr={proc.stderr}"
        )
    return json.loads(proc.stdout) if proc.stdout.strip() else {}


def run_tty(cli: list[str], password: str) -> dict:
    """Run a CLI command that prompts for the master password.

    `client register` and `grant create` go through `admin_service`, which
    refuses to read passwords from anything but an interactive TTY. A pty
    with TIOCSCTTY provides exactly that without a real terminal.
    """
    master, slave = pty.openpty()

    def preexec():
        fcntl.ioctl(0, termios.TIOCSCTTY, 0)

    proc = subprocess.Popen(
        cli,
        stdin=slave,
        stdout=slave,
        stderr=slave,
        close_fds=True,
        start_new_session=True,
        preexec_fn=preexec,
    )
    os.close(slave)
    out = b""
    sent = False
    deadline = time.time() + 30
    while time.time() < deadline:
        ready, _, _ = select.select([master], [], [], 0.5)
        if ready:
            try:
                out += os.read(master, 65536)
            except OSError:
                break
        if not sent and b"password" in out.lower():
            time.sleep(0.2)
            os.write(master, password.encode() + b"\r")
            sent = True
        if proc.poll() is not None and not ready:
            break
    proc.wait(timeout=15)
    os.close(master)
    text = out.decode(errors="replace")
    if proc.returncode != 0:
        raise SystemExit(f"command failed: {cli}\noutput={text}")
    start, end = text.find("{"), text.rfind("}")
    if start < 0 or end <= start:
        raise SystemExit(f"no JSON in output of {cli}\noutput={text}")
    return json.loads(text[start : end + 1])


class GoldenDaemon:
    def __init__(self, sock_path: Path):
        self.sock_path = sock_path

    def call(self, request: dict) -> dict:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
            conn.connect(str(self.sock_path))
            conn.sendall(json.dumps(request).encode() + b"\n")
            buf = b""
            while b"\n" not in buf:
                chunk = conn.recv(65536)
                if not chunk:
                    break
                buf += chunk
        return json.loads(buf.split(b"\n")[0])


def scrub(value, secrets: dict[str, str]):
    """Replace secret strings in-place, preserving JSON structure."""
    if isinstance(value, dict):
        return {k: scrub(v, secrets) for k, v in value.items()}
    if isinstance(value, list):
        return [scrub(v, secrets) for v in value]
    if isinstance(value, str):
        return secrets.get(value, value)
    return value


def main() -> int:
    keylease = sys.argv[1] if len(sys.argv) > 1 else str(
        REPO / "target" / "debug" / "keylease"
    )
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    for old in OUT_DIR.glob("*.json"):
        old.unlink()

    with tempfile.TemporaryDirectory(prefix="keylease-golden-") as tmp:
        tmp = Path(tmp)
        db = tmp / "golden.sqlite"
        sock = tmp / "keylease.sock"
        password_file = tmp / "master-password"
        password_file.write_text(PASSWORD)
        password_file.chmod(0o600)

        initialized = run([keylease, "--db", str(db), "vault", "init",
                           "--password-file", str(password_file)])
        vault_id = initialized["vault_id"]

        registered = run_tty(
            [keylease, "--db", str(db), "client", "register", "golden-capture"],
            PASSWORD,
        )
        agent_id = registered["agent_id"]
        token = registered["client_token"]

        run_tty(
            [
                keylease, "--db", str(db), "grant", "create",
                "--client", agent_id,
                "--resource", f"kl://{vault_id}",
                "--allow", GRANT_ACTIONS,
            ],
            PASSWORD,
        )

        daemon = subprocess.Popen(
            [
                keylease, "--db", str(db), "--socket", str(sock),
                "serve", "--start-locked",
            ],
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            for _ in range(100):
                if sock.exists():
                    break
                if daemon.poll() is not None:
                    raise SystemExit(
                        f"daemon exited early: {daemon.stderr.read()}"
                    )
                time.sleep(0.1)

            conn = GoldenDaemon(sock)
            auth = {
                "agent_id": agent_id,
                "token": token,
                "session_id": "golden",
            }
            secrets = {
                token: PLACEHOLDER_TOKEN,
                PASSWORD: PLACEHOLDER_PASSWORD,
            }
            context: dict[str, str] = {}

            def capture(name: str, request: dict, authenticated=True):
                wire = dict(request)
                if authenticated:
                    wire["auth"] = dict(auth)
                response = conn.call(wire)
                pair = {
                    "name": name,
                    "request": scrub(wire, secrets),
                    "response": scrub(response, secrets),
                }
                out = OUT_DIR / f"{name}.json"
                out.write_text(json.dumps(pair, indent=2) + "\n")
                print(f"  {name}: ok={response.get('ok')}")
                return response

            def result(response: dict):
                if not response.get("ok"):
                    raise SystemExit(
                        f"capture step failed: {json.dumps(response)[:400]}"
                    )
                return response["result"]

            print("capturing golden vectors:")
            capture("00_status_locked", {"command": "status"},
                    authenticated=False)

            bad = dict(auth)
            bad["token"] = token  # real auth, wrong password below
            wrong = {
                "command": "unlock",
                "password": "not the password",
                "session_ttl_seconds": 3600,
                "auth": bad,
            }
            response = conn.call(wrong)
            wrong["password"] = PLACEHOLDER_PASSWORD
            (OUT_DIR / "01_unlock_wrong_password.json").write_text(
                json.dumps({"name": "01_unlock_wrong_password",
                            "request": scrub(wrong, secrets),
                            "response": response}, indent=2) + "\n"
            )
            print(f"  01_unlock_wrong_password: ok={response.get('ok')}")

            result(capture("02_unlock", {
                "command": "unlock",
                "password": PASSWORD,
                "session_ttl_seconds": 3600,
            }))
            capture("03_status_unlocked", {"command": "status"})

            group = result(capture("04_groups_create", {
                "command": "groups_create",
                "name": "Golden Group",
                "parent_id": None,
                "idempotency_key": "golden-group-1",
                "dry_run": False,
            }))
            context["group_id"] = group.get("id") or group.get("group", {}).get(
                "id"
            ) or json.dumps(group)
            capture("05_groups_list", {"command": "groups_list"})

            capture("06_templates_list", {"command": "templates_list"})
            capture("07_templates_get", {
                "command": "templates_get", "kind": "core.login",
            })

            secrets["correct horse battery staple"] = PLACEHOLDER_SECRET
            entry = result(capture("08_entries_create", {
                "command": "entries_create",
                "input": {
                    "group_id": context["group_id"],
                    "kind": "core.login",
                    "title": "Golden Login",
                    "username": "golden@example.com",
                    "password": "correct horse battery staple",
                    "url": "https://example.com",
                    "totp_uri": "otpauth://totp/Golden:golden@example.com"
                                "?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
                                "&issuer=Golden&algorithm=SHA1&digits=6"
                                "&period=30",
                },
                "idempotency_key": "golden-entry-1",
                "dry_run": False,
            }))
            item_id = (
                entry.get("id")
                or entry.get("item_id")
                or entry.get("metadata", {}).get("id")
            )
            context["item_id"] = item_id

            capture("09_entries_search", {
                "command": "entries_search", "query": "golden",
            })
            capture("10_entries_get", {
                "command": "entries_get", "id": item_id,
            })
            view = capture("11_entries_view", {
                "command": "entries_view", "id": item_id,
            })
            capture("12_entries_reveal_username", {
                "command": "entries_reveal", "id": item_id,
                "field": "username",
            })
            capture("13_entries_reveal_password", {
                "command": "entries_reveal", "id": item_id,
                "field": "password",
            })
            capture("14_entries_totp", {
                "command": "entries_totp", "id": item_id,
            })
            capture("15_entries_history", {
                "command": "entries_history", "id": item_id,
            })

            # entries_reveal_by_id needs a real field id from the view.
            fields = (
                view.get("result", {}).get("fields")
                or view.get("result", {}).get("sections", [{}])
            )
            field_id = None
            if isinstance(fields, list) and fields:
                field_id = fields[0].get("id")
            if field_id:
                capture("16_entries_reveal_by_id", {
                    "command": "entries_reveal_by_id",
                    "id": item_id, "field_id": field_id,
                })

            generated = capture("17_generate_password", {
                "command": "generate_password", "length": 24,
            })
            # The generated password is a live credential-shaped string; keep
            # only the shape in the vector.
            generated_pw = generated.get("result", {}).get("password")
            if generated_pw:
                secrets[generated_pw] = PLACEHOLDER_SECRET
                path = OUT_DIR / "17_generate_password.json"
                pair = json.loads(path.read_text())
                path.write_text(
                    json.dumps(scrub(pair, secrets), indent=2) + "\n"
                )
            capture("18_connections_list", {"command": "connections_list"})
            capture("19_approvals_list", {
                "command": "approvals_list", "limit": 50,
            })
            capture("20_audit_query", {
                "command": "audit_query", "limit": 50,
            })

            # A second registered client with no grants -> typed `denied`.
            unprivileged = run_tty(
                [
                    keylease, "--db", str(db),
                    "client", "register", "golden-nogrants",
                ],
                PASSWORD,
            )
            secrets[unprivileged["client_token"]] = PLACEHOLDER_TOKEN
            denied_auth = {
                "agent_id": unprivileged["agent_id"],
                "token": unprivileged["client_token"],
                "session_id": "golden-denied",
            }
            denied = conn.call({
                "command": "entries_search",
                "auth": denied_auth,
                "query": "golden",
            })
            (OUT_DIR / "21_denied.json").write_text(json.dumps({
                "name": "21_denied",
                "request": scrub({
                    "command": "entries_search", "auth": denied_auth,
                    "query": "golden",
                }, secrets),
                "response": denied,
            }, indent=2) + "\n")
            print(f"  21_denied: ok={denied.get('ok')}")

            # Structurally malformed request -> `invalid_request` envelope.
            malformed = {
                "command": "lease_request",
                "auth": auth,
                "request": {"unexpected": "shape"},
                "ttl_seconds": 60,
                "max_uses": 1,
                "approval_id": None,
            }
            invalid = conn.call(malformed)
            (OUT_DIR / "22_invalid_request.json").write_text(json.dumps({
                "name": "22_invalid_request",
                "request": scrub(malformed, secrets),
                "response": invalid,
            }, indent=2) + "\n")
            print(f"  22_invalid_request: ok={invalid.get('ok')}")

            capture("23_lock", {"command": "lock"})
            locked = conn.call({
                "command": "entries_search",
                "auth": auth,
                "query": "golden",
            })
            (OUT_DIR / "24_vault_locked.json").write_text(json.dumps({
                "name": "24_vault_locked",
                "request": scrub({
                    "command": "entries_search", "auth": auth,
                    "query": "golden",
                }, secrets),
                "response": locked,
            }, indent=2) + "\n")
            print(f"  24_vault_locked: ok={locked.get('ok')}")
        finally:
            daemon.terminate()
            daemon.wait(timeout=10)

    print(f"wrote {len(list(OUT_DIR.glob('*.json')))} vectors to {OUT_DIR}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
