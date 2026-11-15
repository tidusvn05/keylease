# Install keylease-server

One command on Linux or macOS. No root, no Docker, no Rust.

```sh
curl -fsSL https://raw.githubusercontent.com/tidusvn05/keylease/main/install.sh | sh -s -- --server
```

You need PostgreSQL's programs installed, not a running database: the server
runs its own private one. If they are missing, the installer stops before
downloading anything and prints the command for your system:

| System | Command |
|---|---|
| Debian, Ubuntu | `sudo apt install postgresql` |
| Fedora, RHEL | `sudo dnf install postgresql-server` |
| Arch | `sudo pacman -S postgresql` |
| macOS | `brew install postgresql@17` |

The installer puts `keylease` and `keylease-server` in `~/.local/bin` (after
checking the download's SHA-256), then runs `keylease-server setup`, which
starts the server as a service and prints what to do next:

```text
KeyLease server is set up in ~/.local/share/keylease-server
  Running:     keylease-server.service (systemctl --user status keylease-server)
  Console:     http://localhost:8080/console/
  Admin token: ~/.local/share/keylease-server/secrets/admin_token
  Database:    private PostgreSQL in ~/.local/share/keylease-server/pg (Unix socket only)
```

Then make your vault the owner and sign in to the console:

```sh
keylease vault init        # once, if you have no vault yet
keylease cloud init --url http://localhost:8080 --admin-token-file ~/.local/share/keylease-server/secrets/admin_token
keylease cloud console     # prints a one-time sign-in link
```

## Day to day

```sh
keylease-server status       # running or not, the console address, the admin token file
keylease-server uninstall    # stop and remove the service; your data stays
```

Upgrade by running the install command again: the binaries are replaced,
setup keeps the secrets and the database, the service restarts and the
database is migrated.

Logs: `journalctl --user -u keylease-server -f` on Linux,
`~/.local/share/keylease-server/server.log` on macOS.

A Linux user service stops at logout unless lingering is on. Setup tells you
when it is off; turn it on with `sudo loginctl enable-linger $USER`.

## Options

Pass them after `--server`, or to `keylease-server setup` directly:

| Option | Default | |
|---|---|---|
| `--listen ADDR:PORT` | `127.0.0.1:8080` | Setup stops early and suggests a free port when this one is taken. |
| `--public-url URL` | `http://localhost:PORT` | The address browsers and vaults use. Set it when a reverse proxy serves a real name. |
| `--database-url-file FILE` | a private cluster | Use a PostgreSQL you already run (a file holding its URL). |
| `--dir DIR` | `~/.local/share/keylease-server` | Where the secrets, database and settings live. |
| `--no-service` | | Only prepare; start it yourself with `keylease-server`. |

The installer also takes `--version X.Y.Z` and `--bin-dir DIR`.

## What setup does

- Generates the admin token, control signing key and KMS root key (mode 0600)
  in `secrets/`. Running setup again keeps them. **Back up
  `secrets/kms_root_key` somewhere else**: Managed secrets cannot be decrypted
  without it.
- Creates a private PostgreSQL cluster in `pg/` that listens only on a Unix
  socket inside that mode-0700 directory: no network port, nothing for other
  users to reach.
- Writes `server.env`. A bare `keylease-server` reads it, starts the private
  PostgreSQL if it is down, migrates and serves.
- Installs the service: a systemd user unit on Linux (a system unit when run
  as root, which needs `--database-url-file`), a launchd agent on macOS. It
  will not replace a service that belongs to another install directory.

## Reaching it from another computer

It listens on the machine only. For a quick look, tunnel it:

```sh
ssh -N -L 8080:127.0.0.1:8080 you@server     # then open http://localhost:8080/console/
```

Passkeys work through the tunnel because the browser sees `localhost`. For a
real name, put a TLS reverse proxy in front and run setup again with
`--public-url https://keys.example.com` (passkeys registered on `localhost`
need registering again):

```text
keys.example.com {
    reverse_proxy 127.0.0.1:8080
}
```

## From source

For unreleased changes, or when no binary fits your platform (releases before
0.4.0, musl systems, glibc older than 2.35):

```sh
git clone https://github.com/tidusvn05/keylease.git && cd keylease
scripts/install-server.sh            # needs Rust and Node.js; options for setup go after --
```

For the full Docker stack with backups, upgrades and the edge node, see
[self-hosted-vps.md](self-hosted-vps.md).
