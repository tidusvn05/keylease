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
| `--domain NAME` | | Serve `https://NAME`; see [A real address](#a-real-address). With `--tls-cert FILE --tls-key FILE` when Caddy's automatic HTTPS is off. |
| `--tunnel tailscale` | | No public address: serve `https://MACHINE.TAILNET.ts.net` to your tailnet. |
| `--listen ADDR:PORT` | `127.0.0.1:8080` | Setup stops early and suggests a free port when this one is taken. |
| `--public-url URL` | `http://localhost:PORT` | The address browsers and vaults use, when you run the proxy yourself. Running setup again keeps the last one. |
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

## A real address

The server listens on the machine only. To put it on a name with HTTPS:

```sh
keylease-server setup --domain keys.example.com
# or, during the install:
curl -fsSL https://raw.githubusercontent.com/tidusvn05/keylease/main/install.sh | sh -s -- --server --domain keys.example.com
```

Setup then:

1. checks where `keys.example.com` points: this machine, Cloudflare's proxy,
   somewhere else, or nowhere yet (it continues either way and says what to
   fix);
2. writes a site for the proxy the machine has: **Caddy** (it gets and renews
   the certificate itself) or **nginx** (with `certbot` for the certificate).
   With neither, it stops and prints how to install Caddy;
3. prints the two or three commands that enable the site and, at a terminal,
   asks before running them with sudo:

```text
Caddy will serve HTTPS. Site file: ~/.local/share/keylease-server/proxy/keylease.caddy
To enable it:
  sudo install -m 644 …/proxy/keylease.caddy /etc/caddy/keylease.caddy
  echo 'import /etc/caddy/keylease.caddy' | sudo tee -a /etc/caddy/Caddyfile >/dev/null
  sudo systemctl reload caddy
Run these now? [Y/n]
```

4. checks that `https://keys.example.com/healthz` answers.

It does not run anything when the site would not work as written. Two cases:
- The Caddyfile turns automatic HTTPS off, as with a Cloudflare origin
  certificate. Pass the files with `--tls-cert` and `--tls-key`; setup shows a
  certificate other sites on the machine already use.
- The name already has a site.

**No public address** (a Mac at home, a box behind NAT): use Tailscale. It
serves `https://MACHINE.TAILNET.ts.net` with a real certificate to your
devices on the tailnet (your laptop, your phone with the Tailscale app):

```sh
keylease-server setup --tunnel tailscale
```

**Changing the address later**:
- Passkeys belong to an address, so register them again in the console.
- Each linked vault follows with `keylease cloud set-url https://NEW`. One
  sync checks it, and nothing changes if the server there does not know the
  vault.
- If console approvals were on, turn them on again.

For a quick look without a name, tunnel the port over SSH. Passkeys work
because the browser sees `localhost`:

```sh
ssh -N -L 8080:127.0.0.1:8080 you@server     # then open http://localhost:8080/console/
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
