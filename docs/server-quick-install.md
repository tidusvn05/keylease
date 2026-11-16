# Install keylease-server

One command on Linux or macOS. No root, no Docker, no Rust.

```sh
curl -fsSL https://raw.githubusercontent.com/tidusvn05/keylease/main/install.sh | sh -s -- --server
```

Run it in a terminal on the server. It walks you through the rest:

1. **PostgreSQL's programs** (not a running database: the server runs its own
   private one). When they are missing, it offers to install them
   (`sudo apt install postgresql`, `dnf`, `pacman` or `brew`).
2. **Where your devices will reach the server**:
   - **A domain name with HTTPS.** It shows the DNS record to add, then
     checks it again until it resolves.
   - **Tailscale**, for a machine with no public address.
   - **Only this machine**, reached over an SSH tunnel.
3. **For a domain, the web server.** It finds Caddy or nginx; with neither,
   it offers to install Caddy. When Caddy has automatic HTTPS turned off, it
   lets you pick a certificate another site on the machine already uses.
   It then shows the commands that enable the site and runs them after a
   yes (they use sudo).
4. **Linking your laptop.** It prints one command with a one-time **setup
   code** in it. Run it on the laptop:

```sh
curl -fsSL https://raw.githubusercontent.com/tidusvn05/keylease/main/install.sh | sh -s -- --link https://keys.example.com KLS-XXXX-XXXX-XXXX-XXXX
```

   It installs `keylease`, creates your vault if you have none (it asks for a
   master password), links the vault as the server's owner, prints the
   recovery kit once and a console sign-in link. With `keylease` already
   installed: `keylease cloud init --url https://keys.example.com --code KLS-…`.

A setup code works once, for 30 minutes, and only to link a vault as an
owner; `keylease-server owner-code` on the server makes a new one. The admin
token never has to leave the server.

Running setup again (to upgrade) keeps the address, the domain and the
certificate choice, and skips a web server site that is already enabled.

Every answer is also an option (`--domain`, `--tunnel`, `--tls-cert`…, see
below), so scripts and CI run setup without questions; with no terminal it
asks nothing and keeps `http://localhost:8080`.

The installer puts `keylease` and `keylease-server` in `~/.local/bin` (after
checking the download's SHA-256). Without a terminal, it stops when
PostgreSQL's programs are missing and prints the command for your system:

| System | Command |
|---|---|
| Debian, Ubuntu | `sudo apt install postgresql` |
| Fedora, RHEL | `sudo dnf install postgresql-server` |
| Arch | `sudo pacman -S postgresql` |
| macOS | `brew install postgresql@17` |

## Day to day

```sh
keylease-server status       # running or not, the console address, the admin token file
keylease-server owner-code   # a new one-time setup code for `keylease cloud init`
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
