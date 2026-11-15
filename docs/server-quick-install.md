# Install keylease-server on one machine

For trying the server, a team on one machine, or a VPS where you do not want
Docker. Two commands from a checkout; no root needed.

```sh
git clone https://github.com/tidusvn05/keylease.git && cd keylease
scripts/install-server.sh --with-cli
```

The script builds the KeyLease Console and `keylease-server` (and, with
`--with-cli`, the `keylease` CLI) into `~/.local/bin`, then runs
`keylease-server setup`. Setup needs PostgreSQL's programs installed
(`apt install postgresql`, `brew install postgresql@17`), not a running
database. It prints where everything is and what to run next:

```text
KeyLease server is set up in ~/.local/share/keylease-server
  Running:     keylease-server.service (systemctl --user status keylease-server)
  Console:     http://localhost:8080/console/
  Admin token: ~/.local/share/keylease-server/secrets/admin_token
  Database:    private PostgreSQL in ~/.local/share/keylease-server/pg (Unix socket only)
```

Then link your vault as the owner and open the console:

```sh
keylease cloud init --url http://localhost:8080 --admin-token-file ~/.local/share/keylease-server/secrets/admin_token
keylease cloud console
```

## What setup does

- Generates the admin token, control signing key and KMS root key, mode 0600,
  in `secrets/`. They are kept when setup runs again. **Back up
  `secrets/kms_root_key` elsewhere**: Managed secrets cannot be decrypted
  without it.
- Creates a private PostgreSQL cluster in `pg/` that listens only on a Unix
  socket inside that mode-0700 directory, and a `keylease` database. With
  `--database-url-file FILE` it uses your database instead.
- Writes `server.env`. A bare `keylease-server` reads it, starts the private
  PostgreSQL if it is down, runs the migrations and serves.
- On Linux with systemd, installs and starts `keylease-server.service` (a user
  service; a system service when run as root with `--database-url-file`).
  Elsewhere it prints the command to run.

Options: `--listen ADDR:PORT` (default `127.0.0.1:8080`), `--public-url URL`
(the address browsers and vaults use; default `http://localhost:PORT`),
`--dir DIR`, `--database-url-file FILE`, `--no-service`.

## Reaching it from another computer

It listens on the machine only. For a quick look, tunnel it:

```sh
ssh -N -L 8080:127.0.0.1:8080 you@server     # then open http://localhost:8080/console/
```

Passkeys work through the tunnel because the browser sees `localhost`. For a
real name, put a TLS reverse proxy in front and run setup again with
`--public-url https://keys.example.com` (passkeys registered on `localhost`
then need registering again):

```text
keys.example.com {
    reverse_proxy 127.0.0.1:8080
}
```

## Operate

```sh
systemctl --user status keylease-server      # state; journalctl --user -u keylease-server -f for logs
systemctl --user restart keylease-server     # after upgrading: scripts/install-server.sh again does this
systemctl --user disable --now keylease-server   # stop it; data stays in ~/.local/share/keylease-server
```

A user service stops at logout unless lingering is on
(`sudo loginctl enable-linger $USER`); setup says so when it is off.

For the full Docker stack with backups, upgrades and the edge node, see
[self-hosted-vps.md](self-hosted-vps.md).
