# PostgreSQL without handing the password to an agent

Step 3 of [ADR 0005](adr/0005-agent-trust-and-secret-use.md).
`keylease db` runs a local PostgreSQL proxy in the agent's process. Clients
connect to a private Unix socket; the proxy connects to the real server and,
when the server asks for SCRAM-SHA-256, sends the challenge to the KeyLease
service. The service computes the client proof from the stored password and
returns only the proof. The password never reaches the proxy, the client, the
agent or the model.

## Store the database

Create a **Database** item (`core.database`) with `engine` = `postgresql`,
`host`, `port` (default 5432), `database` (default `postgres`), `username` and
`password`. Set the item's environment to `production` for production
databases: their connections are risk R3, so trust is capped at one hour
(otherwise R2, up to one day).

The server must use `scram-sha-256` authentication (the PostgreSQL default
since 14). `md5` and `password` methods would require revealing the password,
so the proxy refuses them.

## Use it

```sh
keylease db psql ITEM_ID -- -c 'select count(*) from orders'
keylease db exec ITEM_ID -- pg_dump --schema-only
keylease db exec ITEM_ID -- npm run migrate      # reads DATABASE_URL
```

`db psql` and `db exec` start a private, single-use proxy socket and set
`PGHOST`, `PGPORT`, `PGUSER`, `PGDATABASE` and a password-free `DATABASE_URL`
for the child; `PGPASSWORD` is removed. For a long-lived proxy:

```sh
keylease db proxy ITEM_ID --socket-dir ~/.keylease/run/db
# prints PGHOST=… PGPORT=… PGUSER=… PGDATABASE=…
```

The proxy always connects as the item's role; a client cannot choose another
user. It may choose another database on the same server (`psql -d other`),
which is part of what is approved.

## TLS

The proxy asks the server for TLS and verifies its certificate against the
public web roots plus `--tls-ca FILE` when given. A server that does not offer
TLS is accepted only on a loopback address, or with `--insecure-plaintext`.
The local socket between the client and the proxy is a mode-0600 Unix socket
in a mode-0700 directory, with the peer UID checked.

## Approval

Each connection is `db:connect` on the item, with the database and role as
arguments (never the SCRAM nonces, so retries find the same approval). The
client waits while you approve (120 s by default, `--wait-approval` to change
it). Approve once for one connection, or `--trust 30m|1h|6h|1d` (`1h` for
production) to cover the item — any database on that server, as that role —
for a window. Every connection under a trust is audited with its `trust_id`.

## Limits

- Query results reach the agent and the model. Give agents a read-only role
  where that is enough; the role, not KeyLease, limits what SQL can do.
- The proxy sees the SCRAM exchange. Like a network observer of an
  unencrypted handshake, it could try to guess a weak password offline from
  it. Use a generated password.
- PostgreSQL only; channel binding (`SCRAM-SHA-256-PLUS`) is not used.
