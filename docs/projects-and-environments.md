# Projects, environments and the Personal area

A vault holds two kinds of things:

- **Projects** (`shop`, `blog`, …): the credentials agents work with. Each
  project has **environments** such as dev, staging and production.
- **Personal** items: your own logins, cards and notes. Agents never see them.

## Environments

New projects start with `dev`, `staging` and `production`; `production` is
**protected**. Manage them with the master password:

```sh
keylease projects env list shop
keylease projects env set shop qa --name "QA"            # add or rename
keylease projects env set shop staging --protected        # protect an environment
keylease projects env remove shop qa                      # only when no item uses it
```

An item in a project that defines environments must use one of them:

```sh
keylease entries create --title "Stripe" --group-id G --kind core.api_credential \
  --project shop --environment production --idempotency-key stripe-prod
```

The value is stored as the slug (`production`). Projects created before
environments existed define none; their items keep any free-text environment.

**Protected environments raise the risk tier.** SSH signing, SSH certificates
and database connections to an item in a protected environment are R3 instead
of R2, so a time-boxed trust lasts at most one hour. Moving an item into or out
of a protected environment counts as a protected change
(`entry:update_protected_fields`), so a trust for ordinary edits cannot lower a
production item's tier. Without configured environments, names starting with
`prod` are protected, as before.

Env files (`core.environment` items) take their environment from their
"Environment" metadata field when it names one of the project's environments.

## Named references

Agents can refer to a field by name instead of by ID:

```text
kl://PROJECT[/ENVIRONMENT]/ITEM#FIELD
kl://shop/production/Stripe#password
```

`ITEM` is the item's title (case-insensitive); `FIELD` is a field key, a field
label, or an `.env` variable name. The environment can be left out when only
one item has that title. Use them with `keylease run --env NAME=…` and the MCP
`run_with_secrets` tool. Each use still goes through policy and approval like
an ID reference.

`keylease run --project shop --environment production -- COMMAND` sets every
variable of the project's env files in that environment
([details](run-with-secrets.md)).

## The Personal area

Personal items do not exist for agents: searches skip them, and every command
on one (metadata, reveal, `run`, SSH, database) fails as not found before any
policy rule is consulted, so no grant or trust can reach them. Only the vault
owner (the desktop app or the master password) can see them, and only the
owner can move an item into or out of the area:

```sh
keylease entries create … --personal
echo '{"personal": false}' | keylease entries update ITEM --if-revision N \
  --idempotency-key unhide-1 --patch-json -
```

Items imported from 1PUX start in the Personal area. KDBX imports do too,
unless the file was exported by KeyLease, in which case the flag is restored
as it was. Existing items are not changed.
