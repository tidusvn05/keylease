# Agent-friendly content

KeyLease stores Prompt, Runbook, and Note as encrypted vault items with raw
Markdown bodies. They share tags, an optional project, revision history, and an
explicit agent access mode:

- `none`: only the local desktop owner can read it.
- `read`: registered local agents can search, read, and copy it.
- `read_write`: registered local agents can also update the body, title, tags,
  and project.

Creating and updating these three content types does not require a LeaseGate
grant. It still requires a registered client credential and an unlocked local
vault. The global kill switch disables this grant-free channel. Agents cannot
delete content, change its access mode, or mark it reviewed.

Agent-created content defaults to `read_write` and `unreviewed`. Content made
by the desktop owner defaults to `none` and `human_reviewed`. Any later agent
edit returns it to `unreviewed`; only the desktop owner can review it.

## CLI workflow

The normal `--agent-id` and `--client-token-file` options are omitted below for
readability.

```sh
keylease projects create leasegate --name Leasegate \
  --idempotency-key project-leasegate-v1

keylease content create --type runbook --title "Release safely" \
  --body-file ./release.md --tag release --tag ops --project leasegate \
  --idempotency-key runbook-release-v1

keylease content search "release" --type runbook --project leasegate
keylease content get kl://vault_123/item_123 --raw

keylease content update kl://vault_123/item_123 --body-file ./release-v2.md \
  --add-tag reviewed-later --if-revision 1 \
  --idempotency-key runbook-release-v2
```

The `reference` returned by search is the stable `kl://<vault-id>/<item-id>` form
accepted by `get` and `update`. `--raw` writes only the Markdown body to stdout,
which makes it suitable for shell pipelines and agent CLIs.

Access and review are owner-only operations:

```sh
keylease content access kl://vault_123/item_123 read-write --if-revision 2 \
  --idempotency-key runbook-access-v1
keylease content review kl://vault_123/item_123 --if-revision 3 \
  --idempotency-key runbook-review-v1
```

## Templates and imported items

`keylease templates list` exposes the built-in schemas used by the desktop and
importers. The registry includes the common password-manager categories plus
Prompt, Runbook, Note, and Generic Item. The 1PUX importer maps numeric category
IDs to these canonical kinds. KDBX entries use their explicit KeyLease kind
when present and otherwise apply conservative login, credit-card, SSH-key, and
secure-note inference.

Unknown source fields are preserved as protected opaque JSON instead of being
dropped or guessed as safe. The desktop reads the field-oriented `entries_view`
contract, so imported card numbers, expiry dates, addresses, license fields,
and other typed values are displayed even when they are not legacy login
fields.
