# 1PUX import contract

KeyLease treats 1Password Unencrypted Export (`.1pux`) as a one-way import
adapter, never as native storage or backup. The format is a ZIP containing
`export.attributes`, `export.data`, and `files/`, as documented in
[1Password's format reference](https://support.1password.com/1pux-format/).

## Safety boundary

- The CLI refuses to read the file without `--acknowledge-plaintext` and keeps
  the source bytes in zeroizing memory.
- Import always previews first. `--commit` is a separate, explicit operation.
- The adapter rejects sources over 64 MiB, more than 10,000 archive entries,
  more than 256 MiB expanded data, attachments over 32 MiB, unsafe ZIP paths,
  and format versions newer than version 3.
- No archive entry is extracted to disk. Attachment bytes enter the encrypted
  `VaultItem` extension bag during the atomic import transaction.
- Reports never contain field values or attachment content. Users should keep
  the source out of backup/indexing systems and delete it after validation.

## Mapping

| 1PUX concept | KeyLease representation |
|---|---|
| Account and vault | Parent and child `VaultGroup` objects with deterministic IDs |
| Item UUID | Deterministic item ID scoped by source-vault UUID |
| Login fields | Typed fields in a `Login` section; passwords are highly sensitive and protected |
| Custom sections/fields | Ordered `ItemSection` and `ItemField` values |
| URLs, tags, notes, state | Native item properties |
| Password history | `onepux.password_history` encrypted extension |
| Documents/attachments | Name in `attachments`; bytes and source metadata in `onepux.attachments` encrypted extension |
| App-specific identifiers | Namespaced `onepux.*` extensions |

Unknown typed values are retained as JSON text and identified in the migration
report. That is preservation with an explicit loss-of-type warning, not silent
coercion.

The selected synthetic fixture under `test-vectors/onepux/` exercises the
documented version-3 tree, login and custom typed fields, password history, and
an attachment. Release acceptance still requires current real exports from
1Password on supported desktop platforms.
