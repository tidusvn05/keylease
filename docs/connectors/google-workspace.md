# Google Workspace local connector

One local `google_workspace` connection owns a shared OAuth lifecycle and an
explicit registry of file IDs selected by the user. The credential contract
rejects missing or additional scopes and requires only `drive.file`. The
desktop and CLI setup flow opens Google's system-browser desktop Picker. Rust
binds a random IPv4 loopback callback, uses S256 PKCE and a per-flow state
value, and requires `prompt=consent`, `trigger_onepick=true`, exact returned
scope, an authorization code, and 1–25 selected IDs. Each selection is resolved
through fixed-origin Drive metadata into a canonical resource before the
credential is encrypted. Pending flows expire after ten minutes and are also
cleared on lock. LeaseGate never implements full-Drive search.

Canonical resources are `google:file/<file-id>`,
`google:document/<file-id>`, and `google:spreadsheet/<file-id>`. Sheet actions
also require a numeric stable `sheet_id` and a concrete bounded A1 range in the
typed arguments. Policy should constrain both with JSON pointers such as
`/sheet_id` and `/range`. A tab name alone is never an authorization resource.
Before a range request, the connector fetches sheet properties and verifies
that each explicitly named A1 sheet title resolves to the supplied stable
numeric `sheet_id`.

Writes accept only `value_input_option=RAW`; absent values are canonicalized to
`RAW`, while `USER_ENTERED` is rejected. Updates require
`expected_values_hash`; the connector reads the range immediately before the
write and fails when the digest changes. This reduces accidental overwrites but
is not presented as a transactional compare-and-set boundary.

Create actions target an exact enrolled `google:folder/<folder-id>` resource and
use Drive `files.create` with a fixed Google Doc or Google Sheet MIME type and
that folder as parent. After a successful response, LeaseGate validates and
enrolls the returned stable document/spreadsheet ID; subsequent actions require
that exact ID.

The action catalog intentionally has no formula write, sharing, permission,
clear, delete, structural `batchUpdate`, external-data-source or ownership
operation. Returned provider content is marked `untrusted_content`; audit stores
IDs, revisions and counts but not document text or cell values.

The secure connection input accepts an OAuth credential object through stdin;
the whole object is encrypted as a concealed vault field:

```json
{
  "credential": {
    "access_token": "...",
    "refresh_token": "...",
    "client_id": "...apps.googleusercontent.com",
    "client_secret": null,
    "expires_at": null,
    "scopes": ["https://www.googleapis.com/auth/drive.file"]
  },
  "authorized_resources": [
    "google:document/FILE_ID",
    "google:spreadsheet/SPREADSHEET_ID"
  ]
}
```

The credential object is serialized only inside the encrypted vault item and is
never returned by `connection list`, audit, or gate responses. The connector
uses only `access_token` for downstream authorization and rotates the encrypted
object after a successful refresh. Google desktop clients may omit
`client_secret`.

After granting `connection:add`, begin and complete the interactive flow with:

```sh
keylease connection google-oauth-begin --input-json -
keylease connection google-oauth-complete google_oauth_FLOW_ID
```

The macOS app exposes the same flow and only asks macOS to open an HTTPS
URL whose host is exactly `accounts.google.com`; OAuth codes, PKCE material,
tokens, and selected-ID validation remain in Rust. Real credentials and live
proof that unselected files remain inaccessible are release acceptance checks.
