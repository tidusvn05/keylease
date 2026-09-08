# Vault migrations

KeyLease detects vault migrations after an owner unlocks the managed vault.
Migration discovery and execution live in the Rust service; desktop is a thin
preview/confirmation surface and the CLI exposes the same contracts.

Migration identity is stable and versioned. Applied or rolled-back runs are
recorded so startup detection is idempotent. Semantic migrations never run
silently. Their preview contains item titles, current/proposed templates,
reasons, confidence, expected revisions, and a digest, but no secret values.
Apply recomputes that digest and fails if the preview is stale.

Every apply is one SQLite transaction. Before an item changes, its encrypted
envelope and revision are stored in an encrypted migration checkpoint. Existing
IDs, groups, tags, notes, fields, and agent access are preserved. Rollback is
allowed only while none of the migrated items has been edited since apply; this
prevents rollback from overwriting later user changes.

## CLI

```sh
keylease migrations status
keylease migrations preview kdbx-reclassify-v1
keylease migrations apply kdbx-reclassify-v1 \
  --preview-digest DIGEST_FROM_PREVIEW
keylease migrations rollback kdbx-reclassify-v1
```

Migration apply and rollback are restricted to the local desktop owner.

## `kdbx-reclassify-v1`

The first semantic migration examines active legacy `core.login` items and
creates only high-confidence proposals:

- Credit Card when both a card-number signal and an expiry signal are present.
- SSH Key when a private-key signal and supporting SSH/public-key evidence are
  present.
- Secure Note when the legacy login has notes but no fields or URLs.

Applying a proposal updates the template, template version, semantic roles,
and required sensitivity/protection metadata. It never reveals a protected
field or changes `agent_access`.
