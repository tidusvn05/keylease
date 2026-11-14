# Moving items between a Mac and a VPS without a server

A **bundle** carries items (or a whole project) from one KeyLease node to
another by copy and paste. It is an [age](https://age-encryption.org)-encrypted
file, readable only by the receiving node, and signed by the sending node.

## Once per node

On the VPS (the receiving node):

```sh
keylease node init
# {"node_id": "age1qyq…", "fingerprint": "3f2a:9c1d:…", …}
```

The node ID is a public age recipient; it is safe to copy anywhere. Run the
same command on the Mac to see its fingerprint; you compare it on the first
import.

## Export and import

On the Mac:

```sh
keylease export --to age1qyq… --project shop --name mac > shop.bundle
keylease export --to age1qyq… --item-id item_… --item-id item_…   # single items
```

Copy the text to the VPS (paste it into an SSH session, or `scp` the file) and
import it:

```sh
keylease import shop.bundle --preview              # what it contains, who sent it
keylease import shop.bundle --trust-sender 3f2a:9c1d:…   # first time only
keylease import shop.bundle                         # later bundles from the same Mac
```

Pasting works too: run `keylease import` in a terminal and paste; it reads
until the `-----END AGE ENCRYPTED FILE-----` line, then asks for the master
password. (Piping a file into it does not work, because the password prompt
needs the terminal; pass the file name instead.)

- **First import from a node:** the import stops and prints the sender's
  fingerprint. Compare it with `keylease node init` on the sending node, then
  pass it with `--trust-sender`. Later bundles from that node import without it;
  a bundle signed by another key is refused until you confirm that one too.
- **Read-only by default:** imported items cannot be edited on the VPS
  ("change it there and export it again"). Exporting again and importing
  updates them in place; unchanged items are skipped. `--editable` stores
  independent copies instead.
- **What travels:** a project export sends the project (with its environments)
  and its active items, but never Personal items; an item selected by ID is
  sent even if it is personal. Items are filed in groups of the same name.
- **The other direction** works the same way: `keylease node init` on the Mac,
  `keylease export --to <mac node id> --item-id …` on the VPS (for example a
  secret made with `entries generate-secret`).

A bundle is a standard age file holding JSON (`keylease-bundle/v1`): with the
node's age identity, `age -d -i identity.txt shop.bundle` decrypts it. Treat a
decrypted bundle like any plaintext secret.

The bundle format is the one a KeyLease server will use for syncing private
projects, so moving to a server later changes nothing about the items.

## Importing `.env` files and CSV exports

Both are plaintext secrets on disk; delete the file after importing.

```sh
keylease vault import-env .env.production --project shop --environment production \
  --acknowledge-plaintext
keylease vault import-csv passwords.csv --acknowledge-plaintext
```

- `import-env` stores one env file (`core.environment`) in the project. Every
  value is kept as a protected secret; `keylease run --project shop
  --environment production -- CMD` then sets them all
  ([details](run-with-secrets.md)). It understands `export`, comments, and
  single and double quotes (including multi-line values).
- `import-csv` reads logins from browser and password-manager exports
  (columns such as `name`/`title`, `url`, `username`, `password`, `notes`,
  `totp`) into the Personal area, where agents never see them.
