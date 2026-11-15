# Releasing KeyLease

One tag `vX.Y.Z` on `main` produces everything a release ships:

| Output | For | Made by |
|---|---|---|
| **GitHub release**: release notes | people following releases | `Release` workflow, job `release` |
| **Binaries** `keylease-X.Y.Z-<target>.tar.gz` (+ `.sha256`, `SHA256SUMS`): `keylease` and `keylease-server` with the console inside, for x86_64/aarch64 Linux (glibc 2.35+) and macOS | `install.sh` ([server-quick-install.md](server-quick-install.md)) | jobs `binaries` (`.github/workflows/binaries.yml`, also run on pull requests that touch it) and `attach` |
| **crates.io**: `keylease` and the libraries it needs, at `X.Y.Z` | `cargo install --locked keylease`, and Rust code that embeds the vault | job `crates`, `scripts/release.py publish` with a short-lived Trusted Publishing token |
| **Container images** `ghcr.io/tidusvn05/keylease-server:X.Y.Z` and `ghcr.io/tidusvn05/keylease-edge:X.Y.Z` (and `latest`) | the single-VPS KeyLease Cloud + Edge deployment ([self-hosted-vps.md](self-hosted-vps.md)) | job `image`, from `deploy/compose/Dockerfile.server` and `Dockerfile.edge` |

Most users install the binaries with `install.sh`; `cargo install --locked keylease` builds from crates.io. GitHub
attaches the source archives of the tag to the release. A pre-release tag `vX.Y.Z-rc.N` makes
only a GitHub pre-release with its binaries: no crates, no images.

What is **not** released here: the macOS app (built from source
with `scripts/package-macos-swift.sh`, see [below](#the-macos-app)), the Android app, the
approval web app (its image bakes in a Cloud URL, so each deployment builds it). Releases
v0.2.0 and v0.2.1 attached Linux and macOS archives and a DMG; 0.3.0 attached none; from
0.4.0 the binaries above are attached again.

## Versioning

- One version for the whole workspace (`[workspace.package] version`), SemVer. While KeyLease is
  `0.x`, a minor bump may change the vault format's migrations, the RPC contract or the CLI; a
  patch bump does not.
- The version changes only when a release is prepared. After the release, `main` stays at the
  released version until the next release is prepared; there is no `-dev` version.
- Commits use [Conventional Commits](https://www.conventionalcommits.org/) (`feat:`, `fix:`,
  `docs:`, …). git-cliff turns them into `CHANGELOG.md` and the release notes (`cliff.toml`).
- Published crates, in order (`scripts/release.py order`): `keylease-core`, `keylease-1pux`,
  `keylease-crypto`, `keylease-kdbx`, `keylease-connectors`, `keylease-policy`,
  `keylease-store`, `keylease-service`, `keylease-rpc`, `keylease` (the binary, in
  `crates/keylease-cli`). Every other crate has `publish = false` (inherited from the workspace).
- `keylease-connectors` and `keylease-policy` replaced `leasegate-connectors` and
  `leasegate-policy` after v0.2.1. The new names must go through the first-publish steps below
  once; the old crates stay on crates.io at their last version.

## Publishing without stored tokens

KeyLease publishes with crates.io **Trusted Publishing**. Every crate trusts exactly the
repository `tidusvn05/keylease`, the workflow `release.yml` and the GitHub environment
`crates-io`. The `crates` job asks crates.io for a token through
`rust-lang/crates-io-auth-action` (`permissions: id-token: write`); the token lives 30 minutes
and is revoked when the job ends. No crates.io token is stored in GitHub or in this repository.

Trusted Publishing cannot create a crate, so the first version of each crate is published by
hand. `scripts/release.py pending` lists the crates not yet on crates.io, checks that their
names (with `-` and `_` treated alike) are free, and that existing crates are owned by
`tidusvn05`. The workflow stops at the first crate that is new (see [A new crate](#a-new-crate)).

### First release (bootstrap, once)

1. On crates.io (Account settings → API tokens), create a token with the scopes
   `publish-new`, `publish-update` and `trusted-publishing`, limited to `keylease` and
   `keylease-*` (and, for old releases, `leasegate-*`), expiring in a day.
2. Merge the release pull request. From a clean checkout of the merged `main`, before pushing
   the tag:
   ```sh
   cargo login                                   # paste the token at the prompt, not in a chat
   scripts/release.py publish                    # 10 new crates; crates.io allows about one new
                                                 # crate every 10 minutes after a short burst
   scripts/release.py trustpub tidusvn05/keylease --only
   cargo logout
   ```
   `trustpub` makes each crate trust the repository, `release.yml` and `crates-io`; `--only`
   makes crates.io refuse any other way of publishing them.
3. Delete the token on crates.io. In GitHub, create the environment **`crates-io`** (Settings →
   Environments); you may add yourself as a required reviewer.
4. Push the tag. The `crates` job finds every crate published and skips them.

### A new crate

When a release adds a crate (or makes one publishable), the `crates` job publishes the crates
before it in order, then stops at the new crate and names it. Its dependencies are then on
crates.io, so publish it by hand with a token that has `publish-new`, `publish-update` and
`trusted-publishing`, limited to the new crate's name:

```sh
cargo login
scripts/release.py publish --crates <crate>       # only that crate; the others stay with CI
scripts/release.py trustpub tidusvn05/keylease --crates <crate> --only
cargo logout
```

Then delete the token and re-run the failed job (`gh run rerun <run id> --failed`). It skips
what is published and carries on; with two new crates it stops again at the second.
Check the name first: crate names are permanent.

Do not run a plain `scripts/release.py publish` here: the existing crates accept only Trusted
Publishing (`--only`), so crates.io refuses them with `403 Forbidden`.

## Steps

1. **Prepare** on a branch `release/vX.Y.Z`:
   ```sh
   scripts/release.py version X.Y.Z             # workspace + internal dependencies + Cargo.lock
   git cliff --tag vX.Y.Z -o CHANGELOG.md
   scripts/verify.sh                            # fmt, clippy, tests, cargo deny
   scripts/release.py publish --dry-run         # --allow-dirty while the changes are uncommitted
   scripts/release.py pending
   ```
   Fix dependency advisories and yanked dependencies first. Open a pull request titled
   `chore(release): vX.Y.Z` and squash-merge it when CI is green.
2. **Tag** the merged commit:
   ```sh
   git switch main && git pull
   git tag -a vX.Y.Z -m "KeyLease vX.Y.Z" && git push origin vX.Y.Z
   ```
3. **Watch** the `Release` workflow. `check` confirms the tag format, that the commit is on
   `main`, the version and the changelog, runs `scripts/verify.sh` and packages every crate;
   then come the GitHub release, crates.io and the images.
4. **Verify**: `cargo install --locked keylease --version X.Y.Z` and `keylease --version`; and
   `docker run --rm ghcr.io/tidusvn05/keylease-edge:X.Y.Z --help`.

## The macOS app

Releases do not ship the app. Whoever needs it builds it on a Mac (Xcode 16+, Rust):
`scripts/package-macos-swift.sh --install`, or `--dmg` for a DMG. `KeyLease.app` embeds the
`keylease` helper built from the same checkout, so build the app from the tag of the
`keylease` you run elsewhere. `scripts/package-macos-swift.sh` takes the version from `[workspace.package]`
(`CFBundleShortVersionString`, without a pre-release suffix) and the commit count
(`CFBundleVersion`), so `scripts/release.py version` is the only place a version is set.
`macos.yml` runs on pull requests that touch the app or its packaging (and on demand), runs
the Swift tests and keeps an ad-hoc signed DMG as a workflow artifact for 14 days, to try a
change on a Mac.

Without an Apple certificate the app is **signed ad-hoc** (`EXPANDED_CODE_SIGN_IDENTITY=-`),
not with an Apple Developer ID, and not notarized. Consequences when the app is copied to
another Mac:

- Gatekeeper blocks the first launch of a downloaded copy. The user allows it in System
  Settings → Privacy & Security → **Open Anyway**, or removes the quarantine flag with
  `xattr -dr com.apple.quarantine /Applications/KeyLease.app`.
- macOS identifies an ad-hoc app by its code hash, which changes with every build. After an
  update, macOS may ask again for Keychain access and for permissions such as Screen Recording
  (TOTP QR scan), and the Login Item may need to be allowed again.
- macOS cannot tell who built the app.

Shipping the app in releases again would need the DMG job back in `release.yml` and, to avoid
the Gatekeeper prompt, a "Developer ID Application" certificate and an App Store Connect API key
as secrets in a protected environment, `codesign` with that identity and a timestamp, then
`xcrun notarytool submit --wait` and `xcrun stapler staple` on the DMG.

## When something fails

- **Before the tag:** fix it on `main` (or the release branch) and start over.
- **check or GitHub release:** fix the cause and re-run the failed jobs. If the fix needs
  a new commit, the tag is not moved: release `X.Y.Z+1` instead. `workflow_dispatch` with an
  existing tag rebuilds into a draft release.
- **Images:** re-run the `image` job.
- **crates.io, partly published:** re-run the `crates` job (or `scripts/release.py publish`
  locally). Versions already published are skipped. If crates.io refuses the token, check the
  crate's Trusted Publishing settings: repository, workflow `release.yml` and environment
  `crates-io` must match.
- **Never** move a published tag or replace its assets, and never reuse a version.

## Yanking and fixes

crates.io versions cannot be deleted or reused. A broken version is yanked for each affected
crate with `cargo yank --version X.Y.Z <crate>`, then a patch release `X.Y.Z+1` follows the
steps above. `scripts/release.py` refuses to publish a version that is yanked. Mark the broken
GitHub release in its notes rather than deleting it.
