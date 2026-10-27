#!/bin/sh
# The checks CI and the release run: formatting, lints, tests, dependency policy.
# PostgreSQL tests run when KEYLEASE_TEST_DATABASE_URL is set.
set -eu
cd "$(dirname "$0")/.."
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
if command -v cargo-deny >/dev/null 2>&1; then
  cargo deny check advisories bans licenses sources
else
  echo "verify: cargo-deny not installed; skipping dependency checks" >&2
fi
