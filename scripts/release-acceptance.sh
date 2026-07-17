#!/usr/bin/env bash
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

cargo fmt --all --check
cargo metadata --locked --format-version 1 --no-deps >/dev/null
cargo check --locked --all-targets
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
git diff --check
