#!/usr/bin/env bash
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

cargo fmt --all --check
cargo metadata --locked --format-version 1 --no-deps >/dev/null
cargo check --locked --all-targets --no-default-features
cargo check --locked --all-targets --no-default-features --features service-host
cargo check --locked --all-targets
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
cargo test --locked -p myc_xtask
scripts/verify-supply-chain.sh
git diff --check
