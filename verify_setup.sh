#!/bin/bash
set -e

echo "=== Verifying Mycelium Workspace Setup ==="
echo ""

echo "✓ Checking workspace structure..."
test -f Cargo.toml
test -f rust-toolchain.toml
test -f deny.toml
test -d .cargo
test -d .github/workflows
test -d supply-chain

echo "✓ Checking crate directories..."
test -d crates/myc-crypto
test -d crates/myc-core
test -d crates/myc-github
test -d crates/myc-cli
test -d crates/myc-test-utils

echo "✓ Building workspace..."
cargo build --workspace --quiet

echo "✓ Running tests..."
cargo test --workspace --quiet

echo "✓ Checking formatting..."
cargo fmt --check

echo "✓ Running clippy..."
cargo clippy --workspace --all-targets --all-features --quiet -- -D warnings

echo ""
echo "=== All checks passed! ==="
echo "Workspace is ready for development."
