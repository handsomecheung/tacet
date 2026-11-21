#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

echo "Building release binaries for tacet..."
cd "${PROJECT_DIR}"
cargo build --release --bin tacet --bin tacetd

echo "tacet: ${PROJECT_DIR}/target/release/tacet"
echo "tacetd: ${PROJECT_DIR}/target/release/tacetd"
