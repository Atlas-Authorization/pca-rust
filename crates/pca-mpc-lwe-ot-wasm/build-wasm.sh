#!/usr/bin/env bash
# Path-free, reproducible-input wasm build. Usage: bash build-wasm.sh   (run from anywhere)
# Every host path (crate dir, repo root, $HOME, CARGO_HOME registry, rustc sysroot) is remapped so that panic /
# location strings embedded in the .wasm never carry a developer or CI home directory. The dependency set is
# pinned by Cargo.lock (--locked). Output: ../wasm/pca_mpc_lwe_ot_wasm.wasm
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
cd "$here"
ch="${CARGO_HOME:-$HOME/.cargo}"
# rustc applies the LAST matching --remap-path-prefix, so list broad prefixes first and specific ones last.
flags="-Cdebuginfo=0 -Cstrip=symbols --remap-path-prefix=$HOME=/home --remap-path-prefix=$ch=/cargo"
flags="$flags --remap-path-prefix=$(rustc --print sysroot)=/rustc-sysroot"
top="$(git rev-parse --show-toplevel 2>/dev/null || true)"
[ -n "$top" ] && flags="$flags --remap-path-prefix=$top=/src"
for d in "$ch"/registry/src/*/; do flags="$flags --remap-path-prefix=${d%/}=/cargo-registry"; done
for d in "$ch"/git/checkouts/*/; do [ -d "$d" ] && flags="$flags --remap-path-prefix=${d%/}=/cargo-git"; done
flags="$flags --remap-path-prefix=$here=/crate"
RUSTFLAGS="$flags" cargo build --locked --release --target wasm32-unknown-unknown
cp target/wasm32-unknown-unknown/release/pca_mpc_lwe_ot_wasm.wasm ../wasm/pca_mpc_lwe_ot_wasm.wasm
if grep -a -q -E '/(Users|home)/[A-Za-z0-9_.-]+/' ../wasm/pca_mpc_lwe_ot_wasm.wasm; then
  echo "ERROR: host path still embedded in wasm" >&2; exit 1
fi
