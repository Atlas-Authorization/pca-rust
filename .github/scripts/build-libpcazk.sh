#!/usr/bin/env bash
# build-libpcazk.sh <out-dir> [crate-dir]: builds the Groth16 library's C library (cargo --features capi) and copies the
# shared library plus pca_zk.h into <out-dir>. The last line printed is <out-dir>. <crate-dir> defaults to the checkout's packages/pca-zk/crate
# (in CI: $RUNNER_TEMP/mono/packages/pca-zk/crate after fetch-flagship-corpus.sh --mono). Used by CI; needs a Rust toolchain.
# Platforms: linux and macOS (x64, arm64) and windows x64 (set CARGO_BUILD_TARGET=x86_64-pc-windows-gnu for a mingw cgo link).
set -euo pipefail
OUT="${1:?output dir}"
ROOT="$(cd "$(dirname "$0")/../../../.." && pwd)"
CRATE="${2:-$ROOT/packages/pca-zk/crate}"
mkdir -p "$OUT"
# --locked once the checked-in lockfile covers every dependency (it does when it lists wasmi); before that cargo completes it.
LOCKED=--locked
grep -q '^name = "wasmi"$' "$CRATE/Cargo.lock" 2>/dev/null || LOCKED=
if [ "${PCA_STATIC:-}" = 1 ]; then # PCA_STATIC=1: a static archive (<out-dir>/libpcazk.a) for cgo/vendored packaging instead of the shared library
  ( cd "$CRATE" && cargo rustc $LOCKED --release --features capi --lib --crate-type staticlib -- --print native-static-libs >&2 )
  A="$(find "$CRATE/target" -path '*/release/libpca_zk.a' | head -1)"
  [ -n "$A" ] || { echo "libpcazk.a not built" >&2; exit 1; }
  cp "$A" "$OUT/libpcazk.a"; cp "$CRATE/include/pca_zk.h" "$OUT/"
  echo "$OUT"; exit 0
fi
( cd "$CRATE" && cargo build $LOCKED --release --features capi >&2 )
LIB="$(find "$CRATE/target" -maxdepth 4 -path '*/release/*' \( -name 'libpca_zk.so' -o -name 'libpca_zk.dylib' -o -name 'pca_zk.dll' \) | head -1)"
[ -n "$LIB" ] || { echo "libpcazk not built" >&2; exit 1; }
ext="${LIB##*.}"
case "$ext" in dll) name="pcazk.dll" ;; *) name="libpcazk.$ext" ;; esac
cp "$LIB" "$OUT/$name"
cp "$CRATE/include/pca_zk.h" "$OUT/"
echo "$OUT"
