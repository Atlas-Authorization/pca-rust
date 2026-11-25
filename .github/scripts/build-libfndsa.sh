#!/usr/bin/env bash
# build-libfndsa.sh <out-dir> [crate-dir]: builds the FN-DSA core's C library (cargo --features capi) and copies the
# shared library plus pca_fndsa.h into <out-dir>. The last line printed is <out-dir>. <crate-dir> defaults to the checkout's packages/pca-fndsa-wasm/crate
# (in CI: $RUNNER_TEMP/mono/packages/pca-fndsa-wasm/crate after fetch-flagship-corpus.sh --mono). Used by CI; needs a Rust toolchain.
set -euo pipefail
OUT="${1:?output dir}"
ROOT="$(cd "$(dirname "$0")/../../../.." && pwd)"
CRATE="${2:-$ROOT/packages/pca-fndsa-wasm/crate}"
mkdir -p "$OUT"
if [ "${PCA_STATIC:-}" = 1 ]; then # PCA_STATIC=1: a static archive (<out-dir>/libfndsa.a) for cgo/vendored packaging instead of the shared library
  ( cd "$CRATE" && cargo rustc --locked --release --features capi --lib --crate-type staticlib -- --print native-static-libs >&2 )
  A="$(find "$CRATE/target" -path '*/release/libpca_fndsa_wasm.a' | head -1)"
  [ -n "$A" ] || { echo "libfndsa.a not built" >&2; exit 1; }
  cp "$A" "$OUT/libfndsa.a"; cp "$CRATE/include/pca_fndsa.h" "$OUT/"
  echo "$OUT"; exit 0
fi
( cd "$CRATE" && cargo build --locked --release --features capi >&2 )
LIB="$(find "$CRATE/target/release" -maxdepth 1 \( -name 'libpca_fndsa_wasm.so' -o -name 'libpca_fndsa_wasm.dylib' -o -name 'pca_fndsa_wasm.dll' \) | head -1)"
[ -n "$LIB" ] || { echo "libfndsa not built" >&2; exit 1; }
ext="${LIB##*.}"
case "$ext" in dll) name="fndsa.dll" ;; *) name="libfndsa.$ext" ;; esac
cp "$LIB" "$OUT/$name"
cp "$CRATE/include/pca_fndsa.h" "$OUT/"
echo "$OUT"
