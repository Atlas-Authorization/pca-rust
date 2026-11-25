#!/usr/bin/env bash
# build-wasmtime-host.sh <out-dir> [crate-dir]: builds the reference wasmtime host (cargo, release) that the sandbox subprocess hosts
# spawn, copies it into <out-dir>, and exports PCA_WASMTIME_HOST_BIN and PCA_WASMTIME_HOST_SHA256 (its hex digest, the pin) to
# $GITHUB_ENV when set. The last line printed is the binary path. <crate-dir> defaults to the checkout's packages/pca-sandbox/wasmtime-host
# (in CI: $RUNNER_TEMP/mono/packages/pca-sandbox/wasmtime-host after fetch-flagship-corpus.sh --mono). Needs a Rust toolchain.
set -euo pipefail
OUT="${1:?output dir}"
ROOT="$(cd "$(dirname "$0")/../../../.." && pwd)"
CRATE="${2:-$ROOT/packages/pca-sandbox/wasmtime-host}"
mkdir -p "$OUT"
( cd "$CRATE" && cargo build --release >&2 ) # the crate ships no lockfile (publish = false, ignored)
EXE=""; case "$(uname -s)" in MINGW*|MSYS*|CYGWIN*) EXE=".exe" ;; esac # Windows binary
BIN="$CRATE/target/release/pca-wasmtime-host$EXE"
[ -x "$BIN" ] || { echo "pca-wasmtime-host not built" >&2; exit 1; }
cp "$BIN" "$OUT/pca-wasmtime-host$EXE"
# hash the bare file name from inside the directory: GNU sha256sum prefixes the digest with a backslash when the printed path holds one
# (a Windows runner temp path does), which made the pin 65 characters and the host unpinned
if command -v sha256sum >/dev/null; then SUM="$(cd "$OUT" && sha256sum "pca-wasmtime-host$EXE" | cut -d' ' -f1)"; else SUM="$(cd "$OUT" && shasum -a 256 "pca-wasmtime-host$EXE" | cut -d' ' -f1)"; fi
SUM="${SUM#\\}" # defensively drop a leading escape backslash
case "$SUM" in *[!0-9a-f]*|"") echo "bad digest: $SUM" >&2; exit 1 ;; esac
[ "${#SUM}" -eq 64 ] || { echo "bad digest length: $SUM" >&2; exit 1; }
if [ -n "${GITHUB_ENV:-}" ]; then
  echo "PCA_WASMTIME_HOST_BIN=$OUT/pca-wasmtime-host$EXE" >> "$GITHUB_ENV"
  echo "PCA_WASMTIME_HOST_SHA256=$SUM" >> "$GITHUB_ENV"
fi
echo "sha256 $SUM" >&2
echo "$OUT/pca-wasmtime-host$EXE"
