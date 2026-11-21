#!/usr/bin/env bash
# build-libsealc.sh <seal-tag> <out-dir>: builds Microsoft SEAL's C export library (libsealc) from the pinned tag, with zlib and zstd compression
# (the serialization the reference uses), and prints nothing but the library directory on the last line. SEAL fetches its own
# dependencies (msgsl, zlib, zstd) during configure. Used by CI; needs cmake and a C++17 compiler.
set -euo pipefail
# the env var (unlike -D) also reaches the nested configures FetchContent runs for zlib and zstd (CMake 4 refuses their old minimum version)
export CMAKE_POLICY_VERSION_MINIMUM=3.5
# zlib 1.2.13 (bundled by SEAL) defines fdopen as NULL on Apple targets unless fdopen is already a macro, which breaks the current macOS SDK headers
[ "$(uname -s)" != Darwin ] || export CFLAGS="${CFLAGS:-} -Dfdopen=fdopen"
TAG="${1:?SEAL tag, e.g. v4.1.2}"; OUT="${2:?output dir}"
SRC="$OUT/seal-src"
rm -rf "$SRC"; mkdir -p "$OUT"
git clone --quiet --depth 1 --branch "$TAG" https://github.com/microsoft/SEAL "$SRC"
[ "$TAG" != v4.1.2 ] || test "$(git -C "$SRC" rev-parse HEAD)" = "119dc32e135cb89c1062076a69310d4413ebc824" # the tag is pinned by commit
cmake -S "$SRC" -B "$SRC/build" -DCMAKE_BUILD_TYPE=Release -DSEAL_BUILD_SEAL_C=ON -DSEAL_BUILD_DEPS=ON -DBUILD_SHARED_LIBS=OFF \
  -DSEAL_USE_ZLIB=ON -DSEAL_USE_ZSTD=ON -DSEAL_BUILD_EXAMPLES=OFF -DSEAL_BUILD_TESTS=OFF -DSEAL_BUILD_BENCH=OFF -DCMAKE_POLICY_VERSION_MINIMUM=3.5 >&2
# Windows: the Visual Studio generator is multi-config (--config Release) and the DLL lands in build/bin/Release (build/lib/Release for the import library)
cmake --build "$SRC/build" --target sealc --config Release -j"$(nproc 2>/dev/null || echo 2)" >&2
LIB="$(find "$SRC/build/lib" "$SRC/build/bin" \( -name 'libsealc.so*' -o -name 'libsealc*.dylib' -o -name 'sealc.dll' \) 2>/dev/null | head -1)"
[ -n "$LIB" ] || { echo "libsealc not built" >&2; exit 1; }
echo "$(dirname "$LIB")"
