#!/usr/bin/env bash
# fetch-seal-vendor.sh <dest>: lays out <dest> (the crate's seal-src/) with Microsoft SEAL 4.1.2 and the three dependencies its own
# cmake (cmake/ExternalZLIB.cmake, ExternalZSTD.cmake, ExternalMSGSL.cmake at v4.1.2) pins, as plain source trees, so the
# `fhe-seal-vendored` feature builds libsealc offline. Each tree is fetched by full commit id and the checked-out commit is verified
# (git object ids are content hashes). Run at release time before `cargo package`; the output is not tracked. Needs git.
set -euo pipefail
DEST="${1:?destination dir (seal-src)}"
rm -rf "$DEST"; mkdir -p "$DEST"
get() { # <dir> <url> <commit>
  git init -q "$DEST/$1"
  git -C "$DEST/$1" fetch -q --depth 1 "$2" "$3"
  git -C "$DEST/$1" checkout -q FETCH_HEAD
  [ "$(git -C "$DEST/$1" rev-parse HEAD)" = "$3" ] || { echo "commit mismatch for $1" >&2; exit 1; }
  rm -rf "$DEST/$1/.git" "$DEST/$1/.github"
}
get seal  https://github.com/microsoft/SEAL   119dc32e135cb89c1062076a69310d4413ebc824  # v4.1.2
get zlib  https://github.com/madler/zlib      04f42ceca40f73e2978b50e93806c2a18c1281fc  # 1.2.13 (its CMake builds test/example.c: keep test/)
get zstd  https://github.com/facebook/zstd    e47e674cd09583ff0503f0f6defd6d23d8b718d3  # 1.5.2
get msgsl https://github.com/microsoft/GSL    a3534567187d2edc428efd3f13466ff75fe5805c  # 4.0.0
# zlib 1.2.13 defines fdopen() away under TARGET_OS_MAC, which clashes with the current macOS SDK headers; fdopen exists there
perl -0pi -e 's/^[ \t]*#[ \t]*define fdopen\(fd,mode\) NULL[^\n]*\n//mg' "$DEST/zlib/zutil.h"
! grep -q 'define fdopen(fd,mode) NULL' "$DEST/zlib/zutil.h" || { echo "zlib fdopen patch did not apply" >&2; exit 1; }
# SEAL builds none of these when the *_BUILD_* switches in build.rs are off
rm -rf "$DEST/seal/native/examples" "$DEST/seal/native/tests" "$DEST/seal/native/bench" "$DEST/zstd/doc" "$DEST/zstd/contrib"
# SEAL's CMake configure_file()s the dotnet *.in templates even for the C export library: keep only those
find "$DEST/seal/dotnet" -type f ! -name "*.in" -delete
du -sh "$DEST" >&2
