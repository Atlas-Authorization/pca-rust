#!/usr/bin/env bash
# build-libpcagt.sh <blst-checkout> <pca_gt.c> <out-dir> [libname]: builds supranational blst (pinned v0.3.16 commit) plus the GT shim
# into ONE shared library (blst linked statically into it): <out-dir>/<libname>.{so,dylib,dll}. libname defaults to libpca_gt.
# Optional env, for a JNI build: PCA_GT_EXTRA_SRC (space-separated extra C files, e.g. the JNI wrapper) and PCA_GT_EXTRA_CFLAGS (e.g. -I$JAVA_HOME/include ...).
# Runs on the runner's own platform (linux x64/arm64, macOS x64/arm64, windows x64 under bash with gcc/clang). The last line printed is the library path.
set -euo pipefail
BLST="${1:?blst checkout}"; GT="${2:?pca_gt.c}"; OUT="${3:?output dir}"; NAME="${4:-libpca_gt}"
test "$(git -C "$BLST" rev-parse HEAD)" = "e7f90de551e8df682f3cc99067d204d8b90d27ad" # v0.3.16
mkdir -p "$OUT"
CC_="${CC:-cc}"
case "$(uname -s)" in
  Darwin) ext=dylib; extra=(-dynamiclib -install_name "@rpath/$NAME.dylib") ;;
  MINGW*|MSYS*|CYGWIN*) ext=dll; extra=(-shared) ;;
  *) ext=so; extra=(-shared) ;;
esac
# portable C blst (no assembly), the same build every lane replays its corpus against
"$CC_" -O2 -fPIC "${extra[@]}" -D__BLST_PORTABLE__ -I"$BLST/bindings" ${PCA_GT_EXTRA_CFLAGS:-} -o "$OUT/$NAME.$ext" "$GT" ${PCA_GT_EXTRA_SRC:-} "$BLST/src/server.c" "$BLST/build/assembly.S" >&2
echo "$OUT/$NAME.$ext"
