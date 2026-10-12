#!/usr/bin/env bash
# Reproducible proving run ON an exclusive x86_64 Linux box (repo synced to /work/pca, fixtures pushed alongside):
# installs the RISC Zero toolchain (rzup: rust 1.97.0, r0vm 3.0.6), docker.io and docker-buildx when missing, builds the guest,
# prints its image id (path-independent: the guest is built in risc0's docker guest builder), then runs prove_run (succinct receipt, Groth16 wrap via the docker prover, negative matrix).
#   bash sdks/zkvm-pca/host/box-prove.sh <out-dir>          (PCA_ONLY_BUILD=1: build + image id only)
set -euo pipefail
OUT="${1:?usage: box-prove.sh <out-dir>}"
export PATH="$HOME/.risc0/bin:$HOME/.cargo/bin:$PATH"
cd "$(dirname "$0")/.."
if ! command -v rzup >/dev/null; then
  curl -sSfL https://risczero.com/install | bash
  export PATH="$HOME/.risc0/bin:$PATH"
fi
rzup install rust 1.97.0 >/dev/null 2>&1 || rzup install rust 1.97.0
rzup install r0vm 3.0.6 >/dev/null 2>&1 || rzup install r0vm 3.0.6
rzup show || true
if ! command -v docker >/dev/null; then
  sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -q docker.io
fi
id -nG | grep -qw docker || sudo usermod -aG docker "$USER"
# the docker guest build uses `docker build --output` (BuildKit)
docker buildx version >/dev/null 2>&1 || sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -q docker-buildx
export CARGO_TARGET_DIR=/work/target/zkvm-pca-prove
# the docker stark-to-snark prover bind-mounts host temp files: a private /tmp (systemd PrivateTmp, job units) is invisible to
# the docker daemon, so keep temp files on a shared path
export TMPDIR="${PCA_TMPDIR:-/work/zkvm-pca-tmp}"; mkdir -p "$TMPDIR"
# the guest is built in risc0's docker guest builder (methods/build.rs): path-independent image id
sg docker -c "cargo build --release -p pca-zkvm-host --bin prove_run" 2>&1 | grep -v '^ *Compiling' | tail -5
mkdir -p "$OUT"
if [ -n "${PCA_ONLY_BUILD:-}" ]; then
  PCA_ONLY_NEGATIVE=1 timeout 1 "$CARGO_TARGET_DIR/release/prove_run" "$OUT" 2>&1 | grep -m1 'image id' || true
  exit 0
fi
# docker group membership takes effect in a new login group: run the prover under `sg docker`
sg docker -c "TMPDIR=$TMPDIR $CARGO_TARGET_DIR/release/prove_run '$OUT'" 2>&1 | tee "$OUT/prove_run.log"
