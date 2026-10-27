#!/usr/bin/env python3
"""Assemble the version-11 fixtures from the CI proving jobs' outputs.

usage: ci-finalize.py <succinct-dir> <wrap-dir> <negative-dir> <out-dir>
  succinct-dir: receipt_succinct.bin journal.json run_stats.json (prove_run with PCA_SKIP_GROTH16 PCA_SKIP_NEGATIVE)
  wrap-dir:     receipt_groth16.bin run_stats_wrap.json          (prove_run with PCA_WRAP_ONLY)
  negative-dir: negative_proving.json                            (prove_run with PCA_ONLY_NEGATIVE)
<out-dir> mirrors sdks/zkvm-pca/fixtures: image_id.json, public_journal.json, the two receipts, proof_run/*.
Every job must report the same image id (the docker guest build is path-independent).
"""
import hashlib, json, os, shutil, sys

succ, wrap, neg, out = sys.argv[1:5]
def load(d, f): return json.load(open(os.path.join(d, f)))
stats, wstats = load(succ, "run_stats.json"), load(wrap, "run_stats_wrap.json")
negs = load(neg, "negative_proving.json")
img = stats["image_id_hex"]
assert wstats["image_id_hex"] == img, "wrap job proved under a different image id"
assert stats["risc0_zkvm_version"] == wstats["risc0_zkvm_version"]
assert len(negs) > 0 and all(not n["receipt_produced"] for n in negs), "negative matrix produced a receipt"
words = [int.from_bytes(bytes.fromhex(img)[i:i + 4], "little") for i in range(0, 32, 4)]
image_id = {"guest": "pca-zkvm-guest", "image_id_hex": img, "image_id_words": words, "risc0_zkvm_version": stats["risc0_zkvm_version"], "zkvm": "risc0"}
stats.update({"groth16_wrap_ms": wstats["groth16_wrap_ms"], "groth16_bytes": wstats["groth16_bytes"]})
stats.pop("groth16", None)
pr = os.path.join(out, "proof_run"); os.makedirs(pr, exist_ok=True)
def put(path, data):
    open(path, "wb").write(data if isinstance(data, bytes) else data.encode())
dump = lambda v: json.dumps(v, indent=2, sort_keys=True)
put(os.path.join(pr, "image_id.json"), json.dumps(image_id, indent=2))
put(os.path.join(pr, "run_stats.json"), dump(stats))
put(os.path.join(pr, "negative_proving.json"), json.dumps(negs, indent=2))
shutil.copy(os.path.join(succ, "journal.json"), os.path.join(pr, "journal.json"))
shutil.copy(os.path.join(succ, "receipt_succinct.bin"), os.path.join(pr, "receipt_succinct.bin"))
shutil.copy(os.path.join(wrap, "receipt_groth16.bin"), os.path.join(pr, "receipt_groth16.bin"))
put(os.path.join(out, "image_id.json"), json.dumps(image_id, indent=2))
shutil.copy(os.path.join(pr, "journal.json"), os.path.join(out, "public_journal.json"))
for f in ("receipt_succinct.bin", "receipt_groth16.bin"): shutil.copy(os.path.join(pr, f), os.path.join(out, f))
sha = lambda f: hashlib.sha256(open(os.path.join(pr, f), "rb").read()).hexdigest()
prov = {
    "status": "experimental, unaudited",
    "date_utc": os.environ.get("PCA_PROVENANCE_DATE", ""),
    "statement": "RISC Zero guest pca-zkvm-guest for PCA 0.5.0 (guest_version 11): everything of guest version 10 plus rule 22 of the action kit (version 2 action schemas: floors and traits recomputed from the embedded trait table, the traits check against the grant and the verifier-observed call context, unconfirmed verbs carry every trait, reviewer pins); journal = fixtures/proof_run/journal.json",
    "image_id_hex": img,
    "supersedes_image_id": "432b4713d7981afc30907003d3a2c7e7d0003cc34b2367b4cba8d61b642c0060",
    "guest_elf_note": "ELF not committed (gitignored); Cargo.lock files pin the dependency graph. The image id above is the authoritative identity.",
    "versions": {
        "risc0-zkvm": stats["risc0_zkvm_version"], "r0vm": "3.0.6",
        "guest build": "risczero/risc0-guest-builder:r0.1.97.0 (docker, context crates/zkvm-pca, path-independent; methods/build.rs)",
        "host rustc": "stable (rust-toolchain.toml) as installed by rustup on the runner",
        "groth16 prover docker image": "risczero/risc0-groth16-prover (tag per risc0-zkvm 3.0.6 default, pulled by the host)",
    },
    "host": {"cloud": "GitHub Actions (public repo Atlas-Authorization/pca)", "vm": "ubuntu-latest hosted runner, x86_64 Linux", "gpu": "none (CPU proving)", "run": os.environ.get("PCA_PROVENANCE_RUN", "")},
    "reproduce": "bash crates/zkvm-pca/host/box-prove.sh <out-dir> on an x86_64 Linux box (installs rzup rust 1.97.0 + r0vm 3.0.6 and docker.io when missing), or the zkvm-v11 workflow",
    "pipeline": [
        {"step": "succinct receipt", "where": "CPU", "wall_ms": stats["succinct_prove_ms"], "cycles_total": stats["total_cycles"], "cycles_user": stats["user_cycles"], "segments": stats["segments"], "artifact": "receipt_succinct.bin"},
        {"step": "groth16 wrap (stark-to-snark) of that succinct receipt", "where": "CPU, docker risc0-groth16-prover (x86_64)", "wall_ms": wstats["groth16_wrap_ms"], "artifact": "receipt_groth16.bin"},
        {"step": "negative proving matrix", "where": "separate job (execute + full proving attempt per variant)", "artifact": "negative_proving.json", "result": f"{len(negs)} of {len(negs)} variants: guest panicked, no receipt"},
    ],
    "verified_on": "cargo test -p pca-zkvm-verify (see README)",
    "artifacts_sha256": {f: sha(f) for f in ("receipt_succinct.bin", "receipt_groth16.bin", "journal.json", "image_id.json", "negative_proving.json", "run_stats.json")},
}
put(os.path.join(pr, "PROVENANCE.json"), json.dumps(prov, indent=2))
print("image id", img)
