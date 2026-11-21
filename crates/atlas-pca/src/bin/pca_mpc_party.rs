//! One MPC node as its own OS process: `pca-mpc-party <config.json>` or `pca-mpc-party keygen <dir> <cn>`. Prints exactly one JSON line.
fn main() {
    std::process::exit(atlas_pca::mpc_net_driver::party_main::cli(std::env::args().skip(1).collect()));
}
