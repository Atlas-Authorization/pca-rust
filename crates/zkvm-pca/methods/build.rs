//! R6: the guest is built in risc0's docker guest builder (`risczero/risc0-guest-builder:r0.1.97.0`: rustc 1.97, the toolchain of
//! the earlier rzup builds; risc0-build 3.0.6's default r0.1.88.0 is too old for the locked dependency graph) with the `sdks/zkvm-pca` directory as the build context, so every source path compiled into the
//! guest is `/src/...` and the image id does NOT depend on where the repository is checked out. (A host-toolchain build
//! embeds the absolute path of `core/` in panic locations: three checkouts of the same commit gave three image ids.)
//! `PCA_ZKVM_LOCAL_BUILD=1` falls back to the host rzup toolchain for development; its image id is path-dependent and
//! is never the published one.
use risc0_build::{embed_methods_with_options, DockerOptionsBuilder, GuestOptionsBuilder};
use std::collections::HashMap;

fn main() {
    println!("cargo:rerun-if-env-changed=PCA_ZKVM_LOCAL_BUILD");
    if std::env::var_os("PCA_ZKVM_LOCAL_BUILD").is_some() {
        embed_methods_with_options(HashMap::new());
        return;
    }
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let docker = DockerOptionsBuilder::default().root_dir(root).docker_container_tag("r0.1.97.0").build().expect("docker options");
    let opts = GuestOptionsBuilder::default().use_docker(docker).build().expect("guest options");
    embed_methods_with_options(HashMap::from([("pca-zkvm-guest", opts)]));
}
