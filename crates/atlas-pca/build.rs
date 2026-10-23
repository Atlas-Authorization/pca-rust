//! Feature `less` only: compiles the patched LESS reference C (parameter set CATEGORY=252 TARGET=45) and its verify-only
//! wrapper `atlas_less.c` from `less-c/` inside this crate (a copy of the repository's sdks/pca-less-c, kept by its
//! sync-copies.sh, so a crates.io build needs nothing else), or from ATLAS_PCA_LESS_SRC when set. Without the feature this
//! script does nothing.

fn main() {
    println!("cargo:rerun-if-env-changed=ATLAS_PCA_LESS_SRC");
    #[cfg(feature = "less")]
    less::build();
}

#[cfg(feature = "less")]
mod less {
    use std::path::PathBuf;

    const SOURCES: &[&str] = &[
        "lib/codes.c",
        "lib/fips202.c",
        "lib/keccakf1600.c",
        "lib/LESS.c",
        "lib/monomial.c",
        "lib/rng.c",
        "lib/seedtree.c",
        "lib/sign.c",
        "lib/utils.c",
        "lib/sort.c",
        "lib/canonical.c",
        "lib/transpose.c",
        "atlas_less.c",
    ];

    pub fn build() {
        let dir = std::env::var_os("ATLAS_PCA_LESS_SRC")
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").unwrap()).join("less-c")
            });
        assert!(
            dir.join("atlas_less.c").is_file(),
            "feature `less`: the LESS C sources were not found at {} (the crate's less-c/, or ATLAS_PCA_LESS_SRC)",
            dir.display()
        );
        let mut b = cc::Build::new();
        b.include(dir.join("include"))
            .include(&dir)
            .opt_level(2)
            .define("CATEGORY", "252")
            .define("TARGET", "45")
            .warnings(false);
        for s in SOURCES {
            b.file(dir.join(s));
            println!("cargo:rerun-if-changed={}", dir.join(s).display());
        }
        println!("cargo:rerun-if-changed={}", dir.join("include").display());
        println!(
            "cargo:rerun-if-changed={}",
            dir.join("atlas_less.h").display()
        );
        b.compile("atlas_less");
        if !std::env::var("CARGO_CFG_TARGET_OS").is_ok_and(|os| os == "windows") {
            println!("cargo:rustc-link-lib=pthread");
        }
    }
}
