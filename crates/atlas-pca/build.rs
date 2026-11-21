//! Feature `less` only: compiles the patched LESS reference C (parameter set CATEGORY=252 TARGET=45) and its verify-only
//! wrapper `atlas_less.c` from `less-c/` inside this crate (a copy of the repository's sdks/pca-less-c, kept by its
//! sync-copies.sh, so a crates.io build needs nothing else), or from ATLAS_PCA_LESS_SRC when set. Without the feature this
//! script does nothing.

fn main() {
    println!("cargo:rerun-if-env-changed=ATLAS_PCA_LESS_SRC");
    #[cfg(feature = "less")]
    less::build();
    // Feature `fhe-seal`: link Microsoft SEAL's C export library (libsealc) from ATLAS_PCA_SEAL_LIB (else the system linker path).
    println!("cargo:rerun-if-env-changed=ATLAS_PCA_SEAL_LIB");
    #[cfg(feature = "fhe-seal")]
    {
        if let Some(dir) = std::env::var_os("ATLAS_PCA_SEAL_LIB") {
            let dir = std::path::PathBuf::from(dir);
            println!("cargo:rustc-link-search=native={}", dir.display());
            #[cfg(unix)]
            println!("cargo:rustc-link-arg=-Wl,-rpath,{}", dir.display());
        }
        // an explicit ATLAS_PCA_SEAL_LIB wins over the shipped sources (which are then not built)
        #[cfg(feature = "fhe-seal-vendored")]
        if std::env::var_os("ATLAS_PCA_SEAL_LIB").is_none() {
            seal_vendored();
        }
        println!("cargo:rustc-link-lib=sealc");
    }
}

/// Feature `fhe-seal-vendored`: build libsealc from seal-src/ (SEAL and its pinned zlib, zstd and msgsl, all shipped there, so
/// configure never touches the network) and link it with an rpath to the build output.
#[cfg(feature = "fhe-seal-vendored")]
fn seal_vendored() {
    let root =
        std::path::PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").unwrap()).join("seal-src");
    assert!(
        root.join("seal/CMakeLists.txt").is_file(),
        "feature `fhe-seal-vendored`: seal-src/ is missing (it ships in the crates.io package; a git checkout needs the fetch-seal-vendor script)"
    );
    let mut c = cmake::Config::new(root.join("seal"));
    c.define("SEAL_BUILD_SEAL_C", "ON")
        .define("SEAL_BUILD_DEPS", "ON")
        .define("BUILD_SHARED_LIBS", "OFF")
        .define("SEAL_USE_ZLIB", "ON")
        .define("SEAL_USE_ZSTD", "ON")
        .define("SEAL_BUILD_EXAMPLES", "OFF")
        .define("SEAL_BUILD_TESTS", "OFF")
        .define("SEAL_BUILD_BENCH", "OFF")
        .define("FETCHCONTENT_FULLY_DISCONNECTED", "ON")
        .define("CMAKE_POLICY_VERSION_MINIMUM", "3.5")
        .define("ZSTD_BUILD_PROGRAMS", "OFF")
        .define("ZSTD_BUILD_TESTS", "OFF");
    for (name, dir) in [("MSGSL", "msgsl"), ("ZLIB", "zlib"), ("ZSTD", "zstd")] {
        c.define(format!("FETCHCONTENT_SOURCE_DIR_{name}"), root.join(dir));
    }
    // the env var also reaches the nested configures of the vendored zlib and zstd
    c.env("CMAKE_POLICY_VERSION_MINIMUM", "3.5");
    let out = c.build_target("sealc").build();
    let lib = out.join("build").join("lib");
    println!("cargo:rustc-link-search=native={}", lib.display());
    println!("cargo:rustc-link-arg=-Wl,-rpath,{}", lib.display());
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
        // the LESS sources use GNU attributes and initialisers MSVC cl rejects: use the clang that ships on Windows
        if std::env::var("CARGO_CFG_TARGET_ENV").is_ok_and(|e| e == "msvc") {
            b.compiler("clang");
        }
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
