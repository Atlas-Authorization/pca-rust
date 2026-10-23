# Signature-suite capability matrix

Which signature suites each PCA verifier implements, and with what library. The rules every verifier follows (pure mode,
empty context, exact lengths, `unsupported_suite` for a registered suite it cannot verify, how runners and the
cross-language gate treat it) are in [README.md, "Suite capability"](./README.md#suite-capability-every-implementation-every-signed-surface).

The registry is `SIG_SUITES` in `packages/pca/src/pq.ts` (14 suites). Policy: every verifier implements every suite its
ecosystem has a trustworthy implementation of; a verifier that cannot refuses the suite with `unsupported_suite: <alg>`.
Each verifier exports its manifest:

| verifier | manifest | reason token |
|---|---|---|
| TypeScript (`@atlasauth/pca`) | `SIG_SUITES` / `resolveSigAlg` | n/a (reference) |
| Go (`sdks/go-pca`) | `RegisteredSuites`, `SupportedSuites()` (build tags) | `UnsupportedSuite` |
| Rust (`sdks/rust-pca`) | `REGISTERED_SUITES`, `supported_suites()` (cargo features) | `UNSUPPORTED_SUITE_REASON` |
| Swift (`sdks/swift-pca`) | `PCASuites.registered`, `PCASuites.supported` (runtime) | `PCASuites.unsupportedSuiteReason` |
| Java (`sdks/java-pca`) | `Pq.REGISTERED_SUITES`, `Pq.supportedSuites()` (runtime) | `Pq.UNSUPPORTED_SUITE` |
| Kotlin (`sdks/kotlin-pca`) | `Pq.REGISTERED_SUITES`, `Pq.supportedSuites()` (runtime) | `Pq.UNSUPPORTED_SUITE` |
| .NET (`sdks/dotnet-pca`) | `Pq.RegisteredSuites`, `Pq.SupportedSuites()` (runtime) | `Pq.UnsupportedSuite` |
| Python (`sdks/python-pca`) | `REGISTERED_SUITES`, `supported_suites()` (runtime) | `UNSUPPORTED_SUITE` |
| Ruby (`sdks/ruby-pca`) | `AtlasPca::REGISTERED_SUITES`, `AtlasPca.supported_suites` (runtime) | `AtlasPca::UNSUPPORTED_SUITE` |
| PHP (`sdks/php-pca`) | `Pca::REGISTERED_SUITES`, `Pca::supportedSuites()` (runtime) | `Pca::UNSUPPORTED_SUITE` |
| zkVM guest (`sdks/zkvm-pca/core`) | `pq_suites::suite_supported` | `SuiteError::Unsupported` (`unsupported_suite: <alg>`) |

"Runtime" manifests depend on what is present when the verifier runs (an optional library, the OpenSSL that is loaded,
the OS version); a suite whose backend is absent is reported unsupported and refused with `unsupported_suite`.

## Matrix (current)

`Y` = implemented and verified against the shared corpus (`vectors.json` `pq-leaf-*`, `pq-nonleaf-*`, `r041-share-*`,
`primitives.pq_artifact` / `chain_pin` / `threshold_share`; FN-DSA against `fndsa-vectors.json`). `R` = implemented,
available only when the runtime condition in the notes holds. `-` = refused with `unsupported_suite`.

| suite | TS | Go | Rust | Swift | Java | Kotlin | .NET | Python | Ruby | PHP | zkVM |
|---|---|---|---|---|---|---|---|---|---|---|---|
| `ed25519` | Y | Y | Y | Y | Y | Y | Y | Y | Y | Y | Y |
| `ml-dsa-65` | Y | Y | Y | R (1) | Y | Y | Y | R (2) | R (3) | R (3) | Y |
| `hybrid-ed25519-ml-dsa-65` | Y | Y | Y | R (1) | Y | Y | Y | R (2) | R (3) | R (3) | Y |
| `hybrid-nested-ed25519-ml-dsa-65` | Y | Y | Y | R (1) | Y | Y | Y | R (2) | R (3) | R (3) | Y |
| `ml-dsa-87` | Y | Y | Y | R (1) | Y | Y | Y | R (2) | R (3) | R (3) | Y |
| `hybrid-ed25519-ml-dsa-87` | Y | Y | Y | R (1) | Y | Y | Y | R (2) | R (3) | R (3) | Y |
| `slh-dsa-sha2-128f` | Y | Y | Y | - | Y | Y | Y | R (3) | R (3) | R (3) | Y |
| `hybrid-ed25519-slh-dsa-sha2-128f` | Y | Y | Y | - | Y | Y | Y | R (3) | R (3) | R (3) | Y |
| `slh-dsa-sha2-256s` | Y | Y | Y | - | Y | Y | Y | R (3) | R (3) | R (3) | Y |
| `hybrid-ed25519-slh-dsa-sha2-256s` | Y | Y | Y | - | Y | Y | Y | R (3) | R (3) | R (3) | Y |
| `fn-dsa-512` | R (4) | - | Y | - | - | - | - | - | - | - | Y (6) |
| `fn-dsa-1024` | R (4) | - | Y | - | - | - | - | - | - | - | Y (6) |
| `less-cat1` | R (5) | R (7) | R (8) | - | R (10) | R (10) | R (9) | R (9) | R (9) | R (9) | - |
| `hybrid-ed25519-less-cat1` | R (5) | R (7) | R (8) | - | R (10) | R (10) | R (9) | R (9) | R (9) | R (9) | - |

Notes:
1. CryptoKit `MLDSA65` / `MLDSA87`: macOS / iOS / watchOS / tvOS / visionOS 26 and later. Earlier OSes: `unsupported_suite`.
   Linux (the gate and CI build a patched copy with `tools/pca-audit/swift-mutate/linux-prep.sh`): swift-crypto for CryptoKit
   and liboqs (`OQS_SIG_ml_dsa_65_verify` / `OQS_SIG_ml_dsa_87_verify`, FIPS 204 pure, empty context) for both levels.
2. `dilithium-py` (extra `pq`) if installed, else OpenSSL >= 3.5 libcrypto (see 3).
3. OpenSSL >= 3.5 libcrypto: Ruby through the `openssl` gem it is built against; PHP through FFI (`ext-ffi`); Python through
   `ctypes`. PHP and Python find it at `ATLAS_PCA_LIBCRYPTO` or the usual OpenSSL 3 locations; each key type is probed by
   building a key (no version-number gate).
4. The TS reference verifies FN-DSA through the lazily loaded `@atlasauth/pca-fndsa-wasm`; without it FN-DSA verifies to
   false (deny).
5. LESS (a NIST round-2 candidate, not a standard) through the OPTIONAL `@atlasauth/pca-less-wasm` (the patched reference
   of `sdks/pca-less-c` compiled to wasm, plus wrapper-level guards; see "LESS: one patched reference everywhere").
6. zkVM guest: `fn-dsa-vrfy` 0.4 (pure integer arithmetic, `no_std`; builds for the rv32im guest), the crate the Rust SDK
   uses; DOMAIN_NONE + HASH_ID_RAW, exact lengths 897 / 666 and 1793 / 1280.
7. Go: only a build with `-tags less` and cgo (`less_cgo.go` compiles the patched reference C in the module's `lessc/`, a
   copy of `sdks/pca-less-c`, so the published module builds on its own). A pure-Go
   build (the default, or `-tags less` with `CGO_ENABLED=0`) refuses both suites with `unsupported_suite`.
8. Rust: only with the cargo feature `less` (`build.rs` compiles the crate's own `less-c/`, a copy of `sdks/pca-less-c`
   shipped in the crate so a crates.io build works, or the directory named by `ATLAS_PCA_LESS_SRC`, through `cc`). The
   gate's Rust driver enables it.
9. Python (`ctypes`), Ruby (Fiddle), PHP (FFI, `ext-ffi`), .NET (P/Invoke, `AtlasPca.LessNative`): when the shared library
   `libatlas_less` (built by `sdks/pca-less-c/build.sh`) is found at `ATLAS_PCA_LIBLESS`, else in the repository's
   `sdks/pca-less-c/build/` (Python also tries `ctypes.util.find_library`); it must report the less-252-45 sizes. LESS vectors:
   `less-vectors.json` (`gen-less.mjs`); the gate builds the library once and names it in `ATLAS_PCA_LIBLESS`.
10. Java / Kotlin: `LessNative` binds `libatlas_less` (found as in 9, or via the system property `atlas.pca.libless`) through
   the Foreign Function and Memory API, reached reflectively because the SDKs compile for Java 17 (Kotlin: an Android
   library), so only on a Java 22+ runtime with 64-bit addresses; Java 17-21 and Android refuse LESS. Run with
   `--enable-native-access=ALL-UNNAMED` (the gate does) to silence the JDK's restricted-method warning.

## Matrix before this change (2026-10-12)

| suite | TS | Go | Rust | Swift | Java | Kotlin | .NET | Python | Ruby | PHP | zkVM |
|---|---|---|---|---|---|---|---|---|---|---|---|
| `ed25519` | Y | Y | Y | Y | Y | Y | Y | Y | Y | Y | Y |
| `ml-dsa-65`, `hybrid-ed25519-ml-dsa-65` | Y | Y | Y | R (1) | Y | Y | Y | R (dilithium-py) | R (3) | R (3) | Y |
| `hybrid-nested-ed25519-ml-dsa-65`, `ml-dsa-87`, `hybrid-ed25519-ml-dsa-87` | Y | x | x | x | x | x | x | x | x | x | Y |
| `slh-dsa-sha2-128f/256s` and hybrids | Y | x | x | x | x | x | x | x | x | x | Y |
| `fn-dsa-512`, `fn-dsa-1024` | R (4) | x | x | x | x | x | x | x | x | x | `unsupported_suite` |
| `less-cat1` and hybrid | R (5) | x | x | x | x | x | x | x | x | x | `unsupported_suite` |

`x` = refused as an unknown alg (`unknown signature alg`, a wire failure), and the native runners skipped every vector that
needed a real verdict under it. Swift on an older OS and Python without `dilithium-py` returned a bad signature (not a
distinct reason) for the ML-DSA suites.

## Libraries

| verifier | library (version) | suites |
|---|---|---|
| Go | `github.com/cloudflare/circl` v1.6.5: `sign/mldsa/mldsa65`, `mldsa87`, `sign/slhdsa` (pulls `golang.org/x/crypto`) | ML-DSA, SLH-DSA |
| Rust | `fips204` 0.4 (ML-DSA), `fips205` 0.4 (SLH-DSA; the zkVM guest uses the same crate), `fn-dsa-vrfy` 0.4 (Thomas Pornin's FN-DSA verifier, the crate the TS reference's wasm wraps) | ML-DSA, SLH-DSA, FN-DSA |
| Swift | CryptoKit (`MLDSA65`, `MLDSA87`); no third-party dependencies by package policy | ML-DSA |
| Java, Kotlin | BouncyCastle `bcprov-jdk18on` 1.80 (`MLDSASigner`, `SLHDSASigner`) | ML-DSA, SLH-DSA |
| .NET | `BouncyCastle.Cryptography` 2.6.1 (`MLDsaSigner`, `SlhDsaSigner`) | ML-DSA, SLH-DSA |
| Python | `dilithium-py` >= 1.0 (optional extra `pq`) and/or OpenSSL >= 3.5 libcrypto (`ctypes`) | ML-DSA (either), SLH-DSA (OpenSSL) |
| Ruby | OpenSSL >= 3.5 through the `openssl` gem (`OpenSSL::PKey.new_raw_public_key`) | ML-DSA, SLH-DSA |
| PHP | OpenSSL >= 3.5 libcrypto through FFI (`OpensslPq`) | ML-DSA, SLH-DSA |
| Go (`-tags less`, cgo), Rust (feature `less`), Python (`ctypes`), Ruby (Fiddle), PHP (FFI), .NET (P/Invoke), Java / Kotlin (FFM, Java 22+) | `sdks/pca-less-c`: the LESS reference implementation (less-sig/LESS, CC0) with the Atlas verifier fixes (Atlas-Authorization/LESS, branch `atlas-verifier-hardening`), parameter set less-252-45, verify-only wrapper `atlas_less.c` | LESS |
| Swift on Linux | swift-crypto + liboqs (`linux-prep.sh`) | ML-DSA |
| zkVM guest | `fips204` 0.4, `fips205` 0.4, `fn-dsa-vrfy` 0.4 (pure Rust, `no_std`, build for the rv32im guest) | ML-DSA, SLH-DSA, FN-DSA |

## Why a suite is refused

- **FN-DSA (FIPS 206)** outside Rust: no maintained implementation of the FIPS 206 encoding exists in Go, Swift, the JVM,
  .NET, Python, Ruby or PHP that can be trusted. BouncyCastle ships round-3 Falcon, whose message hashing and encodings
  differ from FN-DSA; liboqs likewise. The standard itself is not final, and the vetted Rust crate warns its encodings may
  still change. The zkVM guest takes `fn-dsa-vrfy` (integer-only, `no_std`) since PCA 0.4.2 (the guest image is
  re-proved for that release).
- **SLH-DSA in Swift**: CryptoKit has no SLH-DSA and the package takes no third-party cryptography. Re-implementing
  FIPS 205 by hand is not "a trustworthy library".
- **FN-DSA in Go**, rechecked 2026-10-12: there is no pure-Go FIPS 206 verifier (cloudflare/circl has none; the Go Falcon
  packages are round-3 Falcon, not FN-DSA), so Go keeps refusing it.
- **LESS** is a NIST round-2 candidate with no standardized encoding and no library but the reference implementation. Every
  native except Swift and the zkVM guest links that reference (patched, `sdks/pca-less-c`) through its C FFI (notes 7-10)
  and refuses LESS when the backend is absent. Swift takes no third-party C by package policy; the zkVM guest has no C.

## LESS: one patched reference everywhere

Every LESS verifier runs the same PATCHED reference (`sdks/pca-less-c`): the natives through their C FFI, the TypeScript
reference through `@atlasauth/pca-less-wasm`, whose wasm is built from those sources by `scripts/build-wasm.sh` (pinned
wasi-sdk 25.0, reproducible; `wasm/BUILD.json`). Until 2026-10-12 the wasm was the UNPATCHED upstream, which accepted a
valid signature whose seed storage was extended by 16 arbitrary bytes with the trailing seed count raised by one (it reads
only the seeds the challenge needs): a malleated signature. The patched `crypto_sign_open` requires the stored seed count to
equal the count the challenge implies; the wasm wrapper also refuses a signature that still opens with its last seed dropped
(a non-canonical count). `less-vectors.json` carries the malleation (`*-seed-padded*`); every verifier must refuse it.

## Keeping this file honest

The manifests are code; this table is documentation. The gate prints every language's manifest (`[lang] suites: ...;
refused: ...`) and records it in `report.json` (`suites`), and every native runner asserts `unsupported_suite` for the
suites it refuses, so a manifest change that this table does not reflect shows up in the next gate run.
