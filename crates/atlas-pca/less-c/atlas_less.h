/*
 * C API of the LESS signature (NIST additional-signature round-2 candidate, not a standard) for the native PCA
 * verifiers (verify, plus keygen and sign for the opt-in signing suites): the patched upstream reference in lib/ + include/ (see README.md), parameter set CATEGORY=252 TARGET=45
 * ("less-252-45", the `less-cat1` suite of packages/pca/src/pq.ts and @atlasauth/pca-less-wasm).
 * Compile every C file of lib/ plus atlas_less.c with -DCATEGORY=252 -DTARGET=45 -Iinclude.
 */
#ifndef ATLAS_LESS_H
#define ATLAS_LESS_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Public key 97,484 bytes; a detached signature is 1,153..1,329 bytes in steps of 16 (the published seed count). */
size_t atlas_less_cat1_public_key_bytes(void);
size_t atlas_less_cat1_signature_min_bytes(void);
size_t atlas_less_cat1_signature_max_bytes(void);

/*
 * 1 iff `sig` is a valid detached less-252-45 signature over `msg` under `pk` (the PCA `less-cat1` primitive: the attached
 * signed message msg || sig opens under pk and yields exactly msg); 0 otherwise. Never reads outside the given buffers; a
 * wrong key length or a signature length the parameter set cannot produce is 0. Thread-safe (verification uses no global
 * state). Runs the reference verifier on a dedicated thread with a 16 MiB stack (it keeps ~0.4 MB of matrices on the stack,
 * more than some platforms give a secondary thread), so it is safe to call from any thread; if that thread cannot be
 * created, the answer is 0 (fail closed).
 */
int atlas_less_cat1_verify(const uint8_t *pk, size_t pk_len, const uint8_t *msg, size_t msg_len, const uint8_t *sig, size_t sig_len);

/*
 * Signing. The reference draws its randomness from one process-global SHAKE-based generator, so keygen and sign take the entropy
 * from the caller (the host's CSPRNG: at least ATLAS_LESS_MIN_SEED_BYTES, any extra bytes are absorbed too) and are serialized
 * on a lock; the same seed gives the same key / signature (known-answer tests). Never reuse a seed across calls in production:
 * a repeated seed repeats the salt. Both run on the same 16 MiB-stack thread as verify. 1 on success, 0 on any failure (a short
 * seed, a buffer of the wrong size, thread failure); nothing is written on failure.
 */
#define ATLAS_LESS_MIN_SEED_BYTES 32

/* Secret key bytes (the 32-byte seed the public key is expanded from). */
size_t atlas_less_cat1_secret_key_bytes(void);

/* Writes the public key (exactly atlas_less_cat1_public_key_bytes) and secret key (exactly atlas_less_cat1_secret_key_bytes). */
int atlas_less_cat1_keygen(uint8_t *pk, size_t pk_cap, uint8_t *sk, size_t sk_cap, const uint8_t *seed, size_t seed_len);

/*
 * Writes the detached signature of `msg` under `sk` to `sig` (capacity `sig_cap` >= atlas_less_cat1_signature_max_bytes) and its
 * length (1,153..1,329 in steps of 16) to `*sig_len`; `atlas_less_cat1_verify` accepts it under the matching public key.
 */
int atlas_less_cat1_sign(const uint8_t *sk, size_t sk_len, const uint8_t *msg, size_t msg_len, const uint8_t *seed, size_t seed_len,
                         uint8_t *sig, size_t sig_cap, size_t *sig_len);

#ifdef __cplusplus
}
#endif

#endif
