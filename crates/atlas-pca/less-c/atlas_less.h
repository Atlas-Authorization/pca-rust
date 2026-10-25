/*
 * Verify-only C API of the LESS signature (NIST additional-signature round-2 candidate, not a standard) for the native PCA
 * verifiers: the patched upstream reference in lib/ + include/ (see README.md), parameter set CATEGORY=252 TARGET=45
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

#ifdef __cplusplus
}
#endif

#endif
