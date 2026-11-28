/* C ABI of pca-zk (cargo feature "capi", libpcazk): Groth16 verification and proving for snarkjs / circom artifacts on BN254 and
 * BLS12-381 (arkworks; the circom witness wasm runs on the wasmi interpreter). Inputs are caller-owned buffers passed with their
 * length (UTF-8 JSON in the snarkjs encoding: decimal-string field elements, G1 [x,y,"1"], G2 [[x0,x1],[y0,y1],["1","0"]]).
 * Outputs of pca_zk_prove are library-owned and released with pca_zk_free. No global state: calls are thread-safe. No panic
 * crosses the boundary: a panic returns PCA_ZK_ERR_INTERNAL. */
#ifndef PCA_ZK_H
#define PCA_ZK_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif

#define PCA_ZK_CURVE_BN254 0
#define PCA_ZK_CURVE_BLS12_381 1
/* pca_zk_verify only, and only with PCA_ZK_FLAG_SNARKJS_COMPAT: the curve is the one the key names (see the flag). With flags 0,
 * and in pca_zk_prove, it is PCA_ZK_ERR_ARG. */
#define PCA_ZK_CURVE_FROM_KEY 2

/* pca_zk_verify flags. Default (0) is strict: protocol groth16 on key and proof, curve match, nPublic and IC length equal to the
 * signals count, canonical decimals below the field modulus, affine points, every point in the prime-order subgroup.
 * SNARKJS_COMPAT reproduces what snarkjs' groth16.verify accepts (the TypeScript reference's behaviour): the key's protocol and
 * nPublic and the proof's protocol/curve are ignored, and IC entries beyond signals + 1 are neither read nor validated. The group,
 * field and subgroup checks stay on in both modes. A lane's public verify API passes SNARKJS_COMPAT (after its own envelope gate).
 * The key's curve name: strict takes exactly "bn128" or "bls12381". SNARKJS_COMPAT reads it as snarkjs' getCurveFromName does:
 * upper-cased, every character that is not an ASCII letter or digit dropped, then BN128, BN254 or ALTBN128 is BN254 and BLS12381
 * is BLS12-381 ("BN254", "alt_bn128", "bls12-381", "BLS12_381" all name a curve); any other name, or none, is
 * PCA_ZK_REASON_BAD_CURVE. With an explicit curve argument the named curve must be that curve; with PCA_ZK_CURVE_FROM_KEY the name
 * alone decides, which is what snarkjs does: a lane should pass it and not map the name itself. */
#define PCA_ZK_FLAG_SNARKJS_COMPAT 1u

/* Return codes. verify: PCA_ZK_VALID or PCA_ZK_INVALID, or a negative error. prove: PCA_ZK_OK or a negative error. */
#define PCA_ZK_VALID 1
#define PCA_ZK_INVALID 0
#define PCA_ZK_OK 0
#define PCA_ZK_ERR_ARG (-1)      /* null pointer, unknown curve, unknown flag, bad seed length; nothing read, nothing allocated */
#define PCA_ZK_ERR_INTERNAL (-2) /* a panic was caught */
#define PCA_ZK_ERR_PROVE (-3)    /* proving failed (witness does not satisfy the circuit, or the zkey is not one the prover reads) */
#define PCA_ZK_ERR_WITNESS (-4)  /* the witness wasm failed or the input does not fit the circuit */
#define PCA_ZK_ERR_ZKEY (-5)     /* the zkey is malformed or is for another curve */
#define PCA_ZK_ERR_INPUT (-6)    /* the input is not a JSON object */

/* Reason codes written by pca_zk_verify. */
#define PCA_ZK_REASON_OK 0
#define PCA_ZK_REASON_BAD_JSON 1
#define PCA_ZK_REASON_BAD_PROTOCOL 2
#define PCA_ZK_REASON_BAD_CURVE 3
#define PCA_ZK_REASON_BAD_ENCODING 4
#define PCA_ZK_REASON_NOT_IN_SUBGROUP 5
#define PCA_ZK_REASON_NOT_AFFINE 6
#define PCA_ZK_REASON_BAD_SHAPE 7
#define PCA_ZK_REASON_SIGNAL_COUNT 8
#define PCA_ZK_REASON_IC_SHORT 9
#define PCA_ZK_REASON_PAIRING_FAILED 10

/* Library version, a static NUL-terminated string. */
const char *pca_zk_version(void);
/* Static NUL-terminated text of a PCA_ZK_REASON_* code ("unknown" for any other value). */
const char *pca_zk_reason_text(int32_t reason);

/* Verifies a snarkjs Groth16 proof (vkey JSON object, proof JSON object, public signals JSON array of decimal strings).
 * Returns PCA_ZK_VALID, PCA_ZK_INVALID (then *reason says why) or a negative error. reason may be NULL. */
int32_t pca_zk_verify(int32_t curve, uint32_t flags, const uint8_t *vkey, size_t vkey_len, const uint8_t *proof, size_t proof_len,
                      const uint8_t *signals, size_t signals_len, int32_t *reason);

/* Proves: runs the circom witness wasm over the input JSON object, reads the snarkjs zkey and proves with Groth16. On PCA_ZK_OK,
 * (*out, *out_len) is the UTF-8 JSON {"proof":{...},"publicSignals":[...]} (the snarkjs proof.json and public.json combined); on any
 * other return except PCA_ZK_ERR_ARG it is a UTF-8 error message. Release it with pca_zk_free(*out, *out_len). seed is 32 bytes that make
 * the blinding factors deterministic (tests only), or NULL with seed_len 0 for operating-system randomness (production). */
int32_t pca_zk_prove(int32_t curve, const uint8_t *wasm, size_t wasm_len, const uint8_t *zkey, size_t zkey_len, const uint8_t *input,
                     size_t input_len, const uint8_t *seed, size_t seed_len, uint8_t **out, size_t *out_len);
/* Releases a buffer returned by pca_zk_prove (pointer and length as returned). NULL is ignored. */
void pca_zk_free(uint8_t *ptr, size_t len);

#ifdef __cplusplus
}
#endif
#endif
