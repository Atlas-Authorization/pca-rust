/* C ABI of the endemic-OT lattice core (cargo feature "capi"). Raw Kyber-768 K-PKE (IND-CPA, caller-supplied
 * seed and coins) plus the ring helpers the endemic base OT needs. Every buffer is caller-owned and passed with
 * its length; a null pointer or a length different from the fixed size is refused and nothing is written.
 * No global state: calls are thread-safe. Return: 0 ok, negative refused. */
#ifndef PCA_LWE_OT_H
#define PCA_LWE_OT_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif

#define LWEOT_OK 0
#define LWEOT_ERR_ARG (-1)      /* null pointer or wrong length */
#define LWEOT_ERR_INTERNAL (-2)

/* Fixed Kyber-768 sizes: pk 1184, sk 1152, ct 1088, ring vector 1152, seed/coins/message 32, hash input cap 4096. */
size_t lweot_len_pk(void);
size_t lweot_len_sk(void);
size_t lweot_len_ct(void);
size_t lweot_len_tvec(void);
size_t lweot_len_sym(void);
size_t lweot_hashin_cap(void);

/* (pk, sk) = K-PKE.KeyGen(seed), deterministic. */
int32_t lweot_kpke_keygen(const uint8_t *seed, size_t seed_len, uint8_t *pk, size_t pk_len, uint8_t *sk, size_t sk_len);
/* (pk, sk) = K-PKE.KeyGen(d) as FIPS 203 Algorithm 13 derives it (RustCrypto ml-kem), deterministic. The endemic receiver uses this one. */
int32_t lweot_kpke_keygen_fips203(const uint8_t *seed, size_t seed_len, uint8_t *pk, size_t pk_len, uint8_t *sk, size_t sk_len);
/* ct = K-PKE.Enc(pk, msg; coins). pk may be any 1184-byte key, including a uniform ring vector || rho. */
int32_t lweot_kpke_enc(const uint8_t *pk, size_t pk_len, const uint8_t *msg, size_t msg_len,
                       const uint8_t *coins, size_t coins_len, uint8_t *ct, size_t ct_len);
/* msg = K-PKE.Dec(sk, ct). */
int32_t lweot_kpke_dec(const uint8_t *sk, size_t sk_len, const uint8_t *ct, size_t ct_len, uint8_t *msg, size_t msg_len);
/* out = (a +/- b) mod q over serialized ring vectors (coefficient-wise). */
int32_t lweot_ring_add(const uint8_t *a, size_t a_len, const uint8_t *b, size_t b_len, uint8_t *out, size_t out_len);
int32_t lweot_ring_sub(const uint8_t *a, size_t a_len, const uint8_t *b, size_t b_len, uint8_t *out, size_t out_len);
/* out = SampleNTT(SHAKE128(input)), a uniform ring vector; input_len 0..lweot_hashin_cap(). */
int32_t lweot_hash_to_ring(const uint8_t *input, size_t input_len, uint8_t *out, size_t out_len);

#ifdef __cplusplus
}
#endif
#endif
