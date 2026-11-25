/* Verify and sign wrapper over the patched LESS reference (see atlas_less.h and README.md). */
#include "atlas_less.h"

#include <stdlib.h>
#include <string.h>

/* before the LESS headers: they define N, K, T and W as macros, which windows.h would then trip over */
#if defined(_WIN32)
#include <windows.h>
#else
#include <pthread.h>
#endif

#include "api.h"
#include "parameters.h"
#include "rng.h"

#if !defined(CATEGORY) || !defined(TARGET) || CATEGORY != 252 || TARGET != 45
#error "atlas_less: build with -DCATEGORY=252 -DTARGET=45 (the less-cat1 parameter set)"
#endif

#define ATLAS_LESS_STACK_BYTES ((size_t)16 * 1024 * 1024)
#define SIG_MIN ((size_t)LESS_SIGNATURE_SIZE(0))
#define SIG_MAX ((size_t)LESS_SIGNATURE_SIZE(MAX_PUBLISHED_SEEDS))

size_t atlas_less_cat1_public_key_bytes(void) { return (size_t)CRYPTO_PUBLICKEYBYTES; }
size_t atlas_less_cat1_signature_min_bytes(void) { return SIG_MIN; }
size_t atlas_less_cat1_signature_max_bytes(void) { return SIG_MAX; }

typedef struct {
    const uint8_t *pk;
    const uint8_t *sm;
    unsigned long long smlen;
    uint8_t *m;
    unsigned long long mlen;
    int rc;
} open_job;

static void run_open(void *arg) {
    open_job *j = (open_job *)arg;
    j->rc = crypto_sign_open(j->m, &j->mlen, j->sm, j->smlen, j->pk);
}

typedef struct {
    void (*fn)(void *);
    void *arg;
} big_job;

#if defined(_WIN32)
static DWORD WINAPI big_thread(LPVOID arg) { big_job *b = (big_job *)arg; b->fn(b->arg); return 0; }
static int on_big_stack(void (*fn)(void *), void *arg) {
    big_job b = {fn, arg};
    HANDLE h = CreateThread(NULL, ATLAS_LESS_STACK_BYTES, big_thread, &b, STACK_SIZE_PARAM_IS_A_RESERVATION, NULL);
    if (h == NULL) return 0;
    WaitForSingleObject(h, INFINITE);
    CloseHandle(h);
    return 1;
}
static SRWLOCK rng_lock = SRWLOCK_INIT;
static void rng_acquire(void) { AcquireSRWLockExclusive(&rng_lock); }
static void rng_release(void) { ReleaseSRWLockExclusive(&rng_lock); }
#else
static void *big_thread(void *arg) { big_job *b = (big_job *)arg; b->fn(b->arg); return NULL; }
static int on_big_stack(void (*fn)(void *), void *arg) {
    big_job b = {fn, arg};
    pthread_attr_t a;
    pthread_t t;
    if (pthread_attr_init(&a) != 0) return 0;
    int ok = pthread_attr_setstacksize(&a, ATLAS_LESS_STACK_BYTES) == 0 && pthread_create(&t, &a, big_thread, &b) == 0;
    pthread_attr_destroy(&a);
    if (!ok) return 0;
    return pthread_join(t, NULL) == 0;
}
static pthread_mutex_t rng_lock = PTHREAD_MUTEX_INITIALIZER;
static void rng_acquire(void) { pthread_mutex_lock(&rng_lock); }
static void rng_release(void) { pthread_mutex_unlock(&rng_lock); }
#endif

int atlas_less_cat1_verify(const uint8_t *pk, size_t pk_len, const uint8_t *msg, size_t msg_len, const uint8_t *sig, size_t sig_len) {
    if (pk == NULL || sig == NULL || (msg == NULL && msg_len != 0)) return 0;
    if (pk_len != (size_t)CRYPTO_PUBLICKEYBYTES) return 0;
    if (sig_len < SIG_MIN || sig_len > SIG_MAX || (SIG_MAX - sig_len) % SEED_LENGTH_BYTES != 0) return 0;
    if (msg_len > (size_t)-1 - sig_len) return 0;
    const size_t smlen = msg_len + sig_len;
    uint8_t *sm = (uint8_t *)malloc(smlen);
    uint8_t *m = (uint8_t *)malloc(smlen);
    int valid = 0;
    if (sm != NULL && m != NULL) {
        if (msg_len) memcpy(sm, msg, msg_len);
        memcpy(sm + msg_len, sig, sig_len);
        open_job j = {pk, sm, (unsigned long long)smlen, m, 0, -1};
        valid = on_big_stack(run_open, &j) && j.rc == 0 && j.mlen == (unsigned long long)msg_len &&
                (msg_len == 0 || memcmp(m, msg, msg_len) == 0);
    }
    free(sm);
    free(m);
    return valid;
}

/* ---- signing: the reference's global generator is seeded from the caller's entropy under a lock ---- */

size_t atlas_less_cat1_secret_key_bytes(void) { return (size_t)CRYPTO_SECRETKEYBYTES; }

typedef struct {
    uint8_t *pk;
    uint8_t *sk;
    const uint8_t *seed;
    size_t seed_len;
    int rc;
} keygen_job;

static void run_keygen(void *arg) {
    keygen_job *j = (keygen_job *)arg;
    init_randombytes(j->seed, j->seed_len);
    j->rc = crypto_sign_keypair(j->pk, j->sk);
}

int atlas_less_cat1_keygen(uint8_t *pk, size_t pk_cap, uint8_t *sk, size_t sk_cap, const uint8_t *seed, size_t seed_len) {
    if (pk == NULL || sk == NULL || seed == NULL || seed_len < ATLAS_LESS_MIN_SEED_BYTES) return 0;
    if (pk_cap != (size_t)CRYPTO_PUBLICKEYBYTES || sk_cap != (size_t)CRYPTO_SECRETKEYBYTES) return 0;
    uint8_t *tp = (uint8_t *)malloc(CRYPTO_PUBLICKEYBYTES);
    uint8_t *ts = (uint8_t *)malloc(CRYPTO_SECRETKEYBYTES);
    int ok = 0;
    if (tp != NULL && ts != NULL) {
        keygen_job j = {tp, ts, seed, seed_len, -1};
        rng_acquire();
        ok = on_big_stack(run_keygen, &j) && j.rc == 0;
        rng_release();
        if (ok) {
            memcpy(pk, tp, CRYPTO_PUBLICKEYBYTES);
            memcpy(sk, ts, CRYPTO_SECRETKEYBYTES);
        }
    }
    if (ts != NULL) {
        volatile uint8_t *z = ts;
        for (size_t i = 0; i < CRYPTO_SECRETKEYBYTES; i++) z[i] = 0;
    }
    free(tp);
    free(ts);
    return ok;
}

typedef struct {
    const uint8_t *sk;
    const uint8_t *msg;
    unsigned long long msg_len;
    const uint8_t *seed;
    size_t seed_len;
    uint8_t *sm;
    unsigned long long smlen;
    int rc;
} sign_job;

static void run_sign(void *arg) {
    sign_job *j = (sign_job *)arg;
    init_randombytes(j->seed, j->seed_len);
    j->rc = crypto_sign(j->sm, &j->smlen, j->msg, j->msg_len, j->sk);
}

int atlas_less_cat1_sign(const uint8_t *sk, size_t sk_len, const uint8_t *msg, size_t msg_len, const uint8_t *seed, size_t seed_len,
                         uint8_t *sig, size_t sig_cap, size_t *sig_len) {
    static const uint8_t none = 0;
    if (sk == NULL || seed == NULL || sig == NULL || sig_len == NULL || (msg == NULL && msg_len != 0)) return 0;
    if (sk_len != (size_t)CRYPTO_SECRETKEYBYTES || seed_len < ATLAS_LESS_MIN_SEED_BYTES || sig_cap < SIG_MAX) return 0;
    if (msg_len > (size_t)-1 - sizeof(sign_t) - 16) return 0;
    const size_t cap = msg_len + sizeof(sign_t) + 16; /* the reference writes a whole sign_t after the message */
    uint8_t *sm = (uint8_t *)calloc(cap, 1);
    int ok = 0;
    if (sm != NULL) {
        sign_job j = {sk, msg == NULL ? &none : msg, (unsigned long long)msg_len, seed, seed_len, sm, 0, -1};
        rng_acquire();
        ok = on_big_stack(run_sign, &j) && j.rc == 0;
        rng_release();
        if (ok) {
            const size_t n = j.smlen >= msg_len ? (size_t)j.smlen - msg_len : 0;
            ok = j.smlen <= cap && n >= SIG_MIN && n <= SIG_MAX && (SIG_MAX - n) % SEED_LENGTH_BYTES == 0;
            if (ok) {
                memcpy(sig, sm + msg_len, n);
                *sig_len = n;
            }
        }
    }
    free(sm);
    return ok;
}
