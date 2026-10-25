/* Verify-only wrapper over the patched LESS reference (see atlas_less.h and README.md). */
#include "atlas_less.h"

#include <stdlib.h>
#include <string.h>

#include "api.h"
#include "parameters.h"

#if !defined(CATEGORY) || !defined(TARGET) || CATEGORY != 252 || TARGET != 45
#error "atlas_less: build with -DCATEGORY=252 -DTARGET=45 (the less-cat1 parameter set)"
#endif

#if defined(_WIN32)
#include <windows.h>
#else
#include <pthread.h>
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

static void run_open(open_job *j) { j->rc = crypto_sign_open(j->m, &j->mlen, j->sm, j->smlen, j->pk); }

#if defined(_WIN32)
static DWORD WINAPI open_thread(LPVOID arg) { run_open((open_job *)arg); return 0; }
static int open_on_big_stack(open_job *j) {
    HANDLE h = CreateThread(NULL, ATLAS_LESS_STACK_BYTES, open_thread, j, STACK_SIZE_PARAM_IS_A_RESERVATION, NULL);
    if (h == NULL) return 0;
    WaitForSingleObject(h, INFINITE);
    CloseHandle(h);
    return 1;
}
#else
static void *open_thread(void *arg) { run_open((open_job *)arg); return NULL; }
static int open_on_big_stack(open_job *j) {
    pthread_attr_t a;
    pthread_t t;
    if (pthread_attr_init(&a) != 0) return 0;
    int ok = pthread_attr_setstacksize(&a, ATLAS_LESS_STACK_BYTES) == 0 && pthread_create(&t, &a, open_thread, j) == 0;
    pthread_attr_destroy(&a);
    if (!ok) return 0;
    return pthread_join(t, NULL) == 0;
}
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
        valid = open_on_big_stack(&j) && j.rc == 0 && j.mlen == (unsigned long long)msg_len &&
                (msg_len == 0 || memcmp(m, msg, msg_len) == 0);
    }
    free(sm);
    free(m);
    return valid;
}
