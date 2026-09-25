#include <stdint.h>
#include <string.h>

#include "params.h"
#include "randombytes.h"
#include "xmss.h"
#include "xmss_core.h"

#define XMSS_WRAPPER_MAX_N 64U
#define XMSS_WRAPPER_MAX_INDEX_BYTES 8U

static void wrapper_secure_zero(void *memory, size_t length)
{
    volatile unsigned char *p = (volatile unsigned char *)memory;
    while (length-- != 0U) *p++ = 0U;
}

/* This file provides wrapper functions that take keys that include OIDs to
identify the parameter set to be used. After setting the parameters accordingly
it falls back to the regular XMSS core functions. */

int xmss_keypair(unsigned char *pk, unsigned char *sk, const uint32_t oid)
{
    xmss_params params;
    unsigned int i;

    if (xmss_parse_oid(&params, oid)) {
        return -1;
    }
    for (i = 0; i < XMSS_OID_LEN; i++) {
        pk[XMSS_OID_LEN - i - 1] = (oid >> (8 * i)) & 0xFF;
        /* For an implementation that uses runtime parameters, it is crucial
        that the OID is part of the secret key as well;
        i.e. not just for interoperability, but also for internal use. */
        sk[XMSS_OID_LEN - i - 1] = (oid >> (8 * i)) & 0xFF;
    }
    return xmss_core_keypair(&params, pk + XMSS_OID_LEN, sk + XMSS_OID_LEN);
}

int xmss_sign(unsigned char *sk,
              unsigned char *sm, unsigned long long *smlen,
              const unsigned char *m, unsigned long long mlen)
{
    xmss_params params;
    uint32_t oid = 0;
    unsigned int i;

    for (i = 0; i < XMSS_OID_LEN; i++) {
        oid |= sk[XMSS_OID_LEN - i - 1] << (i * 8);
    }
    if (xmss_parse_oid(&params, oid)) {
        return -1;
    }
    return xmss_core_sign(&params, sk + XMSS_OID_LEN, sm, smlen, m, mlen);
}

int xmss_sign_open(unsigned char *m, unsigned long long *mlen,
                   const unsigned char *sm, unsigned long long smlen,
                   const unsigned char *pk)
{
    xmss_params params;
    uint32_t oid = 0;
    unsigned int i;

    for (i = 0; i < XMSS_OID_LEN; i++) {
        oid |= pk[XMSS_OID_LEN - i - 1] << (i * 8);
    }
    if (xmss_parse_oid(&params, oid)) {
        return -1;
    }
    return xmss_core_sign_open(&params, m, mlen, sm, smlen, pk + XMSS_OID_LEN);
}

int xmssmt_keypair(unsigned char *pk, unsigned char *sk, const uint32_t oid)
{
    return xmssmt_keypair_with_provider(pk, sk, oid, NULL);
}

int xmssmt_keypair_with_provider(unsigned char *pk, unsigned char *sk,
                                 const uint32_t oid,
                                 const xmss_accel_provider_t *provider)
{
    xmss_params params;
    unsigned char seed[3U * 64U];
    unsigned char staged_pk[XMSS_OID_LEN + 2U * XMSS_WRAPPER_MAX_N];
    unsigned char staged_sk[XMSS_OID_LEN + XMSS_WRAPPER_MAX_INDEX_BYTES +
                            4U * XMSS_WRAPPER_MAX_N];
    xmss_accel_result_t entropy_result = XMSS_ACCEL_NOT_HANDLED;
    int result;
    unsigned int i;

    if (xmssmt_parse_oid(&params, oid)) {
        return -1;
    }
    if (params.n > XMSS_WRAPPER_MAX_N ||
        params.index_bytes > XMSS_WRAPPER_MAX_INDEX_BYTES) return -1;
    memset(seed, 0, sizeof(seed));
    memset(staged_pk, 0, sizeof(staged_pk));
    memset(staged_sk, 0, sizeof(staged_sk));
    i = 0U;
    if (provider != NULL && provider->random_bytes != NULL) {
        for (i = 0U; i < 3U; ++i) {
            entropy_result = provider->random_bytes(
                provider->context, seed + i * params.n, params.n);
            if (entropy_result != XMSS_ACCEL_OK) break;
        }
    }
    if (entropy_result == XMSS_ACCEL_NOT_HANDLED && i == 0U) {
        randombytes(seed, 3U * params.n);
    } else if (entropy_result != XMSS_ACCEL_OK) {
        wrapper_secure_zero(seed, sizeof(seed));
        wrapper_secure_zero(staged_sk, sizeof(staged_sk));
        return -3;
    }
    for (i = 0; i < XMSS_OID_LEN; i++) {
        staged_pk[XMSS_OID_LEN - i - 1] = (oid >> (8 * i)) & 0xFF;
        staged_sk[XMSS_OID_LEN - i - 1] = (oid >> (8 * i)) & 0xFF;
    }
    result = xmssmt_core_seed_keypair_with_provider(
        &params, staged_pk + XMSS_OID_LEN, staged_sk + XMSS_OID_LEN,
        seed, provider);
    if (result == 0) {
        memcpy(pk, staged_pk, XMSS_OID_LEN + params.pk_bytes);
        memcpy(sk, staged_sk, XMSS_OID_LEN + (size_t)params.sk_bytes);
    }
    wrapper_secure_zero(seed, sizeof(seed));
    wrapper_secure_zero(staged_sk, sizeof(staged_sk));
    return result;
}

int xmssmt_sign(unsigned char *sk,
                unsigned char *sm, unsigned long long *smlen,
                const unsigned char *m, unsigned long long mlen)
{
    return xmssmt_sign_with_provider(sk, sm, smlen, m, mlen, NULL);
}

int xmssmt_sign_with_provider(unsigned char *sk,
                              unsigned char *sm, unsigned long long *smlen,
                              const unsigned char *m,
                              unsigned long long mlen,
                              const xmss_accel_provider_t *provider)
{
    xmss_params params;
    uint32_t oid = 0;
    unsigned int i;

    for (i = 0; i < XMSS_OID_LEN; i++) {
        oid |= sk[XMSS_OID_LEN - i - 1] << (i * 8);
    }
    if (xmssmt_parse_oid(&params, oid)) {
        return -1;
    }
    return xmssmt_core_sign_with_provider(&params, sk + XMSS_OID_LEN, sm,
                                           smlen, m, mlen, provider);
}

int xmssmt_sign_open(unsigned char *m, unsigned long long *mlen,
                     const unsigned char *sm, unsigned long long smlen,
                     const unsigned char *pk)
{
    xmss_params params;
    uint32_t oid = 0;
    unsigned int i;

    for (i = 0; i < XMSS_OID_LEN; i++) {
        oid |= pk[XMSS_OID_LEN - i - 1] << (i * 8);
    }
    if (xmssmt_parse_oid(&params, oid)) {
        return -1;
    }
    return xmssmt_core_sign_open(&params, m, mlen, sm, smlen, pk + XMSS_OID_LEN);
}

int xmssmt_sign_open_with_provider(
    unsigned char *m, unsigned long long *mlen,
    const unsigned char *sm, unsigned long long smlen,
    const unsigned char *pk, const xmss_accel_provider_t *provider)
{
    xmss_params params;
    uint32_t oid = 0;
    unsigned int i;

    for (i = 0; i < XMSS_OID_LEN; i++) {
        oid |= pk[XMSS_OID_LEN - i - 1] << (i * 8);
    }
    if (xmssmt_parse_oid(&params, oid)) {
        return -1;
    }
    return xmssmt_core_sign_open_with_provider(
        &params, m, mlen, sm, smlen, pk + XMSS_OID_LEN, provider);
}
