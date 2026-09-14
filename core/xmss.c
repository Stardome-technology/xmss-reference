#include <stdint.h>
#include <string.h>

#include "params.h"
#include "randombytes.h"
#include "xmss.h"
#include "xmss_core.h"

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
    xmss_accel_result_t entropy_result = XMSS_ACCEL_NOT_HANDLED;
    int result;
    unsigned int i;

    if (xmssmt_parse_oid(&params, oid)) {
        return -1;
    }
    for (i = 0; i < XMSS_OID_LEN; i++) {
        pk[XMSS_OID_LEN - i - 1] = (oid >> (8 * i)) & 0xFF;
        sk[XMSS_OID_LEN - i - 1] = (oid >> (8 * i)) & 0xFF;
    }
    if (provider != NULL && provider->random_bytes != NULL) {
        entropy_result = provider->random_bytes(provider->context, seed,
                                                 3U * params.n);
    }
    if (entropy_result == XMSS_ACCEL_NOT_HANDLED) {
        randombytes(seed, 3U * params.n);
    } else if (entropy_result != XMSS_ACCEL_OK) {
        memset(seed, 0, sizeof(seed));
        return -3;
    }
    result = xmssmt_core_seed_keypair_with_provider(
        &params, pk + XMSS_OID_LEN, sk + XMSS_OID_LEN, seed, provider);
    memset(seed, 0, sizeof(seed));
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
