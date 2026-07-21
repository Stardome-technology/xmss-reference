#include <stdint.h>
#include <string.h>

#include "hash_address.h"
#include "utils.h"
#include "params.h"
#include "hash.h"
#include "xmss_callbacks.h"
#include "fips202.h"

static sha_cb_t sha_cb = NULL;

#define XMSS_HASH_PADDING_F 0
#define XMSS_HASH_PADDING_H 1
#define XMSS_HASH_PADDING_HASH 2
#define XMSS_HASH_PADDING_PRF 3
#define XMSS_HASH_PADDING_PRF_KEYGEN 4

void addr_to_bytes(unsigned char *bytes, const uint32_t addr[8])
{
    int i;
    for (i = 0; i < 8; i++) {
        ull_to_bytes(bytes + i*4, 4, addr[i]);
    }
}

int xmss_set_sha_cb(sha_cb_t cb)
{
    if (cb == NULL) return -1;
    sha_cb = cb;
    return 0;
}

static int core_hash(const xmss_params *params,
                     unsigned char *out,
                     const unsigned char *in, unsigned long long inlen)
{
    if (params->func == XMSS_SHA2) {
        if (sha_cb == NULL) return -1;
        return sha_cb(in, inlen, out);
    }
    if (params->func == XMSS_SHAKE256) {
        shake256(out, params->n, in, inlen);
        return 0;
    }
    return -1;
}

int prf(const xmss_params *params,
        unsigned char *out, const unsigned char in[32],
        const unsigned char *key)
{
    unsigned char buf[params->padding_len + params->n + 32];
    ull_to_bytes(buf, params->padding_len, XMSS_HASH_PADDING_PRF);
    memcpy(buf + params->padding_len, key, params->n);
    memcpy(buf + params->padding_len + params->n, in, 32);
    return core_hash(params, out, buf, params->padding_len + params->n + 32);
}

int prf_keygen(const xmss_params *params,
        unsigned char *out, const unsigned char *in,
        const unsigned char *key)
{
    unsigned char buf[params->padding_len + 2*params->n + 32];
    ull_to_bytes(buf, params->padding_len, XMSS_HASH_PADDING_PRF_KEYGEN);
    memcpy(buf + params->padding_len, key, params->n);
    memcpy(buf + params->padding_len + params->n, in, params->n + 32);
    return core_hash(params, out, buf, params->padding_len + 2*params->n + 32);
}

int hash_message(const xmss_params *params, unsigned char *out,
                 const unsigned char *R, const unsigned char *root,
                 unsigned long long idx,
                 unsigned char *m_with_prefix, unsigned long long mlen)
{
    ull_to_bytes(m_with_prefix, params->padding_len, XMSS_HASH_PADDING_HASH);
    memcpy(m_with_prefix + params->padding_len, R, params->n);
    memcpy(m_with_prefix + params->padding_len + params->n, root, params->n);
    ull_to_bytes(m_with_prefix + params->padding_len + 2*params->n, params->n, idx);
    return core_hash(params, out, m_with_prefix, mlen + params->padding_len + 3*params->n);
}

int thash_h(const xmss_params *params,
            unsigned char *out, const unsigned char *in,
            const unsigned char *pub_seed, uint32_t addr[8])
{
    unsigned char bitmask[2 * params->n];
    unsigned char addr_as_bytes[32];
    unsigned int i;
    unsigned char buf[params->padding_len + 3 * params->n];
    ull_to_bytes(buf, params->padding_len, XMSS_HASH_PADDING_H);
    set_key_and_mask(addr, 0);
    addr_to_bytes(addr_as_bytes, addr);
    prf(params, buf + params->padding_len, addr_as_bytes, pub_seed);
    set_key_and_mask(addr, 1);
    addr_to_bytes(addr_as_bytes, addr);
    prf(params, bitmask, addr_as_bytes, pub_seed);
    set_key_and_mask(addr, 2);
    addr_to_bytes(addr_as_bytes, addr);
    prf(params, bitmask + params->n, addr_as_bytes, pub_seed);
    for (i = 0; i < 2 * params->n; i++)
        buf[params->padding_len + params->n + i] = in[i] ^ bitmask[i];
    return core_hash(params, out, buf, params->padding_len + 3 * params->n);
}

int thash_f(const xmss_params *params,
            unsigned char *out, const unsigned char *in,
            const unsigned char *pub_seed, uint32_t addr[8])
{
    unsigned char bitmask[params->n];
    unsigned char addr_as_bytes[32];
    unsigned int i;
    unsigned char buf[params->padding_len + 2 * params->n];
    ull_to_bytes(buf, params->padding_len, XMSS_HASH_PADDING_F);
    set_key_and_mask(addr, 0);
    addr_to_bytes(addr_as_bytes, addr);
    prf(params, buf + params->padding_len, addr_as_bytes, pub_seed);
    set_key_and_mask(addr, 1);
    addr_to_bytes(addr_as_bytes, addr);
    prf(params, bitmask, addr_as_bytes, pub_seed);
    for (i = 0; i < params->n; i++)
        buf[params->padding_len + params->n + i] = in[i] ^ bitmask[i];
    return core_hash(params, out, buf, params->padding_len + 2 * params->n);
}
