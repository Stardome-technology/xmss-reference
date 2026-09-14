#include <stddef.h>

#include "xmss_accel.h"

xmss_accel_result_t xmss_accel_try_prf(
    const xmss_accel_provider_t *provider,
    const xmss_params *params, unsigned char *out,
    const unsigned char input[32], const unsigned char *key)
{
    if (provider == NULL || provider->prf == NULL) return XMSS_ACCEL_NOT_HANDLED;
    return provider->prf(provider->context, params, out, input, key);
}

xmss_accel_result_t xmss_accel_try_h_msg(
    const xmss_accel_provider_t *provider,
    const xmss_params *params, unsigned char *out,
    const unsigned char *r, const unsigned char *root, uint64_t index,
    const unsigned char *message, unsigned long long message_length)
{
    if (provider == NULL || provider->h_msg == NULL) return XMSS_ACCEL_NOT_HANDLED;
    return provider->h_msg(provider->context, params, out, r, root, index,
                           message, message_length);
}

xmss_accel_result_t xmss_accel_try_wots_sign(
    const xmss_accel_provider_t *provider,
    const xmss_params *params, unsigned char *signature,
    const unsigned char *message, const unsigned char *sk_seed,
    const unsigned char *pub_seed, const uint32_t ots_addr[8])
{
    if (provider == NULL || provider->wots_sign == NULL) return XMSS_ACCEL_NOT_HANDLED;
    return provider->wots_sign(provider->context, params, signature, message,
                               sk_seed, pub_seed, ots_addr);
}

xmss_accel_result_t xmss_accel_try_gen_leaf(
    const xmss_accel_provider_t *provider,
    const xmss_params *params, unsigned char *leaf,
    const unsigned char *sk_seed, const unsigned char *pub_seed,
    const uint32_t ltree_addr[8], const uint32_t ots_addr[8])
{
    if (provider == NULL || provider->gen_leaf == NULL) return XMSS_ACCEL_NOT_HANDLED;
    return provider->gen_leaf(provider->context, params, leaf, sk_seed,
                              pub_seed, ltree_addr, ots_addr);
}

xmss_accel_result_t xmss_accel_try_thash_h(
    const xmss_accel_provider_t *provider,
    const xmss_params *params, unsigned char *out,
    const unsigned char *input, const unsigned char *pub_seed,
    const uint32_t node_addr[8])
{
    if (provider == NULL || provider->thash_h == NULL) return XMSS_ACCEL_NOT_HANDLED;
    return provider->thash_h(provider->context, params, out, input, pub_seed,
                             node_addr);
}
