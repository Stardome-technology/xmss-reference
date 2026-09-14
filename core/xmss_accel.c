#include <string.h>

#include "xmss_accel.h"

static xmss_accel_provider_t g_provider;

void xmss_accel_provider_set(const xmss_accel_provider_t *provider)
{
    if (provider == NULL) {
        xmss_accel_provider_clear();
        return;
    }
    g_provider = *provider;
}

void xmss_accel_provider_clear(void)
{
    memset(&g_provider, 0, sizeof(g_provider));
}

xmss_accel_result_t xmss_accel_try_prf(
    const xmss_params *params, unsigned char *out,
    const unsigned char input[32], const unsigned char *key)
{
    if (g_provider.prf == NULL) return XMSS_ACCEL_NOT_HANDLED;
    return g_provider.prf(g_provider.context, params, out, input, key);
}

xmss_accel_result_t xmss_accel_try_h_msg(
    const xmss_params *params, unsigned char *out,
    const unsigned char *r, const unsigned char *root, uint64_t index,
    const unsigned char *message, unsigned long long message_length)
{
    if (g_provider.h_msg == NULL) return XMSS_ACCEL_NOT_HANDLED;
    return g_provider.h_msg(g_provider.context, params, out, r, root, index,
                            message, message_length);
}

xmss_accel_result_t xmss_accel_try_wots_sign(
    const xmss_params *params, unsigned char *signature,
    const unsigned char *message, const unsigned char *sk_seed,
    const unsigned char *pub_seed, const uint32_t ots_addr[8])
{
    if (g_provider.wots_sign == NULL) return XMSS_ACCEL_NOT_HANDLED;
    return g_provider.wots_sign(g_provider.context, params, signature, message,
                                sk_seed, pub_seed, ots_addr);
}

xmss_accel_result_t xmss_accel_try_gen_leaf(
    const xmss_params *params, unsigned char *leaf,
    const unsigned char *sk_seed, const unsigned char *pub_seed,
    const uint32_t ltree_addr[8], const uint32_t ots_addr[8])
{
    if (g_provider.gen_leaf == NULL) return XMSS_ACCEL_NOT_HANDLED;
    return g_provider.gen_leaf(g_provider.context, params, leaf, sk_seed,
                               pub_seed, ltree_addr, ots_addr);
}

xmss_accel_result_t xmss_accel_try_thash_h(
    const xmss_params *params, unsigned char *out,
    const unsigned char *input, const unsigned char *pub_seed,
    const uint32_t node_addr[8])
{
    if (g_provider.thash_h == NULL) return XMSS_ACCEL_NOT_HANDLED;
    return g_provider.thash_h(g_provider.context, params, out, input, pub_seed,
                              node_addr);
}
