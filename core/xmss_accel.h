#ifndef XMSS_ACCEL_H
#define XMSS_ACCEL_H

#include <stdint.h>

#include "params.h"

/*
 * Optional platform-neutral acceleration provider.
 *
 * NOT_HANDLED is the only result that permits the reference software path.
 * PENDING asks a resumable caller to revisit the same primitive without
 * advancing its phase or primitive count. ERROR is terminal and must be
 * propagated; transport faults are never hidden by software fallback.
 */
typedef enum {
    XMSS_ACCEL_ERROR = -1,
    XMSS_ACCEL_NOT_HANDLED = 0,
    XMSS_ACCEL_OK = 1,
    XMSS_ACCEL_PENDING = 2
} xmss_accel_result_t;

typedef struct {
    void *context;

    xmss_accel_result_t (*random_bytes)(
        void *context, unsigned char *out, unsigned long long length);

    xmss_accel_result_t (*prf)(
        void *context, const xmss_params *params, unsigned char *out,
        const unsigned char input[32], const unsigned char *key);

    xmss_accel_result_t (*h_msg)(
        void *context, const xmss_params *params, unsigned char *out,
        const unsigned char *r, const unsigned char *root,
        uint64_t index, const unsigned char *message,
        unsigned long long message_length);

    xmss_accel_result_t (*wots_sign)(
        void *context, const xmss_params *params, unsigned char *signature,
        const unsigned char *message, const unsigned char *sk_seed,
        const unsigned char *pub_seed, const uint32_t ots_addr[8]);

    xmss_accel_result_t (*gen_leaf)(
        void *context, const xmss_params *params, unsigned char *leaf,
        const unsigned char *sk_seed, const unsigned char *pub_seed,
        const uint32_t ltree_addr[8], const uint32_t ots_addr[8]);

    xmss_accel_result_t (*thash_h)(
        void *context, const xmss_params *params, unsigned char *out,
        const unsigned char *input, const unsigned char *pub_seed,
        const uint32_t node_addr[8]);

    /*
     * One bounded WOTS chain segment. The reference derives each base-w digit
     * d and requests start = d, steps = 15 - d so the provider performs the
     * remaining hash iterations from the signature value to the chain top.
     * The provider owns the full chain loop; the reference never issues a
     * THASH_F primitive for verification.
     */
    xmss_accel_result_t (*wots_chain)(
        void *context, const xmss_params *params, unsigned char *out,
        const unsigned char *input, const unsigned char *pub_seed,
        const uint32_t ots_addr[8], unsigned int start, unsigned int steps);

    void (*progress)(void *context, unsigned int primitive_count,
                     unsigned int layer, uint32_t leaf);
    int (*cancel_requested)(void *context);
    /* Cancel any provider-owned in-flight primitive. Optional and idempotent. */
    void (*abort)(void *context);
} xmss_accel_provider_t;

/* Internal dispatch functions used by the stateless reference core. */
xmss_accel_result_t xmss_accel_try_prf(
    const xmss_accel_provider_t *provider,
    const xmss_params *params, unsigned char *out,
    const unsigned char input[32], const unsigned char *key);
xmss_accel_result_t xmss_accel_try_h_msg(
    const xmss_accel_provider_t *provider,
    const xmss_params *params, unsigned char *out,
    const unsigned char *r, const unsigned char *root, uint64_t index,
    const unsigned char *message, unsigned long long message_length);
xmss_accel_result_t xmss_accel_try_wots_sign(
    const xmss_accel_provider_t *provider,
    const xmss_params *params, unsigned char *signature,
    const unsigned char *message, const unsigned char *sk_seed,
    const unsigned char *pub_seed, const uint32_t ots_addr[8]);
xmss_accel_result_t xmss_accel_try_gen_leaf(
    const xmss_accel_provider_t *provider,
    const xmss_params *params, unsigned char *leaf,
    const unsigned char *sk_seed, const unsigned char *pub_seed,
    const uint32_t ltree_addr[8], const uint32_t ots_addr[8]);
xmss_accel_result_t xmss_accel_try_thash_h(
    const xmss_accel_provider_t *provider,
    const xmss_params *params, unsigned char *out,
    const unsigned char *input, const unsigned char *pub_seed,
    const uint32_t node_addr[8]);
xmss_accel_result_t xmss_accel_try_wots_chain(
    const xmss_accel_provider_t *provider,
    const xmss_params *params, unsigned char *out,
    const unsigned char *input, const unsigned char *pub_seed,
    const uint32_t ots_addr[8], unsigned int start, unsigned int steps);

#endif
