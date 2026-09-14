#ifndef XMSS_ACCEL_H
#define XMSS_ACCEL_H

#include <stdint.h>

#include "params.h"

/*
 * Optional platform-neutral acceleration provider.
 *
 * NOT_HANDLED is the only result that permits the reference software path.
 * ERROR is terminal and must be propagated by the caller.  This distinction
 * prevents a transport or accelerator fault from being hidden by fallback.
 */
typedef enum {
    XMSS_ACCEL_ERROR = -1,
    XMSS_ACCEL_NOT_HANDLED = 0,
    XMSS_ACCEL_OK = 1
} xmss_accel_result_t;

typedef struct {
    void *context;

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
} xmss_accel_provider_t;

/* The provider is copied by value. Passing NULL restores software-only mode. */
void xmss_accel_provider_set(const xmss_accel_provider_t *provider);
void xmss_accel_provider_clear(void);

/* Internal dispatch functions used by the stateless reference core. */
xmss_accel_result_t xmss_accel_try_prf(
    const xmss_params *params, unsigned char *out,
    const unsigned char input[32], const unsigned char *key);
xmss_accel_result_t xmss_accel_try_h_msg(
    const xmss_params *params, unsigned char *out,
    const unsigned char *r, const unsigned char *root, uint64_t index,
    const unsigned char *message, unsigned long long message_length);
xmss_accel_result_t xmss_accel_try_wots_sign(
    const xmss_params *params, unsigned char *signature,
    const unsigned char *message, const unsigned char *sk_seed,
    const unsigned char *pub_seed, const uint32_t ots_addr[8]);
xmss_accel_result_t xmss_accel_try_gen_leaf(
    const xmss_params *params, unsigned char *leaf,
    const unsigned char *sk_seed, const unsigned char *pub_seed,
    const uint32_t ltree_addr[8], const uint32_t ots_addr[8]);
xmss_accel_result_t xmss_accel_try_thash_h(
    const xmss_params *params, unsigned char *out,
    const unsigned char *input, const unsigned char *pub_seed,
    const uint32_t node_addr[8]);

#endif
