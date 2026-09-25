#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "hash.h"
#include "hash_address.h"
#include "params.h"
#include "wots.h"
#include "utils.h"
#include "xmss_commons.h"
#include "xmss_resumable.h"

/**
 * Computes a leaf node from a WOTS public key using an L-tree.
 * Note that this destroys the used WOTS public key.
 */
static void l_tree(const xmss_params *params,
                   unsigned char *leaf, unsigned char *wots_pk,
                   const unsigned char *pub_seed, uint32_t addr[8])
{
    unsigned int l = params->wots_len;
    unsigned int parent_nodes;
    uint32_t i;
    uint32_t height = 0;

    set_tree_height(addr, height);

    while (l > 1) {
        parent_nodes = l >> 1;
        for (i = 0; i < parent_nodes; i++) {
            set_tree_index(addr, i);
            /* Hashes the nodes at (i*2)*params->n and (i*2)*params->n + 1 */
            thash_h(params, wots_pk + i*params->n,
                           wots_pk + (i*2)*params->n, pub_seed, addr);
        }
        /* If the row contained an odd number of nodes, the last node was not
           hashed. Instead, we pull it up to the next layer. */
        if (l & 1) {
            memcpy(wots_pk + (l >> 1)*params->n,
                   wots_pk + (l - 1)*params->n, params->n);
            l = (l >> 1) + 1;
        }
        else {
            l = l >> 1;
        }
        height++;
        set_tree_height(addr, height);
    }
    memcpy(leaf, wots_pk, params->n);
}

/**
 * Computes the leaf at a given address. First generates the WOTS key pair,
 * then computes leaf using l_tree. As this happens position independent, we
 * only require that addr encodes the right ltree-address.
 */
void gen_leaf_wots(const xmss_params *params, unsigned char *leaf,
                   const unsigned char *sk_seed, const unsigned char *pub_seed,
                   uint32_t ltree_addr[8], uint32_t ots_addr[8])
{
    unsigned char pk[params->wots_sig_bytes];

    wots_pkgen(params, pk, sk_seed, pub_seed, ots_addr);

    l_tree(params, leaf, pk, pub_seed, ltree_addr);
}


/**
 * Verifies a given message signature pair under a given public key.
 * Note that this assumes a pk without an OID, i.e. [root || PUB_SEED]
 */
int xmss_core_sign_open(const xmss_params *params,
                        unsigned char *m, unsigned long long *mlen,
                        const unsigned char *sm, unsigned long long smlen,
                        const unsigned char *pk)
{
    /* XMSS signatures are fundamentally an instance of XMSSMT signatures.
       For d=1, as is the case with XMSS, some of the calls in the XMSSMT
       routine become vacuous (i.e. the loop only iterates once, and address
       management can be simplified a bit).*/
    return xmssmt_core_sign_open(params, m, mlen, sm, smlen, pk);
}

/**
 * Verifies a given message signature pair under a given public key.
 * Note that this assumes a pk without an OID, i.e. [root || PUB_SEED]
 */
int xmssmt_core_sign_open(const xmss_params *params,
                          unsigned char *m, unsigned long long *mlen,
                          const unsigned char *sm, unsigned long long smlen,
                          const unsigned char *pk)
{
    return xmssmt_core_sign_open_with_provider(
        params, m, mlen, sm, smlen, pk, NULL);
}

/*
 * Provider-aware XMSSMT verification. Drives the same resumable verifier to a
 * terminal result. A null provider selects the software path. On success the
 * recovered message is written to `m` and `mlen` receives its length; on
 * rejection or failure `mlen` is set to zero and no message is published.
 */
int xmssmt_core_sign_open_with_provider(
    const xmss_params *params, unsigned char *m, unsigned long long *mlen,
    const unsigned char *sm, unsigned long long smlen,
    const unsigned char *pk, const xmss_accel_provider_t *provider)
{
    xmssmt_verify_state_storage_t storage;
    xmssmt_verify_state_t *state = NULL;
    xmss_resumable_result_t step_result;
    unsigned long long recovered_length = 0U;
    size_t capacity;

    if (mlen == NULL) return -1;
    *mlen = 0U;
    if (params == NULL || sm == NULL || pk == NULL || m == NULL) return -1;
    if (smlen < params->sig_bytes) return -1;
    capacity = (size_t)(smlen - params->sig_bytes);
    if (xmssmt_verify_init(&storage, params, provider, m, capacity, sm,
                           (size_t)smlen, pk, 2U * params->n, &state) != 0)
        return -1;
    do {
        step_result = xmssmt_verify_step(state);
    } while (step_result == XMSS_RESUMABLE_MORE);
    if (step_result != XMSS_RESUMABLE_DONE ||
        xmssmt_verify_finish(state, &recovered_length) != 0) {
        xmssmt_verify_abort(state);
        *mlen = 0U;
        return step_result == XMSS_RESUMABLE_CANCELLED ? -4 : -1;
    }
    *mlen = recovered_length;
    return 0;
}
