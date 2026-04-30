#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "hash.h"
#include "hash_address.h"
#include "params.h"
#include "randombytes.h"
#include "wots.h"
#include "utils.h"
#include "xmss_commons.h"
#include "xmss_core.h"
#include "xmss_core_hooks.h"
#include "xmss_workspace.h"

static xmss_workspace_t g_xmss_workspace;

xmss_workspace_t *xmss_workspace_get(void)
{
    return &g_xmss_workspace;
}

static int core_params_fit_scratch(const xmss_params *params)
{
    if (params->n > XMSS_WS_MAX_N) {
        return -1;
    }
    if (params->tree_height > XMSS_WS_MAX_TREE_HEIGHT) {
        return -1;
    }
    return 0;
}

/**
 * For a given leaf index, computes the authentication path and the resulting
 * root node using Merkle's TreeHash algorithm.
 * Expects the layer and tree parts of subtree_addr to be set.
 */
static void treehash(const xmss_params *params,
                     unsigned char *root, unsigned char *auth_path,
                     const unsigned char *sk_seed,
                     const unsigned char *pub_seed,
                     uint32_t leaf_idx, const uint32_t subtree_addr[8])
{
    xmss_workspace_t *ws = xmss_workspace_get();
    unsigned char *stack = ws->treehash_stack;
    unsigned int *heights = ws->treehash_heights;
    unsigned int offset = 0;

    /* The subtree has at most 2^20 leafs, so uint32_t suffices. */
    uint32_t idx;
    uint32_t tree_idx;

    /* We need all three types of addresses in parallel. */
    uint32_t ots_addr[8] = {0};
    uint32_t ltree_addr[8] = {0};
    uint32_t node_addr[8] = {0};

    /* Select the required subtree. */
    copy_subtree_addr(ots_addr, subtree_addr);
    copy_subtree_addr(ltree_addr, subtree_addr);
    copy_subtree_addr(node_addr, subtree_addr);

    set_type(ots_addr, XMSS_ADDR_TYPE_OTS);
    set_type(ltree_addr, XMSS_ADDR_TYPE_LTREE);
    set_type(node_addr, XMSS_ADDR_TYPE_HASHTREE);

    if (core_params_fit_scratch(params) != 0) {
        memset(root, 0, params->n);
        memset(auth_path, 0, params->tree_height * params->n);
        return;
    }

    for (idx = 0; idx < (uint32_t)(1 << params->tree_height); idx++) {
        /* Add the next leaf node to the stack. */
        set_ltree_addr(ltree_addr, idx);
        set_ots_addr(ots_addr, idx);
        gen_leaf_wots(params, stack + offset*params->n,
                      sk_seed, pub_seed, ltree_addr, ots_addr);
        offset++;
        heights[offset - 1] = 0;

        /* If this is a node we need for the auth path.. */
        if ((leaf_idx ^ 0x1) == idx) {
            memcpy(auth_path, stack + (offset - 1)*params->n, params->n);
        }

        /* While the top-most nodes are of equal height.. */
        while (offset >= 2 && heights[offset - 1] == heights[offset - 2]) {
            /* Compute index of the new node, in the next layer. */
            tree_idx = (idx >> (heights[offset - 1] + 1));

            /* Hash the top-most nodes from the stack together. */
            /* Note that tree height is the 'lower' layer, even though we use
               the index of the new node on the 'higher' layer. This follows
               from the fact that we address the hash function calls. */
            set_tree_height(node_addr, heights[offset - 1]);
            set_tree_index(node_addr, tree_idx);
            thash_h(params, stack + (offset-2)*params->n,
                           stack + (offset-2)*params->n, pub_seed, node_addr);
            offset--;
            /* Note that the top-most node is now one layer higher. */
            heights[offset - 1]++;

            /* If this is a node we need for the auth path.. */
            if (((leaf_idx >> heights[offset - 1]) ^ 0x1) == tree_idx) {
                memcpy(auth_path + heights[offset - 1]*params->n,
                       stack + (offset - 1)*params->n, params->n);
            }
        }
    }
    memcpy(root, stack, params->n);
}

/**
 * Given a set of parameters, this function returns the size of the secret key.
 * This is implementation specific, as varying choices in tree traversal will
 * result in varying requirements for state storage.
 */
unsigned long long xmss_xmssmt_core_sk_bytes(const xmss_params *params)
{
    return params->index_bytes + 4 * params->n;
}

/*
 * Generates a XMSS key pair for a given parameter set.
 * Format sk: [(32bit) index || SK_SEED || SK_PRF || root || PUB_SEED]
 * Format pk: [root || PUB_SEED], omitting algorithm OID.
 */
int xmss_core_keypair(const xmss_params *params,
                      unsigned char *pk, unsigned char *sk)
{
    /* The key generation procedure of XMSS and XMSSMT is exactly the same.
       The only important detail is that the right subtree must be selected;
       this requires us to correctly set the d=1 parameter for XMSS. */
    return xmssmt_core_keypair(params, pk, sk);
}

/**
 * Signs a message. Returns an array containing the signature followed by the
 * message and an updated secret key.
 */
int xmss_core_sign(const xmss_params *params,
                   unsigned char *sk,
                   unsigned char *sm, unsigned long long *smlen,
                   const unsigned char *m, unsigned long long mlen)
{
    /* XMSS signatures are fundamentally an instance of XMSSMT signatures.
       For d=1, as is the case with XMSS, some of the calls in the XMSSMT
       routine become vacuous (i.e. the loop only iterates once, and address
       management can be simplified a bit).*/
    return xmssmt_core_sign(params, sk, sm, smlen, m, mlen);
}

/*
 * Derives a XMSSMT key pair for a given parameter set.
 * Seed must be 3*n long.
 * Format sk: [(ceil(h/8) bit) index || SK_SEED || SK_PRF || root || PUB_SEED]
 * Format pk: [root || PUB_SEED] omitting algorithm OID.
 */
int xmssmt_core_seed_keypair(const xmss_params *params,
                             unsigned char *pk, unsigned char *sk,
                             unsigned char *seed)
{
    /* We do not need the auth path in key generation, but it simplifies the
       code to have just one treehash routine that computes both root and path
       in one function. */
    xmss_workspace_t *ws = xmss_workspace_get();
    unsigned char *auth_path = ws->seed_keypair_auth_path;
    uint32_t top_tree_addr[8] = {0};

    if (core_params_fit_scratch(params) != 0) {
        return -1;
    }

    set_layer_addr(top_tree_addr, params->d - 1);

    /* Initialize index to 0. */
    memset(sk, 0, params->index_bytes);
    sk += params->index_bytes;

    /* Initialize SK_SEED and SK_PRF. */
    memcpy(sk, seed, 2 * params->n);

    /* Initialize PUB_SEED. */
    memcpy(sk + 3 * params->n, seed + 2 * params->n,  params->n);
    memcpy(pk + params->n, sk + 3*params->n, params->n);

    /* Compute root node of the top-most subtree. */
    treehash(params, pk, auth_path, sk, pk + params->n, 0, top_tree_addr);
    memcpy(sk + 2*params->n, pk, params->n);

    return 0;
}

/*
 * Generates a XMSSMT key pair for a given parameter set.
 * Format sk: [(ceil(h/8) bit) index || SK_SEED || SK_PRF || root || PUB_SEED]
 * Format pk: [root || PUB_SEED] omitting algorithm OID.
 */
int xmssmt_core_keypair(const xmss_params *params,
                        unsigned char *pk, unsigned char *sk)
{
    xmss_workspace_t *ws = xmss_workspace_get();
    unsigned char *seed = ws->keypair_seed;

    if (core_params_fit_scratch(params) != 0) {
        return -1;
    }

    randombytes(seed, 3 * params->n);
    xmssmt_core_seed_keypair(params, pk, sk, seed);

    return 0;
}

/**
 * Signs a message. Returns an array containing the signature followed by the
 * message and an updated secret key.
 */
int xmssmt_core_sign(const xmss_params *params,
                     unsigned char *sk,
                     unsigned char *sm, unsigned long long *smlen,
                     const unsigned char *m, unsigned long long mlen)
{
    xmss_workspace_t *ws = xmss_workspace_get();
    const unsigned char *sk_seed = sk + params->index_bytes;
    const unsigned char *sk_prf = sk + params->index_bytes + params->n;
    const unsigned char *pub_root = sk + params->index_bytes + 2*params->n;
    const unsigned char *pub_seed = sk + params->index_bytes + 3*params->n;

    unsigned char *root = ws->sign_root;
    unsigned char *mhash = root;
    unsigned long long idx;
    unsigned char idx_bytes_32[32];
    unsigned int i;
    uint32_t idx_leaf;
    const uint32_t sign_start_ms = xmssmt_core_hooks_time_now_ms();

    uint32_t ots_addr[8] = {0};
    set_type(ots_addr, XMSS_ADDR_TYPE_OTS);

    xmssmt_core_hooks_sign_timing_begin(params);

    if (core_params_fit_scratch(params) != 0) {
        return -1;
    }

    /* Already put the message in the right place, to make it easier to prepend
     * things when computing the hash over the message. */
    memcpy(sm + params->sig_bytes, m, mlen);
    *smlen = params->sig_bytes + mlen;

    /* Read and use the current index from the secret key. */
    idx = (unsigned long)bytes_to_ull(sk, params->index_bytes);
    
    /* Check if we can still sign with this sk.
     * If not, return -2
     * 
     * If this is the last possible signature (because the max index value 
     * is reached), production implementations should delete the secret key 
     * to prevent accidental further use.
     * 
     * For the case of total tree height of 64 we do not use the last signature 
     * to be on the safe side (there is no index value left to indicate that the 
     * key is finished, hence external handling would be necessary)
     */ 
    if (idx >= ((1ULL << params->full_height) - 1)) {
        // Delete secret key here. We only do this in memory, production code
        // has to make sure that this happens on disk.
        memset(sk, 0xFF, params->index_bytes);
        memset(sk + params->index_bytes, 0, (params->sk_bytes - params->index_bytes));
        if (idx > ((1ULL << params->full_height) - 1))
            return -2; // We already used all one-time keys
        if ((params->full_height == 64) && (idx == ((1ULL << params->full_height) - 1))) 
                return -2; // We already used all one-time keys
    }
    
    memcpy(sm, sk, params->index_bytes);

    /*************************************************************************
     * THIS IS WHERE PRODUCTION IMPLEMENTATIONS WOULD UPDATE THE SECRET KEY. *
     *************************************************************************/
    /* Increment the index in the secret key. */
    ull_to_bytes(sk, params->index_bytes, idx + 1);

    /* Compute the digest randomization value. */
    const uint32_t prf_msg_start_ms = xmssmt_core_hooks_time_now_ms();
    ull_to_bytes(idx_bytes_32, 32, idx);
    prf(params, sm + params->index_bytes, idx_bytes_32, sk_prf);

    /* Compute the message hash. */
    hash_message(params, mhash, sm + params->index_bytes, pub_root, idx,
                 sm + params->sig_bytes - params->padding_len - 3*params->n,
                 mlen);
    xmssmt_core_hooks_sign_timing_note_prf_msg(prf_msg_start_ms);
    sm += params->index_bytes + params->n;

    set_type(ots_addr, XMSS_ADDR_TYPE_OTS);

    for (i = 0; i < params->d; i++) {
        idx_leaf = (idx & ((1 << params->tree_height)-1));
        idx = idx >> params->tree_height;

        set_layer_addr(ots_addr, i);
        set_tree_addr(ots_addr, idx);
        set_ots_addr(ots_addr, idx_leaf);

        /* Compute a WOTS signature. */
        /* Initially, root = mhash, but on subsequent iterations it is the root
           of the subtree below the currently processed subtree. */
        const uint32_t wots_start_ms = xmssmt_core_hooks_time_now_ms();
        wots_sign(params, sm, root, sk_seed, pub_seed, ots_addr);
        xmssmt_core_hooks_sign_timing_note_wots(wots_start_ms);
        sm += params->wots_sig_bytes;

        /* Compute the authentication path for the used WOTS leaf. */
        const uint32_t treehash_start_ms = xmssmt_core_hooks_time_now_ms();
        uint32_t cache_build_ms = 0u;
        int cache_hit = 0;
        if (xmssmt_core_hooks_cached_auth_path(params,
                                               sk_seed,
                                               pub_seed,
                                               i,
                                               idx,
                                               idx_leaf,
                                               root,
                                               sm,
                                               &cache_build_ms,
                                               &cache_hit) != 0) {
            treehash(params, root, sm, sk_seed, pub_seed, idx_leaf, ots_addr);
        }
        xmssmt_core_hooks_sign_timing_note_treehash(treehash_start_ms, cache_build_ms, cache_hit);
        sm += params->tree_height*params->n;
    }

    xmssmt_core_hooks_sign_timing_end(sign_start_ms);

    return 0;
}
