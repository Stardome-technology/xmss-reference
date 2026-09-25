#include "xmss_resumable.h"

#include <string.h>

#include "hash.h"
#include "hash_address.h"
#include "utils.h"
#include "wots.h"
#include "xmss_commons.h"
#include "xmss_workspace.h"

typedef enum {
    PHASE_PRF = 0,
    PHASE_H_MSG,
    PHASE_LAYER,
    PHASE_WOTS,
    PHASE_TREE_INIT,
    PHASE_TREE_LEAF,
    PHASE_TREE_COMBINE,
    PHASE_DONE,
    PHASE_FAILED,
    PHASE_CANCELLED
} sign_phase_t;

typedef enum {
    KEYGEN_LEAF = 0,
    KEYGEN_COMBINE,
    KEYGEN_DONE,
    KEYGEN_FAILED,
    KEYGEN_CANCELLED
} keygen_phase_t;

struct xmssmt_keygen_state {
    xmss_params params;
    const xmss_accel_provider_t *provider;
    unsigned char *caller_pk;
    unsigned char *caller_sk;
    unsigned char staging_pk[2U * XMSS_WS_MAX_N];
    unsigned char staging_sk[8U + 4U * XMSS_WS_MAX_N];
    unsigned char stack[XMSS_WS_TREEHASH_STACK_BYTES];
    unsigned int heights[XMSS_WS_MAX_TREE_HEIGHT + 1U];
    unsigned int stack_offset;
    uint32_t tree_leaf;
    uint32_t tree_index;
    uint32_t ots_addr[8];
    uint32_t ltree_addr[8];
    uint32_t node_addr[8];
    keygen_phase_t phase;
    unsigned int primitive_count;
};

typedef char keygen_state_storage_must_fit[
    sizeof(struct xmssmt_keygen_state) <= sizeof(xmssmt_keygen_state_storage_t)
        ? 1 : -1];

struct xmssmt_sign_state {
    xmss_params params;
    const xmss_accel_provider_t *provider;
    unsigned char *sk;
    unsigned char *sm;
    const unsigned char *message;
    unsigned long long message_length;
    unsigned long long final_length;
    uint64_t original_index;
    uint64_t remaining_tree;
    size_t signature_offset;
    unsigned int layer;
    uint32_t leaf_index;
    sign_phase_t phase;
    unsigned int primitive_count;
    unsigned char root[XMSS_WS_MAX_N];
    unsigned char index_bytes_32[32];
    unsigned char stack[XMSS_WS_TREEHASH_STACK_BYTES];
    unsigned int heights[XMSS_WS_MAX_TREE_HEIGHT + 1U];
    unsigned int stack_offset;
    uint32_t tree_leaf;
    uint32_t tree_index;
    uint32_t ots_addr[8];
    uint32_t ltree_addr[8];
    uint32_t node_addr[8];
};

typedef char state_storage_must_fit[
    sizeof(struct xmssmt_sign_state) <= sizeof(xmssmt_sign_state_storage_t)
        ? 1 : -1];

typedef enum {
    VERIFY_PHASE_H_MSG = 0,
    VERIFY_PHASE_LAYER,
    VERIFY_PHASE_WOTS,
    VERIFY_PHASE_L_TREE,
    VERIFY_PHASE_ROOT,
    VERIFY_PHASE_COMPARE,
    VERIFY_PHASE_DONE,
    VERIFY_PHASE_FAILED,
    VERIFY_PHASE_CANCELLED
} verify_phase_t;

/*
 * Caller-owned cooperative XMSSMT verification state.
 *
 * The verifier owns the full verify dataflow: one H_MSG, then for each of d
 * layers 67 WOTS chain recoveries, 66 L-tree THASH_H reductions, and five
 * authentication-path THASH_H operations. Each step performs at most one
 * provider primitive or one bounded local transition. The canonical
 * accelerated walk completes exactly 1 + 8*(67 + 66 + 5) = 1105 provider
 * primitives and never issues a THASH_F primitive.
 *
 * PENDING leaves every phase index, output pointer, address, and the
 * primitive count unchanged so the next step repeats the identical visit.
 * NOT_HANDLED performs the matching software primitive and advances once.
 * ERROR fails terminally without software fallback.
 */
struct xmssmt_verify_state {
    xmss_params params;
    const xmss_accel_provider_t *provider;
    unsigned char *recovered_message;
    size_t recovered_message_capacity;
    const unsigned char *signed_message;
    size_t signed_message_length;
    const unsigned char *public_key;
    unsigned long long message_length;
    unsigned long long final_length;
    uint64_t original_index;
    uint64_t remaining_tree;
    size_t signature_offset;
    unsigned int layer;
    uint32_t leaf_index;
    verify_phase_t phase;
    unsigned int primitive_count;
    int accepted;
    unsigned char root[XMSS_WS_MAX_N];
    unsigned char digest[XMSS_WS_MAX_N];
    unsigned char wots_pk[XMSS_WS_WOTS_SIG_BYTES];
    unsigned char node[XMSS_WS_MAX_N];
    unsigned char sibling[XMSS_WS_MAX_N];
    unsigned char chain_lengths[XMSS_WS_MAX_WOTS_LEN];
    unsigned char h_msg_prefix[XMSS_WS_MAX_PADDING_LEN + 3U * XMSS_WS_MAX_N +
                               XMSS_WS_MAX_MSG_LEN];
    unsigned int chain;
    unsigned int ltree_level;
    unsigned int ltree_pair;
    unsigned int ltree_count;
    unsigned int row_pairs;
    int row_odd;
    unsigned int root_height;
    uint32_t ots_addr[8];
    uint32_t ltree_addr[8];
    uint32_t node_addr[8];
};

typedef char verify_state_storage_must_fit[
    sizeof(struct xmssmt_verify_state) <= sizeof(xmssmt_verify_state_storage_t)
        ? 1 : -1];

/* Use volatile stores so secret cleanup is not removed as a dead memset. */
static void secure_zero(void *memory, size_t length)
{
    volatile unsigned char *p = (volatile unsigned char *)memory;
    while (length-- != 0U) *p++ = 0U;
}

static void sign_clear_sensitive(struct xmssmt_sign_state *s)
{
    secure_zero(s->root, sizeof(s->root));
    secure_zero(s->index_bytes_32, sizeof(s->index_bytes_32));
    secure_zero(s->stack, sizeof(s->stack));
    secure_zero(s->heights, sizeof(s->heights));
}

static void keygen_clear_sensitive(struct xmssmt_keygen_state *s)
{
    secure_zero(s->staging_sk, sizeof(s->staging_sk));
    secure_zero(s->stack, sizeof(s->stack));
    secure_zero(s->heights, sizeof(s->heights));
}

static int supported(const xmss_params *p)
{
    return p != NULL && p->n <= XMSS_WS_MAX_N &&
           p->tree_height <= XMSS_WS_MAX_TREE_HEIGHT &&
           p->wots_len <= XMSS_WS_MAX_WOTS_LEN && p->full_height < 64U;
}

static int cancelled(struct xmssmt_sign_state *s)
{
    return s->provider != NULL && s->provider->cancel_requested != NULL &&
           s->provider->cancel_requested(s->provider->context) != 0;
}

static void progress(struct xmssmt_sign_state *s)
{
    if (s->provider != NULL && s->provider->progress != NULL) {
        s->provider->progress(s->provider->context, s->primitive_count,
                              s->layer, s->tree_leaf);
    }
}

static xmss_resumable_result_t primitive_result(
    struct xmssmt_sign_state *s, xmss_accel_result_t result)
{
    if (result == XMSS_ACCEL_PENDING) return XMSS_RESUMABLE_MORE;
    if (result == XMSS_ACCEL_ERROR) {
        sign_clear_sensitive(s);
        s->phase = PHASE_FAILED;
        return XMSS_RESUMABLE_ERROR;
    }
    ++s->primitive_count;
    progress(s);
    return XMSS_RESUMABLE_MORE;
}

int xmssmt_sign_init(
    xmssmt_sign_state_storage_t *storage, const xmss_params *params,
    const xmss_accel_provider_t *provider, unsigned char *working_sk,
    unsigned char *signed_message, size_t signed_message_capacity,
    const unsigned char *message, unsigned long long message_length,
    xmssmt_sign_state_t **state)
{
    struct xmssmt_sign_state *s;
    uint64_t index;
    if (storage == NULL || !supported(params) || working_sk == NULL ||
        signed_message == NULL || message == NULL || state == NULL ||
        message_length > SIZE_MAX - params->sig_bytes ||
        signed_message_capacity < params->sig_bytes + (size_t)message_length) {
        return -1;
    }
    index = bytes_to_ull(working_sk, params->index_bytes);
    if (index >= (1ULL << params->full_height) - 1ULL) return -2;
    memset(storage, 0, sizeof(*storage));
    s = (struct xmssmt_sign_state *)(void *)storage->bytes;
    s->params = *params;
    s->provider = provider;
    s->sk = working_sk;
    s->sm = signed_message;
    s->message = message;
    s->message_length = message_length;
    s->final_length = params->sig_bytes + message_length;
    s->original_index = index;
    s->remaining_tree = index;
    memcpy(signed_message + params->sig_bytes, message, (size_t)message_length);
    ull_to_bytes(signed_message, params->index_bytes, index);
    ull_to_bytes(working_sk, params->index_bytes, index + 1ULL);
    ull_to_bytes(s->index_bytes_32, sizeof(s->index_bytes_32), index);
    s->signature_offset = params->index_bytes;
    s->phase = PHASE_PRF;
    *state = s;
    return 0;
}

xmss_resumable_result_t xmssmt_sign_step(xmssmt_sign_state_t *state)
{
    struct xmssmt_sign_state *s = state;
    const xmss_params *p;
    const unsigned char *sk_seed;
    const unsigned char *sk_prf;
    const unsigned char *pub_root;
    const unsigned char *pub_seed;
    xmss_accel_result_t accelerated;
    if (s == NULL) return XMSS_RESUMABLE_ERROR;
    if (s->phase == PHASE_DONE) return XMSS_RESUMABLE_DONE;
    if (s->phase == PHASE_FAILED) return XMSS_RESUMABLE_ERROR;
    if (s->phase == PHASE_CANCELLED) return XMSS_RESUMABLE_CANCELLED;
    if (cancelled(s)) {
        if (s->provider != NULL && s->provider->abort != NULL)
            s->provider->abort(s->provider->context);
        sign_clear_sensitive(s);
        s->phase = PHASE_CANCELLED;
        return XMSS_RESUMABLE_CANCELLED;
    }
    p = &s->params;
    sk_seed = s->sk + p->index_bytes;
    sk_prf = sk_seed + p->n;
    pub_root = sk_prf + p->n;
    pub_seed = pub_root + p->n;

    switch (s->phase) {
    case PHASE_PRF:
        accelerated = xmss_accel_try_prf(
            s->provider, p, s->sm + p->index_bytes,
            s->index_bytes_32, sk_prf);
        if (accelerated == XMSS_ACCEL_PENDING) return XMSS_RESUMABLE_MORE;
        if (accelerated == XMSS_ACCEL_NOT_HANDLED &&
            prf(p, s->sm + p->index_bytes, s->index_bytes_32, sk_prf) != 0)
            accelerated = XMSS_ACCEL_ERROR;
        s->phase = accelerated == XMSS_ACCEL_ERROR ? PHASE_FAILED : PHASE_H_MSG;
        return primitive_result(s, accelerated);

    case PHASE_H_MSG:
        accelerated = xmss_accel_try_h_msg(
            s->provider, p, s->root, s->sm + p->index_bytes, pub_root,
            s->original_index, s->message, s->message_length);
        if (accelerated == XMSS_ACCEL_PENDING) return XMSS_RESUMABLE_MORE;
        if (accelerated == XMSS_ACCEL_NOT_HANDLED) {
            if (hash_message(p, s->root, s->sm + p->index_bytes, pub_root,
                             s->original_index,
                             s->sm + p->sig_bytes - p->padding_len - 3U*p->n,
                             s->message_length) != 0)
                accelerated = XMSS_ACCEL_ERROR;
        }
        s->signature_offset = p->index_bytes + p->n;
        s->phase = accelerated == XMSS_ACCEL_ERROR ? PHASE_FAILED : PHASE_LAYER;
        return primitive_result(s, accelerated);

    case PHASE_LAYER:
        if (s->layer >= p->d) {
            s->phase = PHASE_DONE;
            return XMSS_RESUMABLE_DONE;
        }
        s->leaf_index = (uint32_t)(s->remaining_tree &
            (((uint64_t)1U << p->tree_height) - 1U));
        s->remaining_tree >>= p->tree_height;
        memset(s->ots_addr, 0, sizeof(s->ots_addr));
        set_type(s->ots_addr, XMSS_ADDR_TYPE_OTS);
        set_layer_addr(s->ots_addr, s->layer);
        set_tree_addr(s->ots_addr, s->remaining_tree);
        set_ots_addr(s->ots_addr, s->leaf_index);
        s->phase = PHASE_WOTS;
        return XMSS_RESUMABLE_MORE;

    case PHASE_WOTS:
        accelerated = xmss_accel_try_wots_sign(
            s->provider, p, s->sm + s->signature_offset, s->root,
            sk_seed, pub_seed, s->ots_addr);
        if (accelerated == XMSS_ACCEL_PENDING) return XMSS_RESUMABLE_MORE;
        if (accelerated == XMSS_ACCEL_NOT_HANDLED) {
            wots_sign(p, s->sm + s->signature_offset, s->root,
                      sk_seed, pub_seed, s->ots_addr);
        }
        if (accelerated == XMSS_ACCEL_ERROR)
            return primitive_result(s, accelerated);
        s->signature_offset += p->wots_sig_bytes;
        s->phase = PHASE_TREE_INIT;
        return primitive_result(s, accelerated);

    case PHASE_TREE_INIT:
        memset(s->ots_addr, 0, sizeof(s->ots_addr));
        memset(s->ltree_addr, 0, sizeof(s->ltree_addr));
        memset(s->node_addr, 0, sizeof(s->node_addr));
        set_layer_addr(s->ots_addr, s->layer);
        set_tree_addr(s->ots_addr, s->remaining_tree);
        copy_subtree_addr(s->ltree_addr, s->ots_addr);
        copy_subtree_addr(s->node_addr, s->ots_addr);
        set_type(s->ots_addr, XMSS_ADDR_TYPE_OTS);
        set_type(s->ltree_addr, XMSS_ADDR_TYPE_LTREE);
        set_type(s->node_addr, XMSS_ADDR_TYPE_HASHTREE);
        s->tree_leaf = 0;
        s->stack_offset = 0;
        s->phase = PHASE_TREE_LEAF;
        return XMSS_RESUMABLE_MORE;

    case PHASE_TREE_LEAF:
        set_ltree_addr(s->ltree_addr, s->tree_leaf);
        set_ots_addr(s->ots_addr, s->tree_leaf);
        accelerated = xmss_accel_try_gen_leaf(
            s->provider, p, s->stack + s->stack_offset*p->n,
            sk_seed, pub_seed, s->ltree_addr, s->ots_addr);
        if (accelerated == XMSS_ACCEL_PENDING) return XMSS_RESUMABLE_MORE;
        if (accelerated == XMSS_ACCEL_NOT_HANDLED) {
            gen_leaf_wots(p, s->stack + s->stack_offset*p->n,
                          sk_seed, pub_seed, s->ltree_addr, s->ots_addr);
        }
        if (accelerated == XMSS_ACCEL_ERROR)
            return primitive_result(s, accelerated);
        ++s->stack_offset;
        s->heights[s->stack_offset - 1U] = 0;
        if ((s->leaf_index ^ 1U) == s->tree_leaf)
            memcpy(s->sm + s->signature_offset,
                   s->stack + (s->stack_offset - 1U)*p->n, p->n);
        s->phase = PHASE_TREE_COMBINE;
        return primitive_result(s, accelerated);

    case PHASE_TREE_COMBINE:
        if (s->stack_offset >= 2U &&
            s->heights[s->stack_offset - 1U] ==
            s->heights[s->stack_offset - 2U]) {
            unsigned int height = s->heights[s->stack_offset - 1U];
            s->tree_index = s->tree_leaf >> (height + 1U);
            set_tree_height(s->node_addr, height);
            set_tree_index(s->node_addr, s->tree_index);
            accelerated = xmss_accel_try_thash_h(
                s->provider, p, s->stack + (s->stack_offset - 2U)*p->n,
                s->stack + (s->stack_offset - 2U)*p->n,
                pub_seed, s->node_addr);
            if (accelerated == XMSS_ACCEL_PENDING)
                return XMSS_RESUMABLE_MORE;
            if (accelerated == XMSS_ACCEL_NOT_HANDLED &&
                thash_h(p, s->stack + (s->stack_offset - 2U)*p->n,
                        s->stack + (s->stack_offset - 2U)*p->n,
                        pub_seed, s->node_addr) != 0)
                accelerated = XMSS_ACCEL_ERROR;
            if (accelerated == XMSS_ACCEL_ERROR)
                return primitive_result(s, accelerated);
            --s->stack_offset;
            ++s->heights[s->stack_offset - 1U];
            if (((s->leaf_index >> s->heights[s->stack_offset - 1U]) ^ 1U)
                == s->tree_index) {
                memcpy(s->sm + s->signature_offset +
                       s->heights[s->stack_offset - 1U]*p->n,
                       s->stack + (s->stack_offset - 1U)*p->n, p->n);
            }
            return primitive_result(s, accelerated);
        }
        ++s->tree_leaf;
        if (s->tree_leaf < ((uint32_t)1U << p->tree_height)) {
            s->phase = PHASE_TREE_LEAF;
            return XMSS_RESUMABLE_MORE;
        }
        if (s->stack_offset != 1U || s->heights[0] != p->tree_height) {
            sign_clear_sensitive(s);
            s->phase = PHASE_FAILED;
            return XMSS_RESUMABLE_ERROR;
        }
        memcpy(s->root, s->stack, p->n);
        s->signature_offset += p->tree_height*p->n;
        ++s->layer;
        s->phase = PHASE_LAYER;
        return XMSS_RESUMABLE_MORE;

    default:
        sign_clear_sensitive(s);
        s->phase = PHASE_FAILED;
        return XMSS_RESUMABLE_ERROR;
    }
}

int xmssmt_sign_finish(xmssmt_sign_state_t *state,
                       unsigned long long *signed_message_length)
{
    if (state == NULL || signed_message_length == NULL ||
        state->phase != PHASE_DONE) return -1;
    *signed_message_length = state->final_length;
    sign_clear_sensitive(state);
    return 0;
}

void xmssmt_sign_abort(xmssmt_sign_state_t *state)
{
    if (state != NULL && state->phase != PHASE_DONE) {
        if (state->provider != NULL && state->provider->abort != NULL)
            state->provider->abort(state->provider->context);
        sign_clear_sensitive(state);
        state->phase = PHASE_CANCELLED;
    }
}

unsigned int xmssmt_sign_primitive_count(const xmssmt_sign_state_t *state)
{
    return state == NULL ? 0U : state->primitive_count;
}

/* ------------------------------------------------------------------ */
/* Cooperative XMSSMT verification                                     */
/* ------------------------------------------------------------------ */

static int verify_cancelled(struct xmssmt_verify_state *s)
{
    return s->provider != NULL && s->provider->cancel_requested != NULL &&
           s->provider->cancel_requested(s->provider->context) != 0;
}

static void verify_progress(struct xmssmt_verify_state *s)
{
    if (s->provider != NULL && s->provider->progress != NULL) {
        s->provider->progress(s->provider->context, s->primitive_count,
                              s->layer, s->leaf_index);
    }
}

static xmss_resumable_result_t verify_primitive_result(
    struct xmssmt_verify_state *s, xmss_accel_result_t result)
{
    if (result == XMSS_ACCEL_PENDING) return XMSS_RESUMABLE_MORE;
    if (result == XMSS_ACCEL_ERROR) {
        s->phase = VERIFY_PHASE_FAILED;
        return XMSS_RESUMABLE_ERROR;
    }
    ++s->primitive_count;
    verify_progress(s);
    return XMSS_RESUMABLE_MORE;
}

/* base_w with WOTS_LOG_W = 4 (the only supported Winternitz parameter). */
static void verify_base_w(unsigned char *out, unsigned int output_len,
                          const unsigned char *input_bytes)
{
    unsigned int in_idx = 0U;
    unsigned int bits = 0U;
    unsigned int total = 0U;
    unsigned int o;
    for (o = 0U; o < output_len; ++o) {
        if (bits == 0U) {
            total = input_bytes[in_idx];
            ++in_idx;
            bits += 8U;
        }
        bits -= 4U;
        out[o] = (unsigned char)((total >> bits) & 0x0FU);
    }
}

/*
 * Software WOTS chain segment (mirrors the reference gen_chain). Interprets
 * `in` as the start-th value of the chain and applies `steps` THASH_F
 * iterations. Used only when the provider returns NOT_HANDLED.
 */
static void gen_chain_sw(const xmss_params *params, unsigned char *out,
                         const unsigned char *in, unsigned int start,
                         unsigned int steps, const unsigned char *pub_seed,
                         uint32_t addr[8])
{
    unsigned int i;
    memcpy(out, in, params->n);
    for (i = start; i < start + steps && i < params->wots_w; ++i) {
        set_hash_addr(addr, i);
        if (thash_f(params, out, out, pub_seed, addr) != 0) break;
    }
}

/* WOTS chain lengths: base_w of the 32-byte message plus the checksum. */
static void verify_chain_lengths(struct xmssmt_verify_state *s,
                                 const unsigned char *msg)
{
    unsigned int i;
    unsigned int csum = 0U;
    unsigned char csum_bytes[2];
    verify_base_w(s->chain_lengths, s->params.wots_len1, msg);
    for (i = 0U; i < s->params.wots_len1; ++i)
        csum += s->params.wots_w - 1U - s->chain_lengths[i];
    csum <<= 8U - ((s->params.wots_len2 * s->params.wots_log_w) % 8U);
    csum &= 0xFFFFU;
    csum_bytes[0] = (unsigned char)(csum >> 8);
    csum_bytes[1] = (unsigned char)csum;
    verify_base_w(s->chain_lengths + s->params.wots_len1,
                  s->params.wots_len2, csum_bytes);
}

/* Per-layer geometry: leaf(L) = (idx >> 5L) & 31, tree(L) = idx >> 5(L+1). */
static void verify_layer_geometry(const struct xmssmt_verify_state *s,
                                  unsigned int layer,
                                  uint32_t *leaf, uint64_t *tree)
{
    unsigned int shift = s->params.tree_height * layer;
    *leaf = (uint32_t)((s->original_index >> shift) &
                       (((uint64_t)1U << s->params.tree_height) - 1U));
    *tree = s->original_index >> (shift + s->params.tree_height);
}

static void verify_set_ots_addr(struct xmssmt_verify_state *s,
                                unsigned int layer, uint64_t tree,
                                uint32_t leaf, uint32_t chain)
{
    memset(s->ots_addr, 0, sizeof(s->ots_addr));
    set_type(s->ots_addr, XMSS_ADDR_TYPE_OTS);
    set_layer_addr(s->ots_addr, layer);
    set_tree_addr(s->ots_addr, tree);
    set_ots_addr(s->ots_addr, leaf);
    set_chain_addr(s->ots_addr, chain);
}

static void verify_set_ltree_addr(struct xmssmt_verify_state *s,
                                  unsigned int layer, uint64_t tree,
                                  uint32_t leaf, uint32_t height,
                                  uint32_t index)
{
    memset(s->ltree_addr, 0, sizeof(s->ltree_addr));
    set_type(s->ltree_addr, XMSS_ADDR_TYPE_LTREE);
    set_layer_addr(s->ltree_addr, layer);
    set_tree_addr(s->ltree_addr, tree);
    set_ltree_addr(s->ltree_addr, leaf);
    set_tree_height(s->ltree_addr, height);
    set_tree_index(s->ltree_addr, index);
}

static void verify_set_node_addr(struct xmssmt_verify_state *s,
                                 unsigned int layer, uint64_t tree,
                                 uint32_t height, uint32_t index)
{
    memset(s->node_addr, 0, sizeof(s->node_addr));
    set_type(s->node_addr, XMSS_ADDR_TYPE_HASHTREE);
    set_layer_addr(s->node_addr, layer);
    set_tree_addr(s->node_addr, tree);
    set_tree_height(s->node_addr, height);
    set_tree_index(s->node_addr, index);
}

int xmssmt_verify_init(
    xmssmt_verify_state_storage_t *storage, const xmss_params *params,
    const xmss_accel_provider_t *provider, unsigned char *recovered_message,
    size_t recovered_message_capacity, const unsigned char *signed_message,
    size_t signed_message_length, const unsigned char *public_key,
    size_t public_key_length, xmssmt_verify_state_t **state)
{
    struct xmssmt_verify_state *s;
    unsigned int i;
    if (storage == NULL || !supported(params) || params->d == 0U ||
        recovered_message == NULL || signed_message == NULL ||
        public_key == NULL || state == NULL) return -1;
    if (signed_message_length < params->sig_bytes) return -1;
    if (public_key_length != 2U * params->n) return -1;
    if (recovered_message_capacity <
        signed_message_length - params->sig_bytes) return -1;
    memset(storage, 0, sizeof(*storage));
    s = (struct xmssmt_verify_state *)(void *)storage->bytes;
    s->params = *params;
    s->provider = provider;
    s->recovered_message = recovered_message;
    s->recovered_message_capacity = recovered_message_capacity;
    s->signed_message = signed_message;
    s->signed_message_length = signed_message_length;
    s->public_key = public_key;
    s->message_length = signed_message_length - params->sig_bytes;
    s->final_length = s->message_length;
    s->original_index = bytes_to_ull(signed_message, params->index_bytes);
    if (s->original_index >= (1ULL << params->full_height)) return -2;
    s->remaining_tree = s->original_index;
    s->signature_offset = params->index_bytes;
    s->phase = VERIFY_PHASE_H_MSG;
    for (i = 0U; i < params->wots_len; ++i) s->chain_lengths[i] = 0U;
    *state = s;
    return 0;
}

xmss_resumable_result_t xmssmt_verify_step(xmssmt_verify_state_t *state)
{
    struct xmssmt_verify_state *s = state;
    const xmss_params *p;
    const unsigned char *pub_root;
    const unsigned char *pub_seed;
    xmss_accel_result_t accelerated;
    if (s == NULL) return XMSS_RESUMABLE_ERROR;
    if (s->phase == VERIFY_PHASE_DONE) return XMSS_RESUMABLE_DONE;
    if (s->phase == VERIFY_PHASE_FAILED) return XMSS_RESUMABLE_ERROR;
    if (s->phase == VERIFY_PHASE_CANCELLED) return XMSS_RESUMABLE_CANCELLED;
    if (verify_cancelled(s)) {
        if (s->provider != NULL && s->provider->abort != NULL)
            s->provider->abort(s->provider->context);
        s->phase = VERIFY_PHASE_CANCELLED;
        return XMSS_RESUMABLE_CANCELLED;
    }
    p = &s->params;
    pub_root = s->public_key;
    pub_seed = s->public_key + p->n;

    switch (s->phase) {
    case VERIFY_PHASE_H_MSG: {
        unsigned char *mhash = s->digest;
        accelerated = xmss_accel_try_h_msg(
            s->provider, p, mhash, s->signed_message + p->index_bytes,
            pub_root, s->original_index,
            s->signed_message + p->sig_bytes, s->message_length);
        if (accelerated == XMSS_ACCEL_PENDING) return XMSS_RESUMABLE_MORE;
        if (accelerated == XMSS_ACCEL_NOT_HANDLED) {
            unsigned char *prefix = s->h_msg_prefix;
            if (s->message_length > XMSS_WS_MAX_MSG_LEN)
                accelerated = XMSS_ACCEL_ERROR;
            else {
                memcpy(prefix + p->padding_len + 3U * p->n,
                       s->signed_message + p->sig_bytes,
                       (size_t)s->message_length);
                if (hash_message(p, mhash,
                                 s->signed_message + p->index_bytes,
                                 pub_root, s->original_index, prefix,
                                 s->message_length) != 0)
                    accelerated = XMSS_ACCEL_ERROR;
            }
        }
        if (accelerated == XMSS_ACCEL_ERROR)
            return verify_primitive_result(s, accelerated);
        verify_chain_lengths(s, mhash);
        s->signature_offset = p->index_bytes + p->n;
        s->layer = 0U;
        s->phase = VERIFY_PHASE_LAYER;
        return verify_primitive_result(s, accelerated);
    }

    case VERIFY_PHASE_LAYER: {
        uint32_t leaf;
        uint64_t tree;
        if (s->layer >= p->d) {
            s->phase = VERIFY_PHASE_COMPARE;
            return XMSS_RESUMABLE_MORE;
        }
        verify_layer_geometry(s, s->layer, &leaf, &tree);
        s->leaf_index = leaf;
        s->remaining_tree = tree;
        s->chain = 0U;
        s->phase = VERIFY_PHASE_WOTS;
        return XMSS_RESUMABLE_MORE;
    }

    case VERIFY_PHASE_WOTS: {
        uint32_t leaf;
        uint64_t tree;
        unsigned int digit;
        const unsigned char *sig_word;
        verify_layer_geometry(s, s->layer, &leaf, &tree);
        digit = s->chain_lengths[s->chain];
        sig_word = s->signed_message + s->signature_offset +
                   (size_t)s->chain * p->n;
        verify_set_ots_addr(s, s->layer, tree, leaf, s->chain);
        accelerated = xmss_accel_try_wots_chain(
            s->provider, p, s->wots_pk + (size_t)s->chain * p->n,
            sig_word, pub_seed, s->ots_addr, digit,
            p->wots_w - 1U - digit);
        if (accelerated == XMSS_ACCEL_PENDING) return XMSS_RESUMABLE_MORE;
        if (accelerated == XMSS_ACCEL_NOT_HANDLED) {
            uint32_t address[8];
            memcpy(address, s->ots_addr, sizeof(address));
            set_chain_addr(address, s->chain);
            gen_chain_sw(p, s->wots_pk + (size_t)s->chain * p->n,
                         sig_word, digit, p->wots_w - 1U - digit,
                         pub_seed, address);
        }
        if (accelerated == XMSS_ACCEL_ERROR)
            return verify_primitive_result(s, accelerated);
        ++s->chain;
        if (s->chain == p->wots_len) {
            s->phase = VERIFY_PHASE_L_TREE;
            s->ltree_level = 0U;
            s->ltree_pair = 0U;
            s->ltree_count = p->wots_len;
            s->row_odd = (p->wots_len & 1U) != 0U;
        }
        return verify_primitive_result(s, accelerated);
    }

    case VERIFY_PHASE_L_TREE: {
        uint32_t leaf;
        uint64_t tree;
        unsigned int parent_nodes;
        verify_layer_geometry(s, s->layer, &leaf, &tree);
        if (s->ltree_count == 1U) {
            memcpy(s->node, s->wots_pk, p->n);
            memcpy(s->sibling,
                   s->signed_message + s->signature_offset +
                       p->wots_sig_bytes, p->n);
            s->root_height = 0U;
            s->phase = VERIFY_PHASE_ROOT;
            return XMSS_RESUMABLE_MORE;
        }
        parent_nodes = s->ltree_count >> 1;
        if (s->ltree_pair == 0U) {
            /* Row start: capture the row's pair count. */
            s->row_pairs = parent_nodes;
        }
        if (parent_nodes == 0U) {
            /* Odd row tail: pull the last node up without a hash. */
            memcpy(s->wots_pk + (size_t)(s->ltree_count >> 1) * p->n,
                   s->wots_pk + (size_t)(s->ltree_count - 1U) * p->n, p->n);
            s->ltree_count = (s->ltree_count >> 1) + 1U;
            ++s->ltree_level;
            s->ltree_pair = 0U;
            s->row_odd = (s->ltree_count & 1U) != 0U;
            return XMSS_RESUMABLE_MORE;
        }
        verify_set_ltree_addr(s, s->layer, tree, leaf, s->ltree_level,
                              s->ltree_pair);
        accelerated = xmss_accel_try_thash_h(
            s->provider, p, s->wots_pk + (size_t)s->ltree_pair * p->n,
            s->wots_pk + (size_t)(2U * s->ltree_pair) * p->n,
            pub_seed, s->ltree_addr);
        if (accelerated == XMSS_ACCEL_PENDING) return XMSS_RESUMABLE_MORE;
        if (accelerated == XMSS_ACCEL_NOT_HANDLED) {
            uint32_t address[8];
            memcpy(address, s->ltree_addr, sizeof(address));
            if (thash_h(p, s->wots_pk + (size_t)s->ltree_pair * p->n,
                        s->wots_pk + (size_t)(2U * s->ltree_pair) * p->n,
                        pub_seed, address) != 0)
                accelerated = XMSS_ACCEL_ERROR;
        }
        if (accelerated == XMSS_ACCEL_ERROR)
            return verify_primitive_result(s, accelerated);
        ++s->ltree_pair;
        if ((size_t)(2U * s->ltree_pair) >=
            (size_t)s->ltree_count - (s->row_odd ? 1U : 0U)) {
            if (s->row_odd) {
                memcpy(s->wots_pk + (size_t)s->ltree_pair * p->n,
                       s->wots_pk + (size_t)(s->ltree_count - 1U) * p->n,
                       p->n);
            }
            s->ltree_count = s->ltree_pair + (s->row_odd ? 1U : 0U);
            ++s->ltree_level;
            s->ltree_pair = 0U;
            s->row_odd = (s->ltree_count & 1U) != 0U;
        }
        return verify_primitive_result(s, accelerated);
    }

    case VERIFY_PHASE_ROOT: {
        uint32_t leaf;
        uint64_t tree;
        unsigned char pair[2U * XMSS_WS_MAX_N];
        verify_layer_geometry(s, s->layer, &leaf, &tree);
        verify_set_node_addr(s, s->layer, tree, s->root_height,
                             leaf >> (s->root_height + 1U));
        if (((leaf >> s->root_height) & 1U) != 0U) {
            memcpy(pair, s->sibling, p->n);
            memcpy(pair + p->n, s->node, p->n);
        } else {
            memcpy(pair, s->node, p->n);
            memcpy(pair + p->n, s->sibling, p->n);
        }
        accelerated = xmss_accel_try_thash_h(
            s->provider, p, s->node, pair, pub_seed, s->node_addr);
        if (accelerated == XMSS_ACCEL_PENDING) return XMSS_RESUMABLE_MORE;
        if (accelerated == XMSS_ACCEL_NOT_HANDLED) {
            uint32_t address[8];
            memcpy(address, s->node_addr, sizeof(address));
            if (thash_h(p, s->node, pair, pub_seed, address) != 0)
                accelerated = XMSS_ACCEL_ERROR;
        }
        if (accelerated == XMSS_ACCEL_ERROR)
            return verify_primitive_result(s, accelerated);
        ++s->root_height;
        if (s->root_height >= p->tree_height) {
            memcpy(s->digest, s->node, p->n);
            ++s->layer;
            s->signature_offset += p->wots_sig_bytes + p->tree_height * p->n;
            if (s->layer >= p->d) {
                s->phase = VERIFY_PHASE_COMPARE;
            } else {
                s->phase = VERIFY_PHASE_LAYER;
                verify_chain_lengths(s, s->digest);
            }
        } else {
            memcpy(s->sibling,
                   s->signed_message + s->signature_offset +
                       p->wots_sig_bytes + (size_t)s->root_height * p->n,
                   p->n);
        }
        return verify_primitive_result(s, accelerated);
    }

    case VERIFY_PHASE_COMPARE:
        s->accepted = (memcmp(s->node, pub_root, p->n) == 0);
        s->phase = VERIFY_PHASE_DONE;
        return XMSS_RESUMABLE_DONE;

    default:
        s->phase = VERIFY_PHASE_FAILED;
        return XMSS_RESUMABLE_ERROR;
    }
}

int xmssmt_verify_finish(xmssmt_verify_state_t *state,
                         unsigned long long *recovered_message_length)
{
    if (state == NULL || recovered_message_length == NULL ||
        state->phase != VERIFY_PHASE_DONE || !state->accepted) return -1;
    memcpy(state->recovered_message,
           state->signed_message + state->params.sig_bytes,
           (size_t)state->message_length);
    *recovered_message_length = state->message_length;
    return 0;
}

void xmssmt_verify_abort(xmssmt_verify_state_t *state)
{
    if (state != NULL && state->phase != VERIFY_PHASE_DONE) {
        if (state->provider != NULL && state->provider->abort != NULL)
            state->provider->abort(state->provider->context);
        state->phase = VERIFY_PHASE_CANCELLED;
    }
}

unsigned int xmssmt_verify_primitive_count(
    const xmssmt_verify_state_t *state)
{
    return state == NULL ? 0U : state->primitive_count;
}

static int keygen_cancelled(struct xmssmt_keygen_state *s)
{
    return s->provider != NULL && s->provider->cancel_requested != NULL &&
           s->provider->cancel_requested(s->provider->context) != 0;
}

static xmss_resumable_result_t keygen_primitive_result(
    struct xmssmt_keygen_state *s, xmss_accel_result_t result)
{
    if (result == XMSS_ACCEL_PENDING) return XMSS_RESUMABLE_MORE;
    if (result == XMSS_ACCEL_ERROR) {
        keygen_clear_sensitive(s);
        s->phase = KEYGEN_FAILED;
        return XMSS_RESUMABLE_ERROR;
    }
    ++s->primitive_count;
    if (s->provider != NULL && s->provider->progress != NULL) {
        s->provider->progress(s->provider->context, s->primitive_count,
                              s->params.d - 1U, s->tree_leaf);
    }
    return XMSS_RESUMABLE_MORE;
}

int xmssmt_keygen_init(
    xmssmt_keygen_state_storage_t *storage, const xmss_params *params,
    const xmss_accel_provider_t *provider, unsigned char *public_key,
    unsigned char *secret_key, const unsigned char *seed,
    xmssmt_keygen_state_t **state)
{
    struct xmssmt_keygen_state *s;
    unsigned char *sk_seed;
    if (storage == NULL || !supported(params) || params->d == 0U ||
        public_key == NULL || secret_key == NULL || seed == NULL ||
        state == NULL) return -1;
    memset(storage, 0, sizeof(*storage));
    s = (struct xmssmt_keygen_state *)(void *)storage->bytes;
    s->params = *params;
    s->provider = provider;
    s->caller_pk = public_key;
    s->caller_sk = secret_key;
    sk_seed = s->staging_sk + params->index_bytes;
    memcpy(sk_seed, seed, 2U * params->n);
    memcpy(sk_seed + 3U * params->n, seed + 2U * params->n, params->n);
    memcpy(s->staging_pk + params->n, seed + 2U * params->n, params->n);
    set_layer_addr(s->ots_addr, params->d - 1U);
    copy_subtree_addr(s->ltree_addr, s->ots_addr);
    copy_subtree_addr(s->node_addr, s->ots_addr);
    set_type(s->ots_addr, XMSS_ADDR_TYPE_OTS);
    set_type(s->ltree_addr, XMSS_ADDR_TYPE_LTREE);
    set_type(s->node_addr, XMSS_ADDR_TYPE_HASHTREE);
    s->phase = KEYGEN_LEAF;
    *state = s;
    return 0;
}

xmss_resumable_result_t xmssmt_keygen_step(xmssmt_keygen_state_t *state)
{
    struct xmssmt_keygen_state *s = state;
    const xmss_params *p;
    unsigned char *sk_seed;
    const unsigned char *pub_seed;
    xmss_accel_result_t accelerated;
    if (s == NULL) return XMSS_RESUMABLE_ERROR;
    if (s->phase == KEYGEN_DONE) return XMSS_RESUMABLE_DONE;
    if (s->phase == KEYGEN_FAILED) return XMSS_RESUMABLE_ERROR;
    if (s->phase == KEYGEN_CANCELLED) return XMSS_RESUMABLE_CANCELLED;
    if (keygen_cancelled(s)) {
        if (s->provider != NULL && s->provider->abort != NULL)
            s->provider->abort(s->provider->context);
        keygen_clear_sensitive(s);
        s->phase = KEYGEN_CANCELLED;
        return XMSS_RESUMABLE_CANCELLED;
    }
    p = &s->params;
    sk_seed = s->staging_sk + p->index_bytes;
    pub_seed = s->staging_pk + p->n;
    if (s->phase == KEYGEN_LEAF) {
        set_ltree_addr(s->ltree_addr, s->tree_leaf);
        set_ots_addr(s->ots_addr, s->tree_leaf);
        accelerated = xmss_accel_try_gen_leaf(
            s->provider, p, s->stack + s->stack_offset*p->n,
            sk_seed, pub_seed, s->ltree_addr, s->ots_addr);
        if (accelerated == XMSS_ACCEL_PENDING) return XMSS_RESUMABLE_MORE;
        if (accelerated == XMSS_ACCEL_NOT_HANDLED) {
            gen_leaf_wots(p, s->stack + s->stack_offset*p->n,
                          sk_seed, pub_seed, s->ltree_addr, s->ots_addr);
        }
        if (accelerated == XMSS_ACCEL_ERROR)
            return keygen_primitive_result(s, accelerated);
        ++s->stack_offset;
        s->heights[s->stack_offset - 1U] = 0U;
        s->phase = KEYGEN_COMBINE;
        return keygen_primitive_result(s, accelerated);
    }
    if (s->phase == KEYGEN_COMBINE) {
        if (s->stack_offset >= 2U &&
            s->heights[s->stack_offset - 1U] ==
            s->heights[s->stack_offset - 2U]) {
            unsigned int height = s->heights[s->stack_offset - 1U];
            s->tree_index = s->tree_leaf >> (height + 1U);
            set_tree_height(s->node_addr, height);
            set_tree_index(s->node_addr, s->tree_index);
            accelerated = xmss_accel_try_thash_h(
                s->provider, p, s->stack + (s->stack_offset - 2U)*p->n,
                s->stack + (s->stack_offset - 2U)*p->n,
                pub_seed, s->node_addr);
            if (accelerated == XMSS_ACCEL_PENDING)
                return XMSS_RESUMABLE_MORE;
            if (accelerated == XMSS_ACCEL_NOT_HANDLED &&
                thash_h(p, s->stack + (s->stack_offset - 2U)*p->n,
                        s->stack + (s->stack_offset - 2U)*p->n,
                        pub_seed, s->node_addr) != 0)
                accelerated = XMSS_ACCEL_ERROR;
            if (accelerated == XMSS_ACCEL_ERROR)
                return keygen_primitive_result(s, accelerated);
            --s->stack_offset;
            ++s->heights[s->stack_offset - 1U];
            return keygen_primitive_result(s, accelerated);
        }
        ++s->tree_leaf;
        if (s->tree_leaf < ((uint32_t)1U << p->tree_height)) {
            s->phase = KEYGEN_LEAF;
            return XMSS_RESUMABLE_MORE;
        }
        if (s->stack_offset != 1U || s->heights[0] != p->tree_height) {
            keygen_clear_sensitive(s);
            s->phase = KEYGEN_FAILED;
            return XMSS_RESUMABLE_ERROR;
        }
        memcpy(s->staging_pk, s->stack, p->n);
        memcpy(sk_seed + 2U*p->n, s->stack, p->n);
        s->phase = KEYGEN_DONE;
        return XMSS_RESUMABLE_DONE;
    }
    keygen_clear_sensitive(s);
    s->phase = KEYGEN_FAILED;
    return XMSS_RESUMABLE_ERROR;
}

int xmssmt_keygen_finish(xmssmt_keygen_state_t *state)
{
    size_t pk_bytes;
    size_t sk_bytes;
    if (state == NULL || state->phase != KEYGEN_DONE) return -1;
    pk_bytes = 2U * state->params.n;
    sk_bytes = state->params.index_bytes + 4U * state->params.n;
    memcpy(state->caller_pk, state->staging_pk, pk_bytes);
    memcpy(state->caller_sk, state->staging_sk, sk_bytes);
    keygen_clear_sensitive(state);
    return 0;
}

void xmssmt_keygen_abort(xmssmt_keygen_state_t *state)
{
    if (state != NULL && state->phase != KEYGEN_DONE) {
        if (state->provider != NULL && state->provider->abort != NULL)
            state->provider->abort(state->provider->context);
        keygen_clear_sensitive(state);
        state->phase = KEYGEN_CANCELLED;
    }
}

#ifdef XMSS_RESUMABLE_TEST_HOOKS
static int bytes_are_zero(const void *memory, size_t length)
{
    const unsigned char *bytes = (const unsigned char *)memory;
    size_t i;
    for (i = 0U; i < length; ++i)
        if (bytes[i] != 0U) return 0;
    return 1;
}

int xmssmt_keygen_test_sensitive_is_zero(
    const xmssmt_keygen_state_t *state)
{
    return state != NULL &&
           bytes_are_zero(state->staging_sk, sizeof(state->staging_sk)) &&
           bytes_are_zero(state->stack, sizeof(state->stack)) &&
           bytes_are_zero(state->heights, sizeof(state->heights));
}

int xmssmt_sign_test_sensitive_is_zero(const xmssmt_sign_state_t *state)
{
    return state != NULL &&
           bytes_are_zero(state->root, sizeof(state->root)) &&
           bytes_are_zero(state->index_bytes_32,
                          sizeof(state->index_bytes_32)) &&
           bytes_are_zero(state->stack, sizeof(state->stack)) &&
           bytes_are_zero(state->heights, sizeof(state->heights));
}
#endif

unsigned int xmssmt_keygen_primitive_count(
    const xmssmt_keygen_state_t *state)
{
    return state == NULL ? 0U : state->primitive_count;
}
