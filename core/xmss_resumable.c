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
    if (result == XMSS_ACCEL_ERROR) {
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
        if (accelerated == XMSS_ACCEL_NOT_HANDLED &&
            prf(p, s->sm + p->index_bytes, s->index_bytes_32, sk_prf) != 0)
            accelerated = XMSS_ACCEL_ERROR;
        s->phase = accelerated == XMSS_ACCEL_ERROR ? PHASE_FAILED : PHASE_H_MSG;
        return primitive_result(s, accelerated);

    case PHASE_H_MSG:
        accelerated = xmss_accel_try_h_msg(
            s->provider, p, s->root, s->sm + p->index_bytes, pub_root,
            s->original_index, s->message, s->message_length);
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
            s->phase = PHASE_FAILED;
            return XMSS_RESUMABLE_ERROR;
        }
        memcpy(s->root, s->stack, p->n);
        s->signature_offset += p->tree_height*p->n;
        ++s->layer;
        s->phase = PHASE_LAYER;
        return XMSS_RESUMABLE_MORE;

    default:
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
    return 0;
}

void xmssmt_sign_abort(xmssmt_sign_state_t *state)
{
    if (state != NULL && state->phase != PHASE_DONE)
        state->phase = PHASE_CANCELLED;
}

unsigned int xmssmt_sign_primitive_count(const xmssmt_sign_state_t *state)
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
    if (result == XMSS_ACCEL_ERROR) {
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
            s->phase = KEYGEN_FAILED;
            return XMSS_RESUMABLE_ERROR;
        }
        memcpy(s->staging_pk, s->stack, p->n);
        memcpy(sk_seed + 2U*p->n, s->stack, p->n);
        s->phase = KEYGEN_DONE;
        return XMSS_RESUMABLE_DONE;
    }
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
    memset(state->staging_sk, 0, sizeof(state->staging_sk));
    return 0;
}

void xmssmt_keygen_abort(xmssmt_keygen_state_t *state)
{
    if (state != NULL && state->phase != KEYGEN_DONE) {
        memset(state->staging_sk, 0, sizeof(state->staging_sk));
        state->phase = KEYGEN_CANCELLED;
    }
}

unsigned int xmssmt_keygen_primitive_count(
    const xmssmt_keygen_state_t *state)
{
    return state == NULL ? 0U : state->primitive_count;
}
