#include <string.h>

#include "xmss_core_hooks.h"

static xmssmt_core_hooks_t g_xmssmt_core_hooks;

void xmssmt_core_hooks_set(const xmssmt_core_hooks_t *hooks)
{
    if (hooks == NULL) {
        xmssmt_core_hooks_clear();
        return;
    }

    g_xmssmt_core_hooks = *hooks;
}

void xmssmt_core_hooks_clear(void)
{
    memset(&g_xmssmt_core_hooks, 0, sizeof(g_xmssmt_core_hooks));
}

uint32_t xmssmt_core_hooks_time_now_ms(void)
{
    if (g_xmssmt_core_hooks.time_now_ms == NULL) {
        return 0u;
    }

    return g_xmssmt_core_hooks.time_now_ms();
}

uint32_t xmssmt_core_hooks_time_elapsed_ms(uint32_t start_ms)
{
    if (g_xmssmt_core_hooks.time_elapsed_ms == NULL) {
        return 0u;
    }

    return g_xmssmt_core_hooks.time_elapsed_ms(start_ms);
}

void xmssmt_core_hooks_sign_timing_begin(const xmss_params *params)
{
    if (g_xmssmt_core_hooks.sign_timing_begin != NULL) {
        g_xmssmt_core_hooks.sign_timing_begin(params);
    }
}

void xmssmt_core_hooks_sign_timing_note_prf_msg(uint32_t start_ms)
{
    if (g_xmssmt_core_hooks.sign_timing_note_prf_msg != NULL) {
        g_xmssmt_core_hooks.sign_timing_note_prf_msg(start_ms);
    }
}

void xmssmt_core_hooks_sign_timing_note_wots(uint32_t start_ms)
{
    if (g_xmssmt_core_hooks.sign_timing_note_wots != NULL) {
        g_xmssmt_core_hooks.sign_timing_note_wots(start_ms);
    }
}

void xmssmt_core_hooks_sign_timing_note_treehash(uint32_t start_ms,
                                                 uint32_t cache_build_ms,
                                                 int cache_hit)
{
    if (g_xmssmt_core_hooks.sign_timing_note_treehash != NULL) {
        g_xmssmt_core_hooks.sign_timing_note_treehash(start_ms, cache_build_ms, cache_hit);
    }
}

void xmssmt_core_hooks_sign_timing_end(uint32_t sign_start_ms)
{
    if (g_xmssmt_core_hooks.sign_timing_end != NULL) {
        g_xmssmt_core_hooks.sign_timing_end(sign_start_ms);
    }
}

int xmssmt_core_hooks_cached_auth_path(const xmss_params *params,
                                       const unsigned char *sk_seed,
                                       const unsigned char *pub_seed,
                                       uint32_t layer,
                                       uint64_t tree_idx,
                                       uint32_t leaf_idx,
                                       unsigned char *root,
                                       unsigned char *auth_path,
                                       uint32_t *cache_build_ms,
                                       int *cache_hit)
{
    if (g_xmssmt_core_hooks.cached_auth_path == NULL) {
        if (cache_build_ms != NULL) {
            *cache_build_ms = 0u;
        }
        if (cache_hit != NULL) {
            *cache_hit = 0;
        }
        return -1;
    }

    return g_xmssmt_core_hooks.cached_auth_path(params,
                                                sk_seed,
                                                pub_seed,
                                                layer,
                                                tree_idx,
                                                leaf_idx,
                                                root,
                                                auth_path,
                                                cache_build_ms,
                                                cache_hit);
}