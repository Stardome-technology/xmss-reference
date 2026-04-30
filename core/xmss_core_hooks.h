#ifndef XMSS_CORE_HOOKS_H
#define XMSS_CORE_HOOKS_H

#include <stdint.h>

#include "params.h"

typedef struct {
    uint32_t (*time_now_ms)(void);
    uint32_t (*time_elapsed_ms)(uint32_t start_ms);
    void (*sign_timing_begin)(const xmss_params *params);
    void (*sign_timing_note_prf_msg)(uint32_t start_ms);
    void (*sign_timing_note_wots)(uint32_t start_ms);
    void (*sign_timing_note_treehash)(uint32_t start_ms,
                                      uint32_t cache_build_ms,
                                      int cache_hit);
    void (*sign_timing_end)(uint32_t sign_start_ms);
    int (*cached_auth_path)(const xmss_params *params,
                            const unsigned char *sk_seed,
                            const unsigned char *pub_seed,
                            uint32_t layer,
                            uint64_t tree_idx,
                            uint32_t leaf_idx,
                            unsigned char *root,
                            unsigned char *auth_path,
                            uint32_t *cache_build_ms,
                            int *cache_hit);
} xmssmt_core_hooks_t;

void xmssmt_core_hooks_set(const xmssmt_core_hooks_t *hooks);
void xmssmt_core_hooks_clear(void);

uint32_t xmssmt_core_hooks_time_now_ms(void);
uint32_t xmssmt_core_hooks_time_elapsed_ms(uint32_t start_ms);

void xmssmt_core_hooks_sign_timing_begin(const xmss_params *params);
void xmssmt_core_hooks_sign_timing_note_prf_msg(uint32_t start_ms);
void xmssmt_core_hooks_sign_timing_note_wots(uint32_t start_ms);
void xmssmt_core_hooks_sign_timing_note_treehash(uint32_t start_ms,
                                                 uint32_t cache_build_ms,
                                                 int cache_hit);
void xmssmt_core_hooks_sign_timing_end(uint32_t sign_start_ms);

int xmssmt_core_hooks_cached_auth_path(const xmss_params *params,
                                       const unsigned char *sk_seed,
                                       const unsigned char *pub_seed,
                                       uint32_t layer,
                                       uint64_t tree_idx,
                                       uint32_t leaf_idx,
                                       unsigned char *root,
                                       unsigned char *auth_path,
                                       uint32_t *cache_build_ms,
                                       int *cache_hit);

#endif