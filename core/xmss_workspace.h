#ifndef XMSS_WORKSPACE_H
#define XMSS_WORKSPACE_H

#include <stdint.h>

/*
 * Profile-specialized workspace bounds for the active firmware parameter set:
 *   XMSSMT-SHA2_40/8_256 (OID 0x00000005)
 *
 * n=32, padding_len=32, wots_len=67, checksum_bytes=2, tree_height=5
 */
#define XMSS_WS_MAX_N 32U
#define XMSS_WS_MAX_PADDING_LEN 32U
#define XMSS_WS_MAX_WOTS_LEN 67U
#define XMSS_WS_MAX_CSUM_BYTES 2U
#define XMSS_WS_MAX_TREE_HEIGHT 5U

#define XMSS_WS_PRF_BUF_BYTES (XMSS_WS_MAX_PADDING_LEN + XMSS_WS_MAX_N + 32U)
#define XMSS_WS_PRF_KEYGEN_BUF_BYTES (XMSS_WS_MAX_PADDING_LEN + (2U * XMSS_WS_MAX_N) + 32U)
#define XMSS_WS_THASH_H_BUF_BYTES (XMSS_WS_MAX_PADDING_LEN + (3U * XMSS_WS_MAX_N))
#define XMSS_WS_THASH_F_BUF_BYTES (XMSS_WS_MAX_PADDING_LEN + (2U * XMSS_WS_MAX_N))
#define XMSS_WS_WOTS_SIG_BYTES (XMSS_WS_MAX_N * XMSS_WS_MAX_WOTS_LEN)
#define XMSS_WS_TREEHASH_STACK_BYTES ((XMSS_WS_MAX_TREE_HEIGHT + 1U) * XMSS_WS_MAX_N)
#define XMSS_WS_AUTH_PATH_BYTES (XMSS_WS_MAX_TREE_HEIGHT * XMSS_WS_MAX_N)
#define XMSS_WS_SEED_BYTES (3U * XMSS_WS_MAX_N)

typedef struct {
    unsigned char prf_buf[XMSS_WS_PRF_BUF_BYTES];
    unsigned char prf_keygen_buf[XMSS_WS_PRF_KEYGEN_BUF_BYTES];
    unsigned char thash_h_buf[XMSS_WS_THASH_H_BUF_BYTES];
    unsigned char thash_h_bitmask[2U * XMSS_WS_MAX_N];
    unsigned char thash_f_buf[XMSS_WS_THASH_F_BUF_BYTES];
    unsigned char thash_f_bitmask[XMSS_WS_MAX_N];

    unsigned char expand_seed_buf[XMSS_WS_MAX_N + 32U];
    int wots_lengths[XMSS_WS_MAX_WOTS_LEN];
    unsigned char wots_csum_bytes[XMSS_WS_MAX_CSUM_BYTES];

    unsigned char leaf_wots_pk[XMSS_WS_WOTS_SIG_BYTES];

    unsigned char treehash_stack[XMSS_WS_TREEHASH_STACK_BYTES];
    unsigned int treehash_heights[XMSS_WS_MAX_TREE_HEIGHT + 1U];
    unsigned char seed_keypair_auth_path[XMSS_WS_AUTH_PATH_BYTES];
    unsigned char keypair_seed[XMSS_WS_SEED_BYTES];
    unsigned char sign_root[XMSS_WS_MAX_N];
} xmss_workspace_t;

xmss_workspace_t *xmss_workspace_get(void);

#endif
