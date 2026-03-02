#include "mcu_xmss.h"
#include "xmss.h"
#include "xmss_core.h"
#include "params.h"
#include "xmss_callbacks.h"
#include "sha256.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "system/console/sys_console.h"
#include "system/time/sys_time.h"

// --- Configuration ---
#define XMSS_OID_VAL 0x00000005 // XMSSMT-SHA2_40/8_256
#define INDEX_SAVE_INTERVAL 50
#define XMSS_OID_LEN 4

// --- Static Buffers ---
// Size covers XMSSMT-SHA2_40/8_256 signature (~18.5 KiB sm) with headroom.
#define XMSS_SIG_MAX_STATIC (24 * 1024)
#define XMSS_STORE_SK_MAX 200
#define XMSS_STORE_PK_MAX 200

static xmss_params g_params;
static unsigned char g_sk_static[XMSS_STORE_SK_MAX];
static unsigned char g_pk_static[XMSS_STORE_PK_MAX];
static unsigned char g_signature_static[XMSS_SIG_MAX_STATIC];
static unsigned char g_sk_working_static[XMSS_STORE_SK_MAX];
static unsigned char g_sk_gen_static[XMSS_STORE_SK_MAX];
static unsigned char g_pk_gen_static[XMSS_STORE_PK_MAX];

// --- Internal State ---
static uint64_t g_ram_index = 0;
static int g_initialized = 0;

// Helper to serialize index into SK (big-endian, past OID prefix)
static void set_sk_index(unsigned char *sk, uint64_t idx, const xmss_params *params)
{
    unsigned char *sk_index_ptr = sk + XMSS_OID_LEN;
    for (int i = params->index_bytes - 1; i >= 0; i--) {
        sk_index_ptr[i] = idx & 0xFF;
        idx >>= 8;
    }
}

// Return the detached signature size for the currently parsed XMSS params.
int mcu_xmss_get_sig_bytes(unsigned long long *out)
{
    if (out == NULL) return MCU_XMSS_ERR_KEYS;
    if (g_initialized == 0) return MCU_XMSS_ERR_KEYS;
    *out = (unsigned long long)g_params.sig_bytes;
    return MCU_XMSS_OK;
}

int mcu_xmss_init_ram(void)
{
    // 0. Register Callbacks
    xmss_set_sha_cb(xmss_sha256_wrapper);
    // RNG callback is set by the caller before invoking this function

    // 1. Initialize Parameters
    if (xmssmt_parse_oid(&g_params, XMSS_OID_VAL) != 0) {
        return MCU_XMSS_ERR_KEYS;
    }

    // 2. Generate new keypair into static working buffers (no heap allocation)
    size_t sk_buf_size = (size_t)g_params.sk_bytes + XMSS_OID_LEN;
    size_t pk_buf_size = (size_t)g_params.pk_bytes + XMSS_OID_LEN;
    if (sk_buf_size > sizeof(g_sk_gen_static) || pk_buf_size > sizeof(g_pk_gen_static)) {
        SYS_CONSOLE_PRINT("XMSS: Key buffers exceed static working storage\r\n");
        return MCU_XMSS_ERR_KEYS;
    }

    SYS_CONSOLE_PRINT("XMSS: Starting keypair generation...\r\n");

    // Start timing using SYS_TIME (Harmony standard)
    uint64_t start_count = SYS_TIME_Counter64Get();

    if (xmssmt_keypair(g_pk_gen_static, g_sk_gen_static, XMSS_OID_VAL) != 0) {
        SYS_CONSOLE_PRINT("XMSS: Keypair generation failed\r\n");
        return MCU_XMSS_ERR_KEYS;
    }

    // End timing
    uint64_t end_count = SYS_TIME_Counter64Get();
    uint64_t elapsed_counts = end_count - start_count;
    uint32_t elapsed_ms = (uint32_t)SYS_TIME_CountToMS(elapsed_counts);

    SYS_CONSOLE_PRINT("XMSS: Keypair generation completed in %u ms\r\n", elapsed_ms);

    // 3. Store keys in RAM (include OID prefix)
    size_t sk_copy_len = (size_t)g_params.sk_bytes + XMSS_OID_LEN;
    size_t pk_copy_len = (size_t)g_params.pk_bytes + XMSS_OID_LEN;
    if (sk_copy_len <= sizeof(g_sk_static)) {
        memcpy(g_sk_static, g_sk_gen_static, sk_copy_len);
    } else {
        /* Should not happen: ensure we don't overflow static buffers */
        memcpy(g_sk_static, g_sk_gen_static, sizeof(g_sk_static));
    }
    if (pk_copy_len <= sizeof(g_pk_static)) {
        memcpy(g_pk_static, g_pk_gen_static, pk_copy_len);
    } else {
        memcpy(g_pk_static, g_pk_gen_static, sizeof(g_pk_static));
    }

    // 4. Initialize index to 0
    g_ram_index = 0;

    g_initialized = 1;
    SYS_CONSOLE_PRINT("XMSS: Initialization completed\r\n");
    return MCU_XMSS_OK;
}

int mcu_xmss_sign(const unsigned char *msg, unsigned long long msglen,
                  unsigned char *sig, unsigned long long *siglen)
{
    if (!g_initialized) return MCU_XMSS_ERR_KEYS;
    if (!sig || !siglen) return MCU_XMSS_ERR_KEYS;

    const uint64_t used_index = g_ram_index;

    // 1. Prepare Secret Key with Current Index (static working buffer, no heap)
    size_t sk_working_size = (size_t)g_params.sk_bytes + XMSS_OID_LEN;
    if (sk_working_size > sizeof(g_sk_working_static)) {
        SYS_CONSOLE_PRINT("XMSS: ERROR: sk_working buffer too small (need=%u have=%u)\r\n",
                          (unsigned)sk_working_size,
                          (unsigned)sizeof(g_sk_working_static));
        return MCU_XMSS_ERR_KEYS;
    }
    unsigned char *sk_working = g_sk_working_static;
    /* g_sk_static contains OID + sk bytes */
    memcpy(sk_working, g_sk_static, sk_working_size);

    set_sk_index(sk_working, used_index, &g_params);

    // 2. Sign using upstream API.
    //    NOTE: xmssmt_sign writes a "signed message" buffer: sm = [signature || message].
    //    This wrapper returns only the detached signature bytes so the caller can
    //    transport `message` separately (e.g., merkle_root in the CBOR attestation).
    unsigned long long expected_smlen = (unsigned long long)g_params.sig_bytes + msglen;
    unsigned long long smlen = expected_smlen;
    if (expected_smlen > (unsigned long long)XMSS_SIG_MAX_STATIC) {
        SYS_CONSOLE_PRINT("XMSS: ERROR: signed-message buffer too small (need=%llu have=%u)\r\n",
                          expected_smlen,
                          XMSS_SIG_MAX_STATIC);
        return MCU_XMSS_ERR_KEYS;
    }
    unsigned char *sm = g_signature_static;

    int ret = xmssmt_sign(sk_working, sm, &smlen, msg, msglen);
    if (ret != 0 || smlen < (unsigned long long)g_params.sig_bytes) {
        return MCU_XMSS_ERR_KEYS;
    }

    // Copy signature prefix out.
    memcpy(sig, sm, (size_t)g_params.sig_bytes);
    *siglen = (unsigned long long)g_params.sig_bytes;

    /* 3. Advance index in RAM. */
    g_ram_index = used_index + 1u;

    return MCU_XMSS_OK;
}

int mcu_xmss_shutdown(void)
{
    // RAM-only mode: no persistent state to flush.
    return MCU_XMSS_OK;
}

uint64_t mcu_xmss_get_index(void)
{
    return g_ram_index;
}

int mcu_xmss_get_pk(const uint8_t **pk, size_t *len)
{
    if (!g_initialized) return MCU_XMSS_ERR_KEYS;
    if (pk) *pk = g_pk_static;
    if (len) *len = (size_t)g_params.pk_bytes + XMSS_OID_LEN;
    return MCU_XMSS_OK;
}
