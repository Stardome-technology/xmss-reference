#include "mcu_xmss.h"
#include "xmss.h"
#include "xmss_core.h"
#include "params.h"
#include "xmss_callbacks.h"
#include "sha256.h"
#include "zlib.h"
#include <string.h>
#include <stdio.h>
#include "app_utils.h"

// --- Configuration ---
#define XMSS_OID_VAL 0x00000005 // XMSSMT-SHA2_40/8_256
#define INDEX_SAVE_INTERVAL 50
#define INDEX_FILE "xmss_index.bin"
#define SECRET_FILE "xmss_secret.bin"
#define INTEGRITY_FILE "xmss_integrity.bin"

// --- Mock Hardware/OS Abstraction Layer ---
// Replace these with actual LittleFS and CRC implementations

static int lfs_read_file(const char* filename, void* buffer, size_t size) {
    if (!filename || !buffer || size == 0) {
        return -1;
    }

    size_t bytes_read = 0;
    int rc = app_utils_read_file(filename, buffer, size, &bytes_read);

    /* success only if app_utils returned OK and we read the expected size */
    if (rc == APP_UTILS_OK && bytes_read == size) {
        return 0;
    }

    /* treat any other scenario (missing file, short read, or error) as failure */
    return -1;
}

static int lfs_write_file(const char* filename, const void* buffer, size_t size) {
    if (!filename || !buffer || size == 0) {
        return -1;
    }

    size_t bytes_written = 0;
    /* Use truncate mode to replace file contents when writing checkpoints/integrity */
    int rc = app_utils_write_file(filename, buffer, size, &bytes_written, 1 /*truncate*/);

    if (rc == APP_UTILS_OK && bytes_written == size) return 0;
    return -1;
}

static uint32_t calculate_crc32(const void* data, size_t size) {
    /*
     * Use zlib's crc32_z which accepts a size_t length (safer than crc32).
     * For integer-sized values (in our code we use this for the 64-bit index),
     * compute the CRC over a canonical big-endian byte representation so the
     * CRC is independent of host endianness.
     */
    if (data == NULL || size == 0) return 0;

    /* Handle canonicalization for 64-bit index values */
    if (size == sizeof(uint64_t)) {
        uint8_t be[sizeof(uint64_t)];
        uint64_t v = *(const uint64_t *)data;
        /* store big-endian */
        for (int i = 0; i < (int)sizeof(be); ++i) {
            be[sizeof(be) - 1 - i] = (uint8_t)(v & 0xFF);
            v >>= 8;
        }
        return (uint32_t)crc32_z(0L, be, (z_size_t)sizeof(be));
    }

    /* Fallback: compute CRC over the raw bytes provided */
    return (uint32_t)crc32_z(0L, (const unsigned char *)data, (z_size_t)size);
}

// --- Internal State ---
static uint64_t g_ram_index = 0;
static uint64_t g_flash_index_checkpoint = 0;
static xmss_params g_params;
static unsigned char g_sk_static[200]; // Buffer for SK (size depends on params, ~140 bytes for 40/8)
static unsigned char g_pk_static[200]; // Buffer for PK (size depends on params, ~64 bytes for 40/8)
static int g_initialized = 0;

/* Fallback static buffers used when heap allocation fails on constrained devices.
 * Size chosen to cover common XMSS signature sizes used in tests (tweak as needed
 * for your parameter set or available RAM). If you prefer to increase the heap,
 * update your XC32/MPLAB project linker settings (heap size) or adjust
 * `XMSS_SIG_MAX_STATIC` here.
 */
#define XMSS_SIG_MAX_STATIC (8 * 1024) /* 8 KiB default fallback buffer (reduced) */
static unsigned char g_signature_static[XMSS_SIG_MAX_STATIC];
static unsigned char g_verified_static[XMSS_SIG_MAX_STATIC];

// Helper to serialize index into SK
static void set_sk_index(unsigned char* sk, uint64_t idx, const xmss_params* params) {
    // XMSS reference implementation stores index in big-endian
    // The SK passed to xmssmt_sign includes OID (4 bytes) at the beginning.
    // The index follows the OID.
    unsigned char* sk_index_ptr = sk + XMSS_OID_LEN;
    
    for (int i = params->index_bytes - 1; i >= 0; i--) {
        sk_index_ptr[i] = idx & 0xFF;
        idx >>= 8;
    }
}

// Helper to deserialize index from SK (if needed)
static uint64_t get_sk_index(const unsigned char* sk, const xmss_params* params) {
    uint64_t idx = 0;
    const unsigned char* sk_index_ptr = sk + XMSS_OID_LEN;
    
    for (unsigned int i = 0; i < params->index_bytes; i++) {
        idx = (idx << 8) | sk_index_ptr[i];
    }
    return idx;
}

int mcu_xmss_init_ram(void) {
    // 0. Register Callbacks
    xmss_set_sha_cb(xmss_sha256_wrapper);
    // RNG callback is set in app.c

    // 1. Initialize Parameters
    if (xmssmt_parse_oid(&g_params, XMSS_OID_VAL) != 0) {
        return MCU_XMSS_ERR_KEYS;
    }

    SYS_CONSOLE_PRINT("XMSS: Starting keypair generation...\r\n");

    // 2. Generate new keypair
    size_t sk_buf_size = (size_t)g_params.sk_bytes + XMSS_OID_LEN;
    size_t pk_buf_size = (size_t)g_params.pk_bytes + XMSS_OID_LEN;
    unsigned char *sk = malloc(sk_buf_size);
    unsigned char *pk = malloc(pk_buf_size);
    if (!sk || !pk) {
        SYS_CONSOLE_PRINT("XMSS: Memory allocation failed\r\n");
        if (sk) free(sk);
        if (pk) free(pk);
        return MCU_XMSS_ERR_KEYS;
    }

    // Start timing using SYS_TIME (Harmony standard)
    uint64_t start_count = SYS_TIME_Counter64Get();
    
    if (xmssmt_keypair(pk, sk, XMSS_OID_VAL) != 0) {
        SYS_CONSOLE_PRINT("XMSS: Keypair generation failed\r\n");
        free(sk);
        free(pk);
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
        memcpy(g_sk_static, sk, sk_copy_len);
    } else {
        /* Should not happen: ensure we don't overflow static buffers */
        memcpy(g_sk_static, sk, sizeof(g_sk_static));
    }
    if (pk_copy_len <= sizeof(g_pk_static)) {
        memcpy(g_pk_static, pk, pk_copy_len);
    } else {
        memcpy(g_pk_static, pk, sizeof(g_pk_static));
    }
    free(sk);
    free(pk);

    // 4. Initialize index to 0
    g_ram_index = 0;
    g_flash_index_checkpoint = 0;

    g_initialized = 1;
    SYS_CONSOLE_PRINT("XMSS: Initialization completed\r\n");
    return MCU_XMSS_OK;
}

int mcu_xmss_sign(const unsigned char *msg, unsigned long long msglen,
                  unsigned char *sig, unsigned long long *siglen) {
    if (!g_initialized) return MCU_XMSS_ERR_KEYS;
    if (!sig || !siglen) return MCU_XMSS_ERR_KEYS;

    // 1. Prepare Secret Key with Current Index (use heap to avoid stack overflow)
    size_t sk_working_size = (size_t)g_params.sk_bytes + XMSS_OID_LEN;
    unsigned char *sk_working = malloc(sk_working_size);
    if (!sk_working) return MCU_XMSS_ERR_KEYS;
    /* g_sk_static contains OID + sk bytes */
    memcpy(sk_working, g_sk_static, sk_working_size);

    set_sk_index(sk_working, g_ram_index, &g_params);

    // 2. Sign using upstream API.
    //    NOTE: xmssmt_sign writes a "signed message" buffer: sm = [signature || message].
    //    This wrapper returns only the detached signature bytes so the caller can
    //    transport `message` separately (e.g., merkle_root in the CBOR attestation).
    unsigned long long expected_smlen = (unsigned long long)g_params.sig_bytes + msglen;
    unsigned long long smlen = expected_smlen;
    unsigned char *sm = NULL;
    int sm_is_dynamic = 1;

    sm = (unsigned char *)malloc((size_t)expected_smlen);
    if (!sm) {
        if (expected_smlen <= (unsigned long long)XMSS_SIG_MAX_STATIC) {
            sm = g_signature_static;
            sm_is_dynamic = 0;
        } else {
            free(sk_working);
            return MCU_XMSS_ERR_KEYS;
        }
    }

    int ret = xmssmt_sign(sk_working, sm, &smlen, msg, msglen);
    if (ret != 0 || smlen < (unsigned long long)g_params.sig_bytes) {
        if (sm_is_dynamic) free(sm);
        free(sk_working);
        return MCU_XMSS_ERR_KEYS;
    }

    // Copy signature prefix out.
    memcpy(sig, sm, (size_t)g_params.sig_bytes);
    *siglen = (unsigned long long)g_params.sig_bytes;

    if (sm_is_dynamic) free(sm);

    // 3. Increment RAM Index
    g_ram_index++;
    free(sk_working);
    return MCU_XMSS_OK;
}

int mcu_xmss_test_sign_verify(void) {
    if (!g_initialized) {
        SYS_CONSOLE_PRINT("XMSS: Not initialized\r\n");
        return MCU_XMSS_ERR_KEYS;
    }

    const char *test_message = "STARDOME";
    unsigned long long msg_len = strlen(test_message);
    
    SYS_CONSOLE_PRINT("XMSS: Testing signature with message '%s'\r\n", test_message);

    // Allocate detached signature buffer (wrapper returns signature-only)
    unsigned long long expected_siglen = (unsigned long long)g_params.sig_bytes;
    unsigned long long expected_smlen = (unsigned long long)g_params.sig_bytes + msg_len;
    SYS_CONSOLE_PRINT("XMSS: params.sig_bytes=%u, msg_len=%llu, expected_siglen=%llu, expected_smlen=%llu\r\n",
                      g_params.sig_bytes, msg_len, expected_siglen, expected_smlen);
    unsigned char *signature = malloc((size_t)expected_siglen);
    unsigned long long sig_len = expected_siglen;
    int signature_is_dynamic = 1;

    if (!signature) {
        /* Try static fallback buffer if the heap is too small */
        if (expected_siglen <= (unsigned long long)XMSS_SIG_MAX_STATIC) {
            SYS_CONSOLE_PRINT("XMSS: malloc failed for signature; using static fallback buffer (%u bytes)\r\n", XMSS_SIG_MAX_STATIC);
            signature = g_signature_static;
            signature_is_dynamic = 0;
        } else {
            SYS_CONSOLE_PRINT("XMSS: Memory allocation failed for signature (requested %llu bytes)\r\n", expected_siglen);
            SYS_CONSOLE_PRINT("XMSS: params: sig_bytes=%u, pk_bytes=%u, sk_bytes=%llu\r\n", g_params.sig_bytes, g_params.pk_bytes, g_params.sk_bytes);
            SYS_CONSOLE_PRINT("XMSS: Requested signature buffer exceeds static fallback (%u).\r\n", XMSS_SIG_MAX_STATIC);
            SYS_CONSOLE_PRINT("XMSS: Consider increasing the heap in the XC32 linker options or reducing the XMSS parameter set.\r\n");
            return MCU_XMSS_ERR_KEYS;
        }
    }

    // Start timing for signing
    uint64_t sign_start = SYS_TIME_Counter64Get();
    
    // Sign the message
    int sign_result = mcu_xmss_sign((const unsigned char *)test_message, msg_len, signature, &sig_len);
    
    // End timing for signing
    uint64_t sign_end = SYS_TIME_Counter64Get();
    uint64_t sign_elapsed = sign_end - sign_start;
    uint32_t sign_ms = (uint32_t)SYS_TIME_CountToMS(sign_elapsed);
    
    if (sign_result != MCU_XMSS_OK) {
        SYS_CONSOLE_PRINT("XMSS: Signing failed\r\n");
        free(signature);
        return sign_result;
    }
    
    SYS_CONSOLE_PRINT("XMSS: Signing completed in %u ms, signature size: %llu bytes\r\n", sign_ms, sig_len);

    // Build signed-message buffer for verification (sm = signature || message)
    unsigned char *sm = malloc((size_t)expected_smlen);
    int sm_is_dynamic = 1;
    if (!sm) {
        if (expected_smlen <= (unsigned long long)XMSS_SIG_MAX_STATIC) {
            sm = g_verified_static;
            sm_is_dynamic = 0;
        } else {
            SYS_CONSOLE_PRINT("XMSS: Memory allocation failed for signed-message (requested %llu bytes)\r\n", expected_smlen);
            if (signature_is_dynamic) free(signature);
            return MCU_XMSS_ERR_KEYS;
        }
    }
    memcpy(sm, signature, (size_t)g_params.sig_bytes);
    memcpy(sm + (size_t)g_params.sig_bytes, test_message, (size_t)msg_len);

    // Start timing for verification
    uint64_t verify_start = SYS_TIME_Counter64Get();
    
    // Verify the signature using the upstream verify API.
    // xmssmt_sign_open expects `sm = signature || message`.
    size_t verified_buf_size = (size_t)expected_smlen;
    unsigned char *verified_msg = malloc(verified_buf_size);
    unsigned long long verified_len = 0;
    int verified_is_dynamic = 1;

    if (!verified_msg) {
        if (verified_buf_size <= XMSS_SIG_MAX_STATIC) {
            SYS_CONSOLE_PRINT("XMSS: malloc failed for verification buffer; using static fallback (%u bytes)\r\n", XMSS_SIG_MAX_STATIC);
            verified_msg = g_verified_static;
            verified_is_dynamic = 0;
        } else {
            SYS_CONSOLE_PRINT("XMSS: Memory allocation failed for verification (requested %u bytes)\r\n", (unsigned)verified_buf_size);
            if (signature_is_dynamic) free(signature);
            return MCU_XMSS_ERR_KEYS;
        }
    }

    int verify_result = xmssmt_sign_open(verified_msg, &verified_len, sm, expected_smlen, g_pk_static);
    
    // End timing for verification
    uint64_t verify_end = SYS_TIME_Counter64Get();
    uint64_t verify_elapsed = verify_end - verify_start;
    uint32_t verify_ms = (uint32_t)SYS_TIME_CountToMS(verify_elapsed);
    
    if (verify_result == 0 && verified_len == msg_len && memcmp(verified_msg, test_message, msg_len) == 0) {
        SYS_CONSOLE_PRINT("XMSS: Verification successful in %u ms\r\n", verify_ms);
        SYS_CONSOLE_PRINT("XMSS: Test PASSED\r\n");
    } else {
        SYS_CONSOLE_PRINT("XMSS: Verification failed in %u ms\r\n", verify_ms);
        SYS_CONSOLE_PRINT("XMSS: Test FAILED\r\n");
    }

    if (signature_is_dynamic) free(signature);
    if (sm_is_dynamic) free(sm);
    if (verified_is_dynamic) free(verified_msg);
    return (verify_result == 0) ? MCU_XMSS_OK : MCU_XMSS_ERR_KEYS;
}

int mcu_xmss_shutdown(void) {
    // No-op in RAM-only mode
    return MCU_XMSS_OK;
}

uint64_t mcu_xmss_get_index(void) {
    return g_ram_index;
}

int mcu_xmss_get_pk(const uint8_t **pk, size_t *len) {
    if (!g_initialized) return MCU_XMSS_ERR_KEYS;
    if (pk) *pk = g_pk_static;
    if (len) *len = (size_t)g_params.pk_bytes + XMSS_OID_LEN;
    return MCU_XMSS_OK;
}
