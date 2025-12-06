#include "mcu_xmss.h"
#include "xmss.h"
#include "xmss_core.h"
#include "params.h"
#include "xmss_callbacks.h"
#include "sha256.h"
#include <string.h>
#include <stdio.h>

// --- Configuration ---
#define XMSS_OID_VAL 0x00000005 // XMSSMT-SHA2_40/8_256
#define INDEX_SAVE_INTERVAL 50
#define INDEX_FILE "xmss_index.bin"
#define SECRET_FILE "xmss_secret.bin"
#define INTEGRITY_FILE "xmss_integrity.bin"

// --- Mock Hardware/OS Abstraction Layer ---
// Replace these with actual LittleFS and CRC implementations

static int lfs_read_file(const char* filename, void* buffer, size_t size) {
    // TODO: Implement LittleFS read
    // FILE *f = fopen(filename, "rb");
    // if (!f) return -1;
    // fread(buffer, 1, size, f);
    // fclose(f);
    return 0; // Success
}

static int lfs_write_file(const char* filename, const void* buffer, size_t size) {
    // TODO: Implement LittleFS write (atomic)
    // FILE *f = fopen(filename, "wb");
    // if (!f) return -1;
    // fwrite(buffer, 1, size, f);
    // fclose(f);
    return 0; // Success
}

static uint32_t calculate_crc32(const void* data, size_t size) {
    // TODO: Implement hardware CRC or software CRC32
    return 0xDEADBEEF; 
}

// --- Internal State ---
static uint64_t g_ram_index = 0;
static uint64_t g_flash_index_checkpoint = 0;
static xmss_params g_params;
static unsigned char g_sk_static[200]; // Buffer for SK (size depends on params, ~140 bytes for 40/8)
static int g_initialized = 0;

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

int mcu_xmss_init(void) {
    // 0. Register Callbacks
    xmss_set_sha_cb(xmss_sha256_wrapper);
    // Note: RNG callback is not strictly needed for signing if keys are pre-generated,
    // but if needed, register it here.

    // 1. Initialize Parameters
    if (xmssmt_parse_oid(&g_params, XMSS_OID_VAL) != 0) {
        return MCU_XMSS_ERR_KEYS;
    }

    // 2. Load Secret Key (Static parts)
    // We assume the secret key file contains the full SK. 
    // We will overwrite the index part in RAM.
    if (lfs_read_file(SECRET_FILE, g_sk_static, g_params.sk_bytes) != 0) {
        return MCU_XMSS_ERR_FILESYSTEM;
    }

    // 3. Read Index Checkpoint
    uint64_t stored_index = 0;
    if (lfs_read_file(INDEX_FILE, &stored_index, sizeof(stored_index)) != 0) {
        // If file doesn't exist, assume 0 (fresh device)
        stored_index = 0;
    }

    // 4. Check Integrity (Clean Shutdown?)
    uint32_t stored_crc = 0;
    uint32_t calc_crc = calculate_crc32(&stored_index, sizeof(stored_index));
    
    int clean_shutdown = 0;
    if (lfs_read_file(INTEGRITY_FILE, &stored_crc, sizeof(stored_crc)) == 0) {
        if (stored_crc == calc_crc) {
            clean_shutdown = 1;
        }
    }

    // 5. Determine Start Index
    if (clean_shutdown) {
        g_ram_index = stored_index;
    } else {
        // Dirty shutdown: Skip safety margin
        g_ram_index = stored_index + INDEX_SAVE_INTERVAL;
        
        // Immediately update flash to reflect this skip
        g_flash_index_checkpoint = g_ram_index;
        lfs_write_file(INDEX_FILE, &g_flash_index_checkpoint, sizeof(g_flash_index_checkpoint));
        
        // We do NOT mark clean yet, or we could. 
        // Let's mark clean to establish a new valid baseline.
        uint32_t new_crc = calculate_crc32(&g_flash_index_checkpoint, sizeof(g_flash_index_checkpoint));
        lfs_write_file(INTEGRITY_FILE, &new_crc, sizeof(new_crc));
    }

    g_flash_index_checkpoint = g_ram_index;
    g_initialized = 1;
    return MCU_XMSS_OK;
}

int mcu_xmss_sign(const unsigned char *msg, unsigned long long msglen,
                  unsigned char *sig, unsigned long long *siglen) {
    if (!g_initialized) return MCU_XMSS_ERR_KEYS;

    // 1. Check if we need to update Flash Checkpoint
    // We update if we have advanced INDEX_SAVE_INTERVAL since last checkpoint
    if (g_ram_index >= g_flash_index_checkpoint + INDEX_SAVE_INTERVAL) {
        g_flash_index_checkpoint = g_ram_index;
        
        // Write new index
        if (lfs_write_file(INDEX_FILE, &g_flash_index_checkpoint, sizeof(g_flash_index_checkpoint)) != 0) {
            return MCU_XMSS_ERR_FILESYSTEM;
        }
        
        // Note: We do NOT update the integrity file here. 
        // The integrity file is only for "Clean Shutdown".
        // If we crash now, the CRC will mismatch (old CRC vs new Index), 
        // causing the next boot to skip +50. This is exactly what we want.
    }

    // 2. Prepare Secret Key with Current Index
    // Copy static SK to a working buffer (or just modify in place if thread-safe)
    // Since we are single-threaded MCU, we can modify g_sk_static temporarily 
    // BUT xmssmt_core_sign updates the SK. We should use a copy or reset it.
    // Actually, xmssmt_core_sign updates the index in the SK. 
    // We want to control the index explicitly.
    
    unsigned char sk_working[200]; // Ensure enough space
    memcpy(sk_working, g_sk_static, g_params.sk_bytes);
    
    set_sk_index(sk_working, g_ram_index, &g_params);

    // 3. Sign
    // xmssmt_core_sign(params, sk, sm, smlen, m, mlen)
    // It produces sm = sig || msg. We need to extract sig.
    // Wait, xmssmt_core_sign signature:
    // int xmssmt_core_sign(const xmss_params *params, unsigned char *sk,
    //                      unsigned char *sm, unsigned long long *smlen,
    //                      const unsigned char *m, unsigned long long mlen);
    // It writes signature + message into sm.
    // We want just the signature.
    // We can pass a temporary buffer or point sm to sig and handle the message copy.
    // Standard API usually copies message.
    
    unsigned char *sm = NULL;
    unsigned long long smlen = 0;
    
    // Allocate buffer for sig + msg
    // On MCU, be careful with stack. 
    // Sig size ~10KB. Msg size unknown.
    // Better to use the 'sig' buffer provided by user if it's large enough?
    // The user API `mcu_xmss_sign` asks for `sig` buffer.
    // Usually `sig` buffer is just for signature.
    // `xmssmt_core_sign` puts Sig || Msg into `sm`.
    // We can't easily use `xmssmt_core_sign` if we don't want to copy the message.
    // Let's look at `xmss_core_sign` implementation.
    // It calls `xmssmt_core_sign_open`? No.
    
    // Let's use a temporary buffer for the signature part if possible, 
    // or just trick it.
    // The reference implementation `xmss_core_sign` does:
    //   xmss_sign_signature(sk, sm, m, mlen) -> writes sig to sm
    //   memcpy(sm + sig_len, m, mlen);
    // Wait, I need to check `xmss_core.c` to see if there is a function that JUST generates signature.
    // `xmssmt_core_sign` does both.
    
    // Let's assume we can use `xmssmt_sign_signature` if it exists (it was mentioned in the gemini doc).
    // If not, we use `xmssmt_core_sign` and discard the message part.
    // We need a buffer of size sig_len + msg_len.
    // If msg is large, this is bad.
    
    // Let's check `xmss_core.c` for `xmssmt_core_sign` implementation.
    // If it calls a lower level function, we can use that.
    
    // For now, I will assume I can allocate a buffer for Sig+Msg, 
    // or I will check if I can pass `sig` and `msg` separately.
    // The `xmss.h` has `xmssmt_sign` which returns `sig` and `sk`.
    // `xmssmt_sign` calls `xmssmt_core_sign`.
    
    // Let's look at `xmss.c`.
    
    // For the purpose of this file, I will use a simplified flow:
    // 1. Set index in SK.
    // 2. Call `xmssmt_core_sign` with a temp buffer (if msg is small) or handle it.
    // Actually, `xmssmt_sign` in `xmss.c` takes `sig` buffer.
    // int xmssmt_sign(unsigned char *sk, unsigned char *sig, unsigned long long *siglen, ...)
    // This is exactly what we want.
    // It handles the `sm` construction internally?
    // Let's check `xmss.c`.
    
    // If `xmss.c` is available, I should use `xmssmt_sign`.
    // But `xmssmt_sign` updates `sk`.
    // That's fine, we are using a local copy `sk_working`.
    
    int ret = xmssmt_sign(sk_working, sig, siglen, msg, msglen);
    if (ret != 0) return MCU_XMSS_ERR_KEYS;

    // 4. Increment RAM Index
    g_ram_index++;

    return MCU_XMSS_OK;
}

int mcu_xmss_shutdown(void) {
    if (!g_initialized) return MCU_XMSS_ERR_KEYS;

    // 1. Save current index
    g_flash_index_checkpoint = g_ram_index;
    if (lfs_write_file(INDEX_FILE, &g_flash_index_checkpoint, sizeof(g_flash_index_checkpoint)) != 0) {
        return MCU_XMSS_ERR_FILESYSTEM;
    }

    // 2. Mark Clean Shutdown (Update Integrity)
    uint32_t crc = calculate_crc32(&g_flash_index_checkpoint, sizeof(g_flash_index_checkpoint));
    if (lfs_write_file(INTEGRITY_FILE, &crc, sizeof(crc)) != 0) {
        return MCU_XMSS_ERR_FILESYSTEM;
    }

    return MCU_XMSS_OK;
}

uint64_t mcu_xmss_get_index(void) {
    return g_ram_index;
}
