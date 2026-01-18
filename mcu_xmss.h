#ifndef MCU_XMSS_H
#define MCU_XMSS_H

#include <stdint.h>
#include <stddef.h>

// Return codes
#define MCU_XMSS_OK 0
#define MCU_XMSS_ERR_FILESYSTEM -1
#define MCU_XMSS_ERR_KEYS -2
#define MCU_XMSS_ERR_INDEX -3

/**
 * Initialize the MCU XMSS module in RAM-only mode.
 * - Generates new keys on the fly.
 * - No file persistence.
 * - Initializes internal state with fresh keys.
 */
int mcu_xmss_init_ram(void);

/**
 * Sign a message using the current index.
 * - Manages index increment.
 * - Updates flash storage periodically (every 50 signatures).
 * - Uses XMSSMT-SHA2_40/8_256 parameters.
 * - NOTE: The underlying XMSS reference API produces a "signed message" buffer
 *   (sm = signature || message). This wrapper returns a detached signature
 *   only (the signature prefix), so higher layers can transport `merkle_root`
 *   separately per the CBOR schema.
 * 
 * @param msg Pointer to the message to sign.
 * @param msglen Length of the message.
 * @param sig Buffer to store the detached signature (must be at least params.sig_bytes).
 * @param siglen Pointer to store the length of the detached signature (== params.sig_bytes).
 */
int mcu_xmss_sign(const unsigned char *msg, unsigned long long msglen,
                  unsigned char *sig, unsigned long long *siglen);

/**
 * Test XMSS signing and verification with "STARDOME" message.
 * - Signs the test message
 * - Verifies the signature
 * - Logs timing information
 * - Returns MCU_XMSS_OK on success, error code on failure
 */
int mcu_xmss_test_sign_verify(void);

/**
 * Perform a clean shutdown.
 * - Saves the current index to flash.
 * - Updates the integrity check to mark a clean shutdown.
 */
int mcu_xmss_shutdown(void);

/**
 * Get the current index (for display/debug).
 */
uint64_t mcu_xmss_get_index(void);

/**
 * NOTE: This module should be compiled with `xmss_core.c` (stateless implementation),
 * NOT `xmss_core_fast.c` (which uses large BDS state in RAM).
 * The stateless implementation is slower but uses significantly less RAM and is
 * simpler for "Index-Only" storage strategies.
 */

/**
 * Get the current XMSS public key.
 * @param pk Pointer to pointer that will be set to the public key buffer.
 * @param len Pointer to size_t that will be set to the length of the public key.
 * @return MCU_XMSS_OK on success, error code on failure.
 */
int mcu_xmss_get_pk(const uint8_t **pk, size_t *len);

#endif // MCU_XMSS_H
