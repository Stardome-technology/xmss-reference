#ifndef SHA256_H
#define SHA256_H

#include <stdint.h>
#include <stddef.h>

typedef struct {
    uint32_t state[8];
    uint64_t count;
    uint8_t buffer[64];
    int error;
} sha256_ctx;

typedef struct {
    int (*backend_ready)(void);
    int (*fixed_dispatch)(const unsigned char *in,
                          unsigned long long inlen,
                          unsigned char *out,
                          int *handled);
    int (*process_blocks_with_state)(const uint32_t state_in[8],
                                     const uint8_t *data,
                                     uint32_t length,
                                     uint32_t state_out[8]);
    void (*backend_failed)(const char *reason);
} sha256_platform_hooks_t;

void sha256_init(sha256_ctx *ctx);
int sha256_update(sha256_ctx *ctx, const uint8_t *data, size_t len);
int sha256_final(sha256_ctx *ctx, uint8_t *hash);
void sha256_platform_hooks_set(const sha256_platform_hooks_t *hooks);
void sha256_platform_hooks_clear(void);

// Wrapper for XMSS callback
int xmss_sha256_wrapper(const unsigned char *in, unsigned long long inlen, unsigned char *out);

#endif
