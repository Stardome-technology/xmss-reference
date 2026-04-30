/* sha256.c - SHA reference implementation using C         */
/*   Written and placed in public domain by Jeffrey Walton */

#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include "sha256.h"

#define SHA256_BLOCK_BYTES 64u

enum
{
    SHA256_ERR_NONE = 0,
    SHA256_ERR_INPUT_NULL_WITH_LEN = 1,
    SHA256_ERR_HW_STATUS,
    SHA256_ERR_HW_TIMEOUT,
    SHA256_ERR_HW_WORKSPACE
};

static const uint32_t K256[] =
{
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
    0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
    0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
    0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
    0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
    0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
    0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
    0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
    0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2
};

static const uint32_t g_sha256_initial_state[8] =
{
    0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
    0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u
};

static const sha256_platform_hooks_t *g_sha256_platform_hooks = NULL;
static bool g_sha256_platform_backend_disabled = false;

#define ROTATE(x,y)  (((x) >> (y)) | ((x) << (32 - (y))))
#define Sigma0(x)    (ROTATE((x), 2) ^ ROTATE((x), 13) ^ ROTATE((x), 22))
#define Sigma1(x)    (ROTATE((x), 6) ^ ROTATE((x), 11) ^ ROTATE((x), 25))
#define sigma0(x)    (ROTATE((x), 7) ^ ROTATE((x), 18) ^ ((x) >> 3))
#define sigma1(x)    (ROTATE((x), 17) ^ ROTATE((x), 19) ^ ((x) >> 10))

#define Ch(x,y,z)    (((x) & (y)) ^ ((~(x)) & (z)))
#define Maj(x,y,z)   (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))

static uint32_t B2U32(uint8_t val, uint8_t sh)
{
    return ((uint32_t)val) << sh;
}

static void sha256_process_blocks_software(uint32_t state[8], const uint8_t data[], uint32_t length)
{
    uint32_t a, b, c, d, e, f, g, h, s0, s1, T1, T2;
    uint32_t X[16], i;
    size_t blocks = length / SHA256_BLOCK_BYTES;

    while (blocks--)
    {
        a = state[0];
        b = state[1];
        c = state[2];
        d = state[3];
        e = state[4];
        f = state[5];
        g = state[6];
        h = state[7];

        for (i = 0; i < 16; i++)
        {
            X[i] = B2U32(data[0], 24) | B2U32(data[1], 16) | B2U32(data[2], 8) | B2U32(data[3], 0);
            data += 4;

            T1 = h;
            T1 += Sigma1(e);
            T1 += Ch(e, f, g);
            T1 += K256[i];
            T1 += X[i];

            T2 = Sigma0(a);
            T2 += Maj(a, b, c);

            h = g;
            g = f;
            f = e;
            e = d + T1;
            d = c;
            c = b;
            b = a;
            a = T1 + T2;
        }

        for (; i < 64; i++)
        {
            s0 = X[(i + 1) & 0x0f];
            s0 = sigma0(s0);
            s1 = X[(i + 14) & 0x0f];
            s1 = sigma1(s1);

            T1 = X[i & 0x0f] += s0 + s1 + X[(i + 9) & 0x0f];
            T1 += h + Sigma1(e) + Ch(e, f, g) + K256[i];
            T2 = Sigma0(a) + Maj(a, b, c);
            h = g;
            g = f;
            f = e;
            e = d + T1;
            d = c;
            c = b;
            b = a;
            a = T1 + T2;
        }

        state[0] += a;
        state[1] += b;
        state[2] += c;
        state[3] += d;
        state[4] += e;
        state[5] += f;
        state[6] += g;
        state[7] += h;
    }
}

static void sha256_state_init(uint32_t state[8])
{
    memcpy(state, g_sha256_initial_state, sizeof(g_sha256_initial_state));
}

static void sha256_store_digest_from_state(const uint32_t state[8], uint8_t *hash)
{
    for (uint32_t i = 0u; i < 8u; i++)
    {
        hash[4u * i + 0u] = (uint8_t)((state[i] >> 24) & 0xFFu);
        hash[4u * i + 1u] = (uint8_t)((state[i] >> 16) & 0xFFu);
        hash[4u * i + 2u] = (uint8_t)((state[i] >> 8) & 0xFFu);
        hash[4u * i + 3u] = (uint8_t)(state[i] & 0xFFu);
    }
}

void sha256_platform_hooks_set(const sha256_platform_hooks_t *hooks)
{
    g_sha256_platform_hooks = hooks;
    g_sha256_platform_backend_disabled = false;
}

void sha256_platform_hooks_clear(void)
{
    g_sha256_platform_hooks = NULL;
    g_sha256_platform_backend_disabled = false;
}

static int sha256_platform_backend_ready(void)
{
    if (g_sha256_platform_hooks == NULL || g_sha256_platform_hooks->backend_ready == NULL)
    {
        return 0;
    }

    return g_sha256_platform_hooks->backend_ready();
}

static int sha256_platform_fixed_dispatch(const unsigned char *in,
                                          unsigned long long inlen,
                                          unsigned char *out,
                                          bool *handled)
{
    int handled_int = 0;
    int rc;

    if (handled != NULL)
    {
        *handled = false;
    }
    if (g_sha256_platform_hooks == NULL || g_sha256_platform_hooks->fixed_dispatch == NULL)
    {
        return 0;
    }

    rc = g_sha256_platform_hooks->fixed_dispatch(in, inlen, out, &handled_int);
    if (handled != NULL)
    {
        *handled = (handled_int != 0);
    }
    return rc;
}

static int sha256_platform_process_blocks_with_state(const uint32_t state_in[8],
                                                     const uint8_t *data,
                                                     uint32_t length,
                                                     uint32_t state_out[8])
{
    if (g_sha256_platform_hooks == NULL || g_sha256_platform_hooks->process_blocks_with_state == NULL)
    {
        return -1;
    }

    return g_sha256_platform_hooks->process_blocks_with_state(state_in, data, length, state_out);
}

static void sha256_platform_backend_failed(const char *reason)
{
    if (g_sha256_platform_hooks == NULL || g_sha256_platform_hooks->backend_failed == NULL)
    {
        return;
    }

    g_sha256_platform_hooks->backend_failed(reason);
}

static bool sha256_platform_backend_is_active(void)
{
    if (g_sha256_platform_backend_disabled)
    {
        return false;
    }

    return sha256_platform_backend_ready() == 1;
}

static void sha256_disable_platform_backend(const char *reason)
{
    g_sha256_platform_backend_disabled = true;
    sha256_platform_backend_failed(reason);
}

static int sha256_process_full_blocks(sha256_ctx *ctx, const uint8_t *data, uint32_t length)
{
    uint32_t next_state[8];

    if (ctx == NULL)
    {
        return -1;
    }
    if (length == 0u)
    {
        return 0;
    }

    if (sha256_platform_backend_is_active())
    {
        if (sha256_platform_process_blocks_with_state(ctx->state, data, length, next_state) == 0)
        {
            memcpy(ctx->state, next_state, sizeof(next_state));
            return 0;
        }

        sha256_disable_platform_backend("platform continuation failed");
    }

    sha256_process_blocks_software(ctx->state, data, length);
    return 0;
}

void sha256_init(sha256_ctx *ctx)
{
    if (ctx == NULL)
    {
        return;
    }

    sha256_state_init(ctx->state);
    ctx->count = 0u;
    ctx->error = SHA256_ERR_NONE;
    memset(ctx->buffer, 0, sizeof(ctx->buffer));
}

int sha256_update(sha256_ctx *ctx, const uint8_t *data, size_t len)
{
    size_t offset = 0u;
    size_t buffer_idx = 0u;

    if (ctx == NULL)
    {
        return -1;
    }
    if (ctx->error != SHA256_ERR_NONE)
    {
        return -1;
    }
    if (len == 0u)
    {
        return 0;
    }
    if (data == NULL)
    {
        ctx->error = SHA256_ERR_INPUT_NULL_WITH_LEN;
        return -1;
    }

    buffer_idx = (size_t)(ctx->count % SHA256_BLOCK_BYTES);
    ctx->count += (uint64_t)len;

    if (buffer_idx != 0u)
    {
        const size_t space = SHA256_BLOCK_BYTES - buffer_idx;
        const size_t take = (len < space) ? len : space;
        memcpy(&ctx->buffer[buffer_idx], data, take);

        if ((buffer_idx + take) == SHA256_BLOCK_BYTES)
        {
            if (sha256_process_full_blocks(ctx, ctx->buffer, SHA256_BLOCK_BYTES) != 0)
            {
                ctx->error = SHA256_ERR_HW_WORKSPACE;
                return -1;
            }
            offset += take;
        }
        else
        {
            return 0;
        }
    }

    if ((len - offset) >= SHA256_BLOCK_BYTES)
    {
        const size_t full_blocks_len = ((len - offset) / SHA256_BLOCK_BYTES) * SHA256_BLOCK_BYTES;
        if (sha256_process_full_blocks(ctx, &data[offset], (uint32_t)full_blocks_len) != 0)
        {
            ctx->error = SHA256_ERR_HW_WORKSPACE;
            return -1;
        }
        offset += full_blocks_len;
    }

    if (offset < len)
    {
        memcpy(ctx->buffer, &data[offset], len - offset);
    }

    return 0;
}

int sha256_final(sha256_ctx *ctx, uint8_t *hash)
{
    size_t buffer_idx;
    uint64_t bit_count;

    if (ctx == NULL || hash == NULL)
    {
        return -1;
    }
    if (ctx->error != SHA256_ERR_NONE)
    {
        return -1;
    }

    buffer_idx = (size_t)(ctx->count % SHA256_BLOCK_BYTES);
    bit_count = ctx->count * 8u;

    ctx->buffer[buffer_idx++] = 0x80u;

    if (buffer_idx > 56u)
    {
        memset(&ctx->buffer[buffer_idx], 0, SHA256_BLOCK_BYTES - buffer_idx);
        if (sha256_process_full_blocks(ctx, ctx->buffer, SHA256_BLOCK_BYTES) != 0)
        {
            ctx->error = SHA256_ERR_HW_STATUS;
            return -1;
        }
        buffer_idx = 0u;
    }

    memset(&ctx->buffer[buffer_idx], 0, 56u - buffer_idx);
    for (uint32_t i = 0u; i < 8u; i++)
    {
        ctx->buffer[56u + i] = (uint8_t)(bit_count >> (56u - (8u * i)));
    }

    if (sha256_process_full_blocks(ctx, ctx->buffer, SHA256_BLOCK_BYTES) != 0)
    {
        ctx->error = SHA256_ERR_HW_TIMEOUT;
        return -1;
    }

    sha256_store_digest_from_state(ctx->state, hash);
    return 0;
}

int xmss_sha256_wrapper(const unsigned char *in, unsigned long long inlen, unsigned char *out)
{
    sha256_ctx ctx;
    bool handled = false;

    if (out == NULL)
    {
        return -1;
    }
    if (in == NULL && inlen != 0u)
    {
        return -1;
    }
    if (inlen > (unsigned long long)(~(size_t)0))
    {
        return -1;
    }

    if (sha256_platform_backend_is_active())
    {
        const int fixed_rc = sha256_platform_fixed_dispatch(in, inlen, out, &handled);
        if (fixed_rc == 0 && handled)
        {
            return 0;
        }
        if (handled && fixed_rc != 0)
        {
            sha256_disable_platform_backend("platform one-shot backend failed");
        }
    }

    sha256_init(&ctx);
    if (sha256_update(&ctx, in, (size_t)inlen) != 0)
    {
        return -1;
    }
    return sha256_final(&ctx, out);
}
