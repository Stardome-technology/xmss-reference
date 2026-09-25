#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "hash.h"
#include "hash_address.h"
#include "params.h"
#include "utils.h"
#include "wots.h"
#include "xmss_accel.h"
#include "xmss_commons.h"
#include "xmss_core.h"

static unsigned checks;
static unsigned failures;

#define CHECK(condition, message) do { \
    checks++; \
    if (!(condition)) { failures++; printf("FAIL: %s\n", (message)); } \
} while (0)

typedef struct {
    unsigned prf_calls;
    unsigned h_msg_calls;
    unsigned wots_calls;
    unsigned gen_leaf_calls;
    unsigned thash_h_calls;
    unsigned wots_chain_calls;
    int fail_h_msg;
    int fail_wots_chain;
    int pending_wots_chain;
} provider_state_t;

static xmss_accel_result_t provider_prf(
    void *context, const xmss_params *params, unsigned char *out,
    const unsigned char input[32], const unsigned char *key)
{
    provider_state_t *state = context;
    state->prf_calls++;
    return prf(params, out, input, key) == 0 ?
        XMSS_ACCEL_OK : XMSS_ACCEL_ERROR;
}

static xmss_accel_result_t provider_h_msg(
    void *context, const xmss_params *params, unsigned char *out,
    const unsigned char *r, const unsigned char *root, uint64_t index,
    const unsigned char *message, unsigned long long message_length)
{
    provider_state_t *state = context;
    const size_t prefix = params->padding_len + 3U * params->n;
    unsigned char *buffer;
    int result;
    state->h_msg_calls++;
    if (state->fail_h_msg) return XMSS_ACCEL_ERROR;
    if (message_length > (unsigned long long)(SIZE_MAX - prefix)) {
        return XMSS_ACCEL_ERROR;
    }
    buffer = malloc(prefix + (size_t)message_length);
    if (buffer == NULL) return XMSS_ACCEL_ERROR;
    memset(buffer, 0, prefix);
    memcpy(buffer + prefix, message, (size_t)message_length);
    result = hash_message(params, out, r, root, index, buffer, message_length);
    free(buffer);
    return result == 0 ? XMSS_ACCEL_OK : XMSS_ACCEL_ERROR;
}

static xmss_accel_result_t provider_wots_sign(
    void *context, const xmss_params *params, unsigned char *signature,
    const unsigned char *message, const unsigned char *sk_seed,
    const unsigned char *pub_seed, const uint32_t ots_addr[8])
{
    provider_state_t *state = context;
    uint32_t address[8];
    state->wots_calls++;
    memcpy(address, ots_addr, sizeof(address));
    wots_sign(params, signature, message, sk_seed, pub_seed, address);
    return XMSS_ACCEL_OK;
}

static xmss_accel_result_t provider_gen_leaf(
    void *context, const xmss_params *params, unsigned char *leaf,
    const unsigned char *sk_seed, const unsigned char *pub_seed,
    const uint32_t ltree_addr[8], const uint32_t ots_addr[8])
{
    provider_state_t *state = context;
    uint32_t ltree[8];
    uint32_t ots[8];
    state->gen_leaf_calls++;
    memcpy(ltree, ltree_addr, sizeof(ltree));
    memcpy(ots, ots_addr, sizeof(ots));
    gen_leaf_wots(params, leaf, sk_seed, pub_seed, ltree, ots);
    return XMSS_ACCEL_OK;
}

static xmss_accel_result_t provider_thash_h(
    void *context, const xmss_params *params, unsigned char *out,
    const unsigned char *input, const unsigned char *pub_seed,
    const uint32_t node_addr[8])
{
    provider_state_t *state = context;
    uint32_t address[8];
    state->thash_h_calls++;
    memcpy(address, node_addr, sizeof(address));
    return thash_h(params, out, input, pub_seed, address) == 0 ?
        XMSS_ACCEL_OK : XMSS_ACCEL_ERROR;
}

static xmss_accel_result_t provider_wots_chain(
    void *context, const xmss_params *params, unsigned char *out,
    const unsigned char *input, const unsigned char *pub_seed,
    const uint32_t ots_addr[8], unsigned int start, unsigned int steps)
{
    provider_state_t *state = context;
    uint32_t address[8];
    unsigned int i;
    state->wots_chain_calls++;
    if (state->fail_wots_chain) return XMSS_ACCEL_ERROR;
    if (state->pending_wots_chain) {
        state->pending_wots_chain = 0;
        return XMSS_ACCEL_PENDING;
    }
    memcpy(address, ots_addr, sizeof(address));
    memcpy(out, input, params->n);
    for (i = start; i < start + steps && i < params->wots_w; ++i) {
        set_hash_addr(address, i);
        if (thash_f(params, out, out, pub_seed, address) != 0)
            return XMSS_ACCEL_ERROR;
    }
    return XMSS_ACCEL_OK;
}

static xmss_accel_provider_t provider(provider_state_t *state)
{
    xmss_accel_provider_t result;
    memset(&result, 0, sizeof(result));
    result.context = state;
    result.prf = provider_prf;
    result.h_msg = provider_h_msg;
    result.wots_sign = provider_wots_sign;
    result.gen_leaf = provider_gen_leaf;
    result.thash_h = provider_thash_h;
    result.wots_chain = provider_wots_chain;
    return result;
}

int main(void)
{
    xmss_params params;
    unsigned char seed[96];
    unsigned char message[32];
    unsigned char pk_software[64];
    unsigned char sk_software[133];
    unsigned char pk_provider[64];
    unsigned char sk_provider[133];
    unsigned char sm_software[18469 + 32];
    unsigned char sm_provider[18469 + 32];
    unsigned long long software_length = 0;
    unsigned long long provider_length = 0;
    provider_state_t state;
    xmss_accel_provider_t hooks;
    size_t i;

    CHECK(xmssmt_parse_oid(&params, 0x0000002dU) == 0,
          "parse SHAKE256_40/8 OID");
    for (i = 0; i < sizeof(seed); ++i) seed[i] = (unsigned char)i;
    for (i = 0; i < sizeof(message); ++i)
        message[i] = (unsigned char)(0xA5U ^ (unsigned char)(i * 0x3DU));

    CHECK(xmssmt_core_seed_keypair(&params, pk_software, sk_software,
                                   seed) == 0,
          "software keypair");
    CHECK(xmssmt_core_sign(&params, sk_software, sm_software,
                           &software_length, message, sizeof(message)) == 0,
          "software signature");

    memset(&state, 0, sizeof(state));
    hooks = provider(&state);
    CHECK(xmssmt_core_seed_keypair_with_provider(
              &params, pk_provider, sk_provider, seed, &hooks) == 0,
          "provider keypair");
    CHECK(memcmp(pk_provider, pk_software, sizeof(pk_provider)) == 0,
          "provider public key equals software");
    CHECK(state.gen_leaf_calls == 32U && state.thash_h_calls == 31U,
          "keypair provider command counts");

    memset(&state, 0, sizeof(state));
    CHECK(xmssmt_core_sign_with_provider(
              &params, sk_provider, sm_provider, &provider_length, message,
              sizeof(message), &hooks) == 0,
          "provider signature");
    CHECK(provider_length == software_length &&
          memcmp(sm_provider, sm_software, (size_t)provider_length) == 0,
          "provider signature equals software");
    CHECK(state.prf_calls == 1U && state.h_msg_calls == 1U &&
          state.wots_calls == 8U && state.gen_leaf_calls == 256U &&
          state.thash_h_calls == 248U,
          "uncached provider uses canonical 514-operation schedule");

    memcpy(sk_provider, sk_software, sizeof(sk_provider));
    ull_to_bytes(sk_provider, params.index_bytes, 0U);
    memset(&state, 0, sizeof(state));
    state.fail_h_msg = 1;
    provider_length = 123U;
    CHECK(xmssmt_core_sign_with_provider(
              &params, sk_provider, sm_provider, &provider_length, message,
              sizeof(message), &hooks) == -3,
          "provider error propagates");
    CHECK(provider_length == 0U, "provider error withholds signed message");
    CHECK(state.prf_calls == 1U && state.h_msg_calls == 1U &&
          state.wots_calls == 0U && state.gen_leaf_calls == 0U &&
          state.thash_h_calls == 0U,
          "provider error stops subsequent work");

    /* wots_chain dispatch: canonical verify through the provider. */
    {
        unsigned char recovered[18469U + 32U];
        unsigned long long recovered_length = 0U;
        memset(&state, 0, sizeof(state));
        CHECK(xmssmt_core_sign_open_with_provider(
                  &params, recovered, &recovered_length, sm_software,
                  software_length, pk_software, &hooks) == 0,
              "provider-aware verify accepts canonical");
        CHECK(recovered_length == sizeof(message) &&
              memcmp(recovered, message, sizeof(message)) == 0,
              "provider-aware verify recovers message");
        CHECK(state.h_msg_calls == 1U && state.wots_chain_calls == 536U &&
              state.thash_h_calls == 568U,
              "provider-aware verify uses canonical 1105-operation schedule");
    }

    /* wots_chain PENDING: the next visit repeats the identical callback. */
    {
        unsigned char recovered[18469U + 32U];
        unsigned long long recovered_length = 0U;
        memset(&state, 0, sizeof(state));
        state.pending_wots_chain = 1;
        CHECK(xmssmt_core_sign_open_with_provider(
                  &params, recovered, &recovered_length, sm_software,
                  software_length, pk_software, &hooks) == 0,
              "provider-aware verify survives a pending wots_chain");
        CHECK(state.wots_chain_calls == 537U,
              "pending wots_chain is revisited without advancing");
    }

    /* wots_chain ERROR: verification fails terminally without fallback. */
    {
        unsigned char recovered[18469U + 32U];
        unsigned long long recovered_length = 0U;
        memset(&state, 0, sizeof(state));
        state.fail_wots_chain = 1;
        recovered_length = 123U;
        CHECK(xmssmt_core_sign_open_with_provider(
                  &params, recovered, &recovered_length, sm_software,
                  software_length, pk_software, &hooks) != 0,
              "provider wots_chain error fails verification");
        CHECK(recovered_length == 0U,
              "provider wots_chain error withholds the message");
        CHECK(state.wots_chain_calls == 1U,
              "provider wots_chain error stops subsequent work");
    }

    /* Null provider falls back to software verification. */
    {
        unsigned char recovered[18469U + 32U];
        unsigned char wrapper_recovered[18469U + 32U];
        unsigned long long recovered_length = 0U;
        unsigned long long wrapper_length = 0U;
        CHECK(xmssmt_core_sign_open_with_provider(
                  &params, recovered, &recovered_length, sm_software,
                  software_length, pk_software, NULL) == 0,
              "null-provider verify accepts canonical");
        CHECK(recovered_length == sizeof(message) &&
              memcmp(recovered, message, sizeof(message)) == 0,
              "null-provider verify recovers message");
          CHECK(xmssmt_core_sign_open(
                &params, wrapper_recovered, &wrapper_length, sm_software,
                software_length, pk_software) == 0,
              "provider-less core verify accepts canonical");
          CHECK(wrapper_length == recovered_length &&
              memcmp(wrapper_recovered, recovered,
                   (size_t)recovered_length) == 0,
              "provider-less core verify equals null-provider wrapper");
    }

    printf("Acceleration provider checks: %u, failures: %u\n", checks,
           failures);
    return failures == 0U ? 0 : 1;
}
