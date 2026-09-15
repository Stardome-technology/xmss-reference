#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "params.h"
#include "xmss_core.h"
#include "xmss_resumable.h"

static unsigned int checks;
static unsigned int failures;

#define CHECK(condition, message) do {                                      \
    ++checks;                                                               \
    if (!(condition)) {                                                     \
        ++failures;                                                         \
        printf("FAIL: %s\n", (message));                                  \
    }                                                                       \
} while (0)

static int all_bytes_are(const unsigned char *bytes, size_t length,
                         unsigned char value)
{
    size_t i;
    for (i = 0U; i < length; ++i)
        if (bytes[i] != value) return 0;
    return 1;
}

typedef struct {
    unsigned int progress_calls;
    unsigned int cancel_after;
} observer_t;

static void observe_progress(void *context, unsigned int primitive_count,
                             unsigned int layer, uint32_t leaf)
{
    observer_t *observer = (observer_t *)context;
    (void)layer;
    (void)leaf;
    observer->progress_calls = primitive_count;
}

static int observe_cancel(void *context)
{
    observer_t *observer = (observer_t *)context;
    return observer->cancel_after != 0U &&
           observer->progress_calls >= observer->cancel_after;
}

static int drive(xmssmt_sign_state_t *state)
{
    xmss_resumable_result_t result;
    unsigned int transitions = 0U;
    do {
        result = xmssmt_sign_step(state);
        ++transitions;
        if (transitions > 2048U) return -1;
    } while (result == XMSS_RESUMABLE_MORE);
    return result == XMSS_RESUMABLE_DONE ? 0 : (int)result;
}

int main(void)
{
    xmss_params params;
    unsigned char seed[96];
    unsigned char message[32];
    unsigned char public_key[64];
    unsigned char original_key[133];
    unsigned char synchronous_key[133];
    unsigned char resumable_key[133];
    unsigned char cancelled_key[133];
    unsigned char synchronous[18469U + 32U];
    unsigned char resumable[18469U + 32U];
    unsigned char cancelled_output[18469U + 32U];
    unsigned long long synchronous_length = 0U;
    unsigned long long resumable_length = 0U;
    xmssmt_sign_state_storage_t storage;
    xmssmt_sign_state_t *state = NULL;
    xmssmt_keygen_state_storage_t keygen_storage;
    xmssmt_keygen_state_t *keygen_state = NULL;
    unsigned char resumable_pk[64];
    unsigned char resumable_sk[133];
    unsigned char cancelled_pk[64];
    unsigned char cancelled_sk[133];
    xmssmt_keygen_state_storage_t cancelled_keygen_storage;
    xmssmt_keygen_state_t *cancelled_keygen_state = NULL;
    xmss_accel_provider_t provider;
    observer_t observer;
    size_t i;

    CHECK(xmssmt_parse_oid(&params, 0x0000002dU) == 0,
          "parse SHAKE256_40/8 OID");
    for (i = 0U; i < sizeof(seed); ++i) seed[i] = (unsigned char)i;
    for (i = 0U; i < sizeof(message); ++i)
        message[i] = (unsigned char)(0xA5U ^ (unsigned char)(i * 0x3DU));
    CHECK(xmssmt_core_seed_keypair(&params, public_key, original_key, seed) == 0,
          "build deterministic keypair");
    memset(resumable_pk, 0xA5, sizeof(resumable_pk));
    memset(resumable_sk, 0xA5, sizeof(resumable_sk));
    CHECK(xmssmt_keygen_init(&keygen_storage, &params, NULL, resumable_pk,
                             resumable_sk, seed, &keygen_state) == 0,
          "initialize resumable key generation");
    {
        xmss_resumable_result_t keygen_result;
        unsigned int keygen_steps = 0U;
        do {
            keygen_result = xmssmt_keygen_step(keygen_state);
            ++keygen_steps;
        } while (keygen_result == XMSS_RESUMABLE_MORE && keygen_steps < 256U);
        CHECK(keygen_result == XMSS_RESUMABLE_DONE,
              "drive resumable key generation to completion");
    }
    CHECK(xmssmt_keygen_finish(keygen_state) == 0,
          "finish resumable key generation");
    CHECK(memcmp(resumable_pk, public_key, sizeof(public_key)) == 0 &&
          memcmp(resumable_sk, original_key, sizeof(original_key)) == 0,
          "resumable keypair is byte-identical");
    CHECK(xmssmt_keygen_primitive_count(keygen_state) == 63U,
          "key generation has 32 leaves and 31 hashes");
    CHECK(xmssmt_keygen_test_sensitive_is_zero(keygen_state),
          "finished key generation clears secret staging");

    memset(&provider, 0, sizeof(provider));
    memset(&observer, 0, sizeof(observer));
    observer.cancel_after = 3U;
    provider.context = &observer;
    provider.progress = observe_progress;
    provider.cancel_requested = observe_cancel;
    memset(cancelled_pk, 0xC7, sizeof(cancelled_pk));
    memset(cancelled_sk, 0xC7, sizeof(cancelled_sk));
    CHECK(xmssmt_keygen_init(&cancelled_keygen_storage, &params, &provider,
                             cancelled_pk, cancelled_sk, seed,
                             &cancelled_keygen_state) == 0,
          "initialize cancellable key generation");
    {
        xmss_resumable_result_t keygen_result;
        unsigned int keygen_steps = 0U;
        do {
            keygen_result = xmssmt_keygen_step(cancelled_keygen_state);
            ++keygen_steps;
        } while (keygen_result == XMSS_RESUMABLE_MORE &&
                 keygen_steps < 256U);
        CHECK(keygen_result == XMSS_RESUMABLE_CANCELLED,
              "cancel key generation at a primitive boundary");
    }
    CHECK(all_bytes_are(cancelled_pk, sizeof(cancelled_pk), 0xC7U) &&
          all_bytes_are(cancelled_sk, sizeof(cancelled_sk), 0xC7U),
          "cancelled key generation publishes no key bytes");
    CHECK(xmssmt_keygen_test_sensitive_is_zero(cancelled_keygen_state),
          "cancelled key generation clears secret staging");

    memcpy(synchronous_key, original_key, sizeof(original_key));
    CHECK(xmssmt_core_sign(&params, synchronous_key, synchronous,
                           &synchronous_length, message, sizeof(message)) == 0,
          "synchronous software signature");

    memset(&provider, 0, sizeof(provider));
    memset(&observer, 0, sizeof(observer));
    provider.context = &observer;
    provider.progress = observe_progress;
    provider.cancel_requested = observe_cancel;
    memcpy(resumable_key, original_key, sizeof(original_key));
    memset(resumable, 0xA6, sizeof(resumable));
    CHECK(xmssmt_sign_init(&storage, &params, &provider, resumable_key,
                           resumable, sizeof(resumable), message,
                           sizeof(message), &state) == 0,
          "initialize resumable signer");
    CHECK(drive(state) == 0, "drive resumable signer to completion");
    CHECK(xmssmt_sign_finish(state, &resumable_length) == 0,
          "finish resumable signer");
    CHECK(resumable_length == synchronous_length &&
          memcmp(resumable, synchronous, (size_t)resumable_length) == 0,
          "resumable signature is byte-identical");
    CHECK(memcmp(resumable_key, synchronous_key, sizeof(resumable_key)) == 0,
          "resumable working-key mutation is byte-identical");
    CHECK(xmssmt_sign_primitive_count(state) == 514U &&
          observer.progress_calls == 514U,
          "canonical schedule has 514 bounded primitives");
    CHECK(xmssmt_sign_test_sensitive_is_zero(state),
          "finished signing clears resumable secret workspace");

    memset(&observer, 0, sizeof(observer));
    observer.cancel_after = 3U;
    memcpy(cancelled_key, original_key, sizeof(original_key));
    memset(cancelled_output, 0x5AU, sizeof(cancelled_output));
    CHECK(xmssmt_sign_init(&storage, &params, &provider, cancelled_key,
                           cancelled_output, sizeof(cancelled_output), message,
                           sizeof(message), &state) == 0,
          "initialize cancellable signer");
    CHECK(drive(state) == (int)XMSS_RESUMABLE_CANCELLED,
          "cancellation stops cooperative signer");
    CHECK(xmssmt_sign_finish(state, &resumable_length) != 0,
          "cancelled operation cannot publish a length");
    CHECK(observer.progress_calls == 3U,
          "cancellation occurs at a primitive boundary");
    CHECK(xmssmt_sign_test_sensitive_is_zero(state),
          "cancelled signing clears resumable secret workspace");

    printf("Resumable XMSSMT checks: %u, failures: %u\n", checks, failures);
    return failures == 0U ? 0 : 1;
}
