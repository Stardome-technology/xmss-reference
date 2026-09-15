#ifndef XMSS_RESUMABLE_H
#define XMSS_RESUMABLE_H

#include <stddef.h>
#include <stdint.h>

#include "params.h"
#include "xmss_accel.h"

typedef enum {
    XMSS_RESUMABLE_ERROR = -1,
    XMSS_RESUMABLE_DONE = 0,
    XMSS_RESUMABLE_MORE = 1,
    XMSS_RESUMABLE_CANCELLED = 2
} xmss_resumable_result_t;

typedef union {
    void *align_ptr;
    uint64_t align_u64;
    unsigned char bytes[4096U];
} xmssmt_sign_state_storage_t;

typedef struct xmssmt_sign_state xmssmt_sign_state_t;

typedef union {
    void *align_ptr;
    uint64_t align_u64;
    unsigned char bytes[4096U];
} xmssmt_keygen_state_storage_t;

typedef struct xmssmt_keygen_state xmssmt_keygen_state_t;

int xmssmt_keygen_init(
    xmssmt_keygen_state_storage_t *storage, const xmss_params *params,
    const xmss_accel_provider_t *provider, unsigned char *public_key,
    unsigned char *secret_key, const unsigned char *seed,
    xmssmt_keygen_state_t **state);

xmss_resumable_result_t xmssmt_keygen_step(xmssmt_keygen_state_t *state);

int xmssmt_keygen_finish(xmssmt_keygen_state_t *state);

void xmssmt_keygen_abort(xmssmt_keygen_state_t *state);

unsigned int xmssmt_keygen_primitive_count(
    const xmssmt_keygen_state_t *state);

int xmssmt_sign_init(
    xmssmt_sign_state_storage_t *storage, const xmss_params *params,
    const xmss_accel_provider_t *provider, unsigned char *working_sk,
    unsigned char *signed_message, size_t signed_message_capacity,
    const unsigned char *message, unsigned long long message_length,
    xmssmt_sign_state_t **state);

xmss_resumable_result_t xmssmt_sign_step(xmssmt_sign_state_t *state);

int xmssmt_sign_finish(xmssmt_sign_state_t *state,
                       unsigned long long *signed_message_length);

void xmssmt_sign_abort(xmssmt_sign_state_t *state);

unsigned int xmssmt_sign_primitive_count(const xmssmt_sign_state_t *state);

#ifdef XMSS_RESUMABLE_TEST_HOOKS
int xmssmt_keygen_test_sensitive_is_zero(
    const xmssmt_keygen_state_t *state);
int xmssmt_sign_test_sensitive_is_zero(const xmssmt_sign_state_t *state);
#endif

#endif
