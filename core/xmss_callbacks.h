#ifndef XMSS_CALLBACKS_H
#define XMSS_CALLBACKS_H

#include <stddef.h>

/* Callback used for SHA and RNG operations. */
typedef int (*sha_cb_t)(const unsigned char *in, unsigned long long inlen,
                        unsigned char *out);
typedef int (*rng_cb_t)(void * output, size_t length);

int xmss_set_sha_cb(sha_cb_t cb);
int xmss_set_rng_cb(rng_cb_t cb);

#endif
