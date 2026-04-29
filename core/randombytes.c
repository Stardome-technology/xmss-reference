#include <stddef.h>
#include <stdlib.h>

#include "xmss_callbacks.h"

static rng_cb_t rng_cb = NULL;

int xmss_set_rng_cb(rng_cb_t cb)
{
    if (cb == NULL) {
        return -1;
    }
    rng_cb = cb;
    return 0;
}

void randombytes(unsigned char *x, unsigned long long xlen)
{
    if (rng_cb == NULL) {
        abort();
    }

    if (rng_cb(x, (size_t)xlen) != 0) {
        abort();
    }
}
