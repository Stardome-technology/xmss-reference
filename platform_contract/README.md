# Platform Contract

This directory documents the contract between the reusable XMSS `core/` and any
consumer-owned platform layer.

## Scope

The contract is deliberately narrow. `core/` owns XMSS parameter parsing, keygen,
sign, verify, hashing orchestration, and internal workspace management. Consumers
own wrapper APIs, persistence strategy, timing/logging, and any hardware-specific
acceleration.

## Required integration points

Consumers must register the following callbacks before invoking XMSS operations that
depend on them:

1. SHA callback via `xmss_set_sha_cb()`
2. RNG callback via `xmss_set_rng_cb()`

The callback typedefs live in `core/xmss_callbacks.h`:

- `sha_cb_t`: computes SHA-256 over the provided input buffer into the output buffer
- `rng_cb_t`: fills a caller-provided output buffer with random bytes

## Intentionally out of scope

The public contract does not define a canonical implementation for:

- boot-time or runtime initialization wrappers
- detached-signature formatting helpers
- filesystem, flash, or monotonic-index persistence
- console logging or time measurement
- hardware SHA or FPGA acceleration dispatch

Those concerns belong in the consumer repository, not in the public XMSS reference.

## Consumer examples by role

- Embedded consumers can provide an MCU-specific platform layer for flash, timing,
  and acceleration.
- Host consumers can provide an x86 software-only platform layer and any file or
  CLI convenience wrappers they need.

Both classes of consumer should compile the same `core/` sources.