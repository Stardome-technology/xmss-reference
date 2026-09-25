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

## Optional hook seam

Consumers may also register an optional neutral hook table via
`xmssmt_core_hooks_set()` from `core/xmss_core_hooks.h`.

This hook ABI is intended for cross-platform concerns that can remain neutral at the
core boundary:

- sign-timing observation
- cached-auth-path reuse

If no hook table is registered, the core still behaves correctly and falls back to
its normal internal flow.

## Optional acceleration-provider seam

Consumers that implement bounded XMSS primitives in hardware may register an
`xmss_accel_provider_t` from `core/xmss_accel.h`. The stateless core consults the
provider at six natural operation boundaries:

- PRF for signature randomization;
- H_MSG;
- WOTS_SIGN;
- GEN_LEAF during TreeHash; and
- THASH_H during TreeHash, L-tree reduction, and root reconstruction; and
- WOTS_CHAIN for one bounded verification chain segment.

The provider is an implementation service, not an alternative composer. Parameter
selection, index/layer scheduling, structured addresses, TreeHash order, key layout,
and signature serialization remain owned by the core.

Each callback returns one of four outcomes. `XMSS_ACCEL_OK` means the requested
output is complete. `XMSS_ACCEL_NOT_HANDLED` asks the core to execute its existing
software operation. `XMSS_ACCEL_PENDING` requires a resumable caller to revisit
the identical primitive without advancing phase, addresses, output pointer, or
primitive count. `XMSS_ACCEL_ERROR` is terminal and must not silently fall back.
This distinction lets an absent accelerator remain optional without masking a real
transport or hardware failure.

The reference owns verification composition. It derives each base-w digit and
requests WOTS_CHAIN with `start = digit` and `steps = 15 - digit`, performs the
L-tree and authentication-path schedule through THASH_H, and compares the final
root. The provider is still an implementation service, not an alternative
composer; it must not own signature parsing, layer scheduling, or acceptance.

`core/xmss_resumable.h` exposes caller-owned cooperative key-generation,
signing, and verification state. Cancellation and explicit abort release any
provider-owned in-flight primitive through the optional idempotent `abort`
callback. Existing provider-less entry points remain software-compatible.

The initial provider integration applies to the stateless `xmss_core.c` build. The
alternative BDS implementation in `xmss_core_fast.c` is not provider-enabled and
must not be selected by a consumer that requires this ABI.

## Intentionally out of scope

The public contract does not define a canonical implementation for:

- boot-time or runtime initialization wrappers
- detached-signature formatting helpers
- filesystem, flash, or monotonic-index persistence
- console logging or time measurement
- hook implementations themselves
- hardware SHA or FPGA acceleration dispatch

Concrete acceleration drivers remain out of scope even though the neutral provider
ABI is part of the public core contract.

Those concerns belong in the consumer repository, not in the public XMSS reference.

## Consumer examples by role

- Embedded consumers can provide an MCU-specific platform layer for flash, timing,
  and acceleration.
- Host consumers can provide an x86 software-only platform layer and any file or
  CLI convenience wrappers they need.

Both classes of consumer should compile the same `core/` sources.
