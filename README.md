# XMSS Reference

This repository now exposes a narrow public layout:

- `core/`: reusable XMSS implementation sources and headers
- `platform_contract/`: documentation for the external integration contract

The public repo intentionally does not ship a canonical wrapper such as `mcu_xmss.*`.
High-level lifecycle, persistence, logging, timing, detached-signature formatting, and
hardware acceleration policies belong to consuming projects.

## Integration model

Consumers should vendor or submodule this repository and compile against `core/`.
Each consumer is responsible for its own platform layer and wrapper API.

The current low-level public seam is callback-based:

- SHA-256 implementation is injected via `xmss_set_sha_cb()` from `core/xmss_callbacks.h`
- RNG implementation is injected via `xmss_set_rng_cb()` from `core/xmss_callbacks.h`

The core also exposes an optional neutral hook ABI via `core/xmss_core_hooks.h` for
sign-timing observation and cached-auth-path reuse. Consumers may ignore this seam
entirely, or register hook implementations without changing the core algorithm code.

The stateless core additionally exposes the optional acceleration-provider ABI in
`core/xmss_accel.h`. It covers PRF, H_MSG, WOTS signing, WOTS-leaf generation, and
two-node THASH_H while leaving XMSSMT scheduling, addresses, TreeHash, key layout,
and signature serialization in the reference core. A provider reports success,
not-handled, or error. Only not-handled selects the software fallback; provider
errors fail the operation instead of being hidden by fallback.

That keeps the reusable code portable while avoiding a public opinion about board
services, host utilities, or product-specific wrapper behavior.
