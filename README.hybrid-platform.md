# Hybrid FPGA platform branch

## Purpose

The `hybrid-platform` branch is derived from Stardome's
`stardome-stripped-v2` branch at commit
`c689fd1` (`Merge pull request #4 from Stardome-technology/dev-v2`). It adds a
platform-neutral way for a consuming embedded application to execute selected
XMSSMT primitives on an external FPGA.

The change does **not** move the XMSSMT algorithm into the FPGA. The reference
implementation remains responsible for:

- parameter and OID interpretation;
- signature-index handling;
- layer, tree, leaf, and address scheduling;
- TreeHash traversal and authentication-path selection;
- signature and key serialization; and
- verification composition and final-root comparison.

The FPGA is an optional primitive executor. The consuming platform translates
the neutral callbacks into its own transport. The reference has no dependency
on SAMV71, Harmony, SPI/QSPI, USB, FPGA registers, or product storage types.

## Why the original branch needed an extension

The original `stardome-stripped-v2` implementation called its C primitives
directly and completed key generation or signing in one synchronous call. That
was correct for a software-only implementation, but it did not provide a safe
boundary for an external accelerator:

1. A platform could not replace only an eligible primitive without replacing
   or duplicating the XMSSMT orchestration.
2. A transport failure could not be distinguished from an unsupported
   acceleration shape, making silent software fallback hazardous.
3. One FPGA command may require request submission, acceptance confirmation,
   bounded status polling, response transfer, and validation. A monolithic
   reference call could hide that complete wait loop.
4. Cancellation could stop MCU computation but could not notify a provider
   that owned an in-flight accelerator request.
5. A global callback or symbol override would hide provider lifetime,
   concurrency, and test ownership.

The branch addresses these limitations while retaining the original public
software entry points.

## Acceleration-provider contract

`core/xmss_accel.h` defines an explicitly injected provider with a caller-owned
context. It exposes callbacks for:

- production entropy;
- PRF;
- H_MSG;
- WOTS_SIGN;
- GEN_LEAF;
- THASH_H;
- one bounded WOTS chain segment for verification;
- progress observation;
- cancellation observation; and
- aborting provider-owned in-flight work.

The selected primitive granularity is intentional. WOTS_SIGN and GEN_LEAF
encapsulate their many internal WOTS/THASH_F operations, avoiding excessive
transport traffic while leaving the reference in control of the XMSSMT
schedule.

Provider callbacks return one of four results:

- `XMSS_ACCEL_OK`: the requested output is complete and valid;
- `XMSS_ACCEL_NOT_HANDLED`: the provider does not support this valid shape, so
  and only so may the reference software implementation run;
- `XMSS_ACCEL_PENDING`: the operation is still active; a resumable caller must
  revisit the same primitive without advancing its phase or primitive count;
- `XMSS_ACCEL_ERROR`: the provider attempted the operation and failed; the
  reference operation terminates without software recomputation.

This fail-closed distinction is load-bearing. An FPGA, transport, protocol, or
result-validation error must never be disguised by calculating a replacement
result in software.

## Resumable reference engine

`core/xmss_resumable.c` and `core/xmss_resumable.h` provide shared state
machines for key generation, signing, and verification:

```text
xmssmt_keygen_init / step / finish / abort
xmssmt_sign_init   / step / finish / abort
xmssmt_verify_init / step / finish / abort
```

Each step performs at most one provider-primitive visit or one local algorithm
transition. A `PENDING` result keeps the same phase, addresses, output pointer,
and primitive count. Cancellation invokes the provider's optional `abort`
callback before the reference state becomes cancelled.

The ordinary synchronous functions drive these same state machines to
completion. Consequently, synchronous and cooperative operation do not contain
separate production algorithms that could drift apart. The former synchronous
bodies are retained only behind differential-test macros and are excluded from
normal builds.

## Public API compatibility

The original entry points remain available and select the software path by
passing no provider:

```c
xmssmt_keypair(...);
xmssmt_sign(...);
```

Provider-aware entry points are additive:

```c
xmssmt_keypair_with_provider(..., const xmss_accel_provider_t *provider);
xmssmt_sign_with_provider(..., const xmss_accel_provider_t *provider);
xmssmt_sign_open_with_provider(..., const xmss_accel_provider_t *provider);
```

Verification remains reference-owned. A null provider or a valid
`XMSS_ACCEL_NOT_HANDLED` response selects the existing software primitive;
provider-aware verification may accelerate H_MSG, one WOTS chain at a time,
and THASH_H while the reference retains layer/address scheduling, L-tree and
authentication-path composition, and final-root comparison. The cooperative
verifier completes the supported canonical walk in 1105 provider primitives.
`PENDING` repeats the identical primitive visit; `ERROR` is terminal and never
falls back to software.

## Key-generation entropy

Provider-aware key generation may obtain independent `SK_SEED`, `SK_PRF`, and
`PUB_SEED` material through the provider's entropy callback. A
`NOT_HANDLED` result permits the original random source. An entropy `ERROR`
terminates key generation and does not silently switch sources. Temporary seed
storage is cleared before returning.

The provider is called three times with exactly `n` bytes, once per seed. If
the first request is not handled, the original software source fills all three
seeds; a provider that starts handling the sequence must complete all three or
the operation fails. Public and secret keys are staged and copied to caller
buffers only after the full accelerated root construction succeeds.

The provider then accelerates eligible GEN_LEAF and THASH_H operations while
the reference constructs and serializes the key in its normal format.

## Consuming-platform responsibilities

The consuming project must:

- own the provider context for the entire active operation;
- serialize access to a stateful accelerator;
- validate the exact supported parameter shape before claiming a callback;
- map real transport and accelerator failures to `XMSS_ACCEL_ERROR`;
- return `NOT_HANDLED` only for a valid, deliberately unsupported shape;
- preserve provider output storage across `PENDING` visits;
- implement bounded transport polling and recovery;
- abort in-flight transport work when the reference calls provider `abort`;
- reserve stateful XMSS indices durably before signing; and
- publish keys or signatures only after complete success.

Persistence, authorization, key lifecycle, index reservation, USB behavior,
and hardware transport policy intentionally remain outside this repository.

## Tested compatibility boundary

The branch has been tested against the consuming CMODS7 HAT production-source
mock for `XMSSMT-SHAKE256_40/8_256`. Current evidence includes:

- software-provider regression: 12 checks, 0 failures;
- resumable-engine regression: 25 checks, 0 failures;
- production-source HAT reference-platform mock: 240 checks, 0 failures;
- key generation through 32 GEN_LEAF and 31 THASH_H operations;
- signing through the canonical 514 primitive operations;
- verification through the canonical 1105 primitive operations;
- byte-identical 18,469-byte canonical signature output;
- accelerated index-one output equal to the independent software path;
- terminal provider-error behavior without software fallback at PRF, H_MSG,
  WOTS_SIGN, WOTS_CHAIN, GEN_LEAF, and THASH_H boundaries;
- failure-atomic signature publication through the consuming HAT staging layer;
- volatile-store zeroization of resumable key-generation/signing secrets on
  finish, failure, and cancellation;
- cancellation of provider-owned in-flight work; and
- synchronous/cooperative execution through the same state machines.

These tests establish the integration architecture; they do not by themselves
constitute final physical-hardware, timing, lifecycle, or persistence
acceptance.

## Current limitations and open work

- The maintained remote and final dependency pin have not yet been selected.
- The consuming HAT provider currently accepts only the frozen
  `XMSSMT-SHAKE256_40/8_256` shape.
- The resumable workspace currently accepts `full_height < 64`; other OIDs and
  height-64 behavior require separate review and tests.
- Physical-target inspection of secret-zeroization remains part of final HAT
  integration; host acceptance covers the reference engine and consuming HAT
  staging boundary.
- Provider lifetime, replacement, teardown, and concurrency require further
  acceptance tests.
- Physical FPGA key-generation/signing equivalence and measured step timing
  remain outside the present host evidence.

Until those gates are complete, this branch should be treated as a tested local
integration branch rather than a published maintained dependency.

## Branch commits

The architectural changes were introduced in three local commits:

- `e121a8c`: neutral fail-closed acceleration provider;
- `e541bfd`: shared context-based resumable key-generation/signing engines;
- `d5e41af`: pending-aware provider execution and cancellation cleanup.

Consumers should pin a full remotely reachable commit hash only after the
publication and provenance gate is explicitly approved.
