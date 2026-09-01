# ratelimiter

`github.com/dash-xd/ratelimiter` is the public Go component for compact rate/lifecycle policy declarations and Redis-owned live enforcement state.

Redis/Lua mechanics live under `internal/`, executables live under `cmd/`, and executable behavior is selected through opaque profile packages.

## Authority boundaries

Ratelimiter owns versioned `PolicyCode` encoding/decoding, explicit policy descriptors and validation, entitlement ceilings, profile capability checks, Redis Function definitions for rate/lifecycle state, absolute timer semantics, and the runtime Redis command contract needed by those Functions.

Ratelimiter does **not** own pricing, billing, durable deployment registration, destructive cleanup authority, Terraform state, or proof that a resource is absent. Commercial plans may map to ratelimiter entitlements while usage accounting remains independent.

## Policy v2

V2 deliberately favors explicit domain data over compressed mathematical inference.

```text
PolicySpec
  rate          RateID       // sustained requests/second
  burst         CountID      // burst capacity
  publishes     CountID      // total publish ceiling
  duration      DurationID
  concurrency   CountID
  features      PolicyFeature bitset
        |
        v
EncodePolicy
        |
        v
PolicyCode uint64
```

`RateID`, `CountID`, and `DurationID` are separate opaque stable wire identities. Their numeric IDs have no ordering semantics. Descriptor registries map them to actual requests/second, counts, and wall-clock durations.

This separation is intentional: a rate has units and must not be treated as the same quantity as a burst capacity, publish total, or concurrency count.

Adding a supported value means assigning a new unused ID in the appropriate registry. Existing IDs never move. Semantic comparisons use descriptor values, never raw IDs.

`LimitID`, `ScaleClass`, and `DurationClass` remain migration aliases where practical, but v2 does not use the old exponent/mantissa scale encoding and does not treat duration IDs as ordinal enums.

### Wire layout

V2 keeps the compact 64-bit envelope:

```text
bits  0..7   rate RateID
bits  8..15  burst CountID
bits 16..23  publishes CountID
bits 24..31  duration DurationID
bits 32..39  concurrency CountID
bits 40..55  feature mask
bits 56..59  reserved, must be zero
bits 60..63  version
```

New encodes use version `2`.

There is deliberately no pricing tier, allocation strategy, or synthetic resource currency in the wire code.

The v1 decoder is migration-only. It decodes the old exponent/mantissa scale field into the actual numeric value and then looks up that value in the appropriate v2 registry. Legacy duration codes are translated explicitly. If no exact v2 descriptor exists, migration fails closed rather than silently changing the policy.

For example, v1 had `20m = 7` and later appended `10m = 15`. V2 uses `10m = 7` and `20m = 8`; the version field disambiguates them.

## Entitlements, tiers, usage, and burst

V2 removes the synthetic cross-axis `EnergyCost` allocator. A plan/security boundary is a set of explicit independent ceilings:

```text
Entitlement
  features
  max sustained requests/second
  max burst capacity
  max publishes
  max duration
  max concurrency
```

That maps cleanly to tiered plus usage-based pricing. A tier can grant, for example, a sustained 100 requests/second and burst capacity 500, while metering separately records actual consumption for usage billing.

Burst remains a first-class policy axis, separate from sustained rate. Representation is not the same as enforcement: a selected profile must advertise `CapabilityBurst` before a burst-bearing policy can execute. Until a profile implements burst, validation fails rather than pretending the ceiling is enforced. The same rule applies to concurrency.

This is a security property: a policy cannot claim a capability that its runtime path does not actually implement.

## Requirements and capabilities

Policy requirements and executable profile capabilities remain separate:

```text
PolicySpec requirements
        |
        v
ValidatePolicy
        ^
        |
selected Profile capabilities
```

A field being representable in `PolicySpec` does not imply every profile can enforce it.

## Profile composition

| Import | Redis state | Publishes | Lifecycle timers |
| --- | --- | --- | --- |
| `profile/minimal` | window ZSET | nothing | no |
| `profile/preflight` | window ZSET + lifecycle keys | `preflight` | yes |
| `profile/decisions` | window ZSET + blocked streak | `allowed` or `blocked` | no |
| `profile/lifecycle` | window ZSET + blocked streak + lifecycle keys | `preflight`, `allowed`/`blocked`, shutdown | yes |

`ratelimiter.Profile` is opaque. Profile packages are the supported constructors so callers do not couple themselves to Redis library/function names or internal flags.

## Lifecycle policies

Named lifecycle policies such as `smoke-10m` are human aliases that compile to canonical `PolicySpec` and versioned `PolicyCode`. Durable owners persist the code plus original activation/deadline; names remain navigation/configuration metadata.

Durable lifecycle owners persist original activation plus `PolicyCode`, derive the absolute deadline once, and reconstruct live Redis state with `Limiter.ArmTimerAt`:

```text
persisted activated_at + decoded PolicyCode
             |
             v
       absolute deadline
             |
             v
      Limiter.ArmTimerAt
             |
             v
 Redis ZSET deadline + callback payload hash
```

`reset=false` preserves the first live deadline. Reconstruction may repair missing callback payload without extending the timer. `Limiter.Tick` is only a clock pulse; Redis owns due evaluation and dispatch. Missing/malformed callback state or a shutdown target with no subscriber leaves the timer pending. `Limiter.CancelTimer` is idempotent.

## Bootstrap and runtime authority

`RedisStore.Bootstrap` performs `FUNCTION LOAD REPLACE` and belongs to privileged bootstrap authority.

Redis Functions execute under the caller ACL. Runtime authority is therefore **not** `+FCALL` alone: lifecycle callers need the exact command set returned by `TimerRuntimeACLCommands(profile)`, plus narrowly scoped key/channel patterns. Bootstrap/admin commands such as `FUNCTION`, `CONFIG`, and `ACL` remain excluded.

`WorkerKeyspace` builds literal scope-first Redis prefixes for independently ACL-scoped workers/subsystems. It rejects delimiters, glob characters, hash-tag characters, whitespace, empty segments, and silent normalization so an ACL namespace cannot accidentally broaden through user-supplied pattern syntax.

## Design rule

Use mathematics where it describes a real mechanical structure: token buckets, hashing, partitioning, bounded allocation, subnet sizing, shard/fanout geometry, or capacity planning. Keep business and security semantics explicit when a compact mathematical encoding would obscure what a value actually means.

The objective is not to avoid mathematical structure. It is to keep each useful mathematical invariant local, testable, and subordinate to the system contract.

## Qualification

Required coverage includes v2 round trips/reserved-bit rejection, unknown descriptor rejection, v1 migration fixtures including historical `10m = 15`, independent rate/count/duration semantics, named lifecycle compilation, exact deadline reconstruction, entitlement and profile-capability rejection, Redis lifecycle behavior, subscriber-required shutdown delivery, runtime ACL denial tests, strict keyspace validation, and exact Logma + ratelimiter + Redis composition.

`.github/requests/test.txt` is the push pseudo-dispatch trigger. A source commit is not qualified merely because it exists; consumers should pin a revision contained in an exact successful qualification run.
