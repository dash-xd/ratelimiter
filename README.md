# ratelimiter

`github.com/dash-xd/ratelimiter` is the public Go component for compact rate/lifecycle policy declarations and Redis-owned live enforcement state.

Redis/Lua mechanics live under `internal/`, executables live under `cmd/`, and executable behavior is selected through opaque profile packages.

## Authority boundaries

Ratelimiter owns:

- versioned `PolicyCode` encoding/decoding;
- explicit policy descriptors and validation;
- entitlement ceilings and profile capability checks;
- Redis Function definitions for rate and lifecycle state;
- absolute timer arm, tick, and idempotent cancel semantics;
- the runtime Redis command contract needed to execute timer Functions.

Ratelimiter does **not** own pricing, billing, durable deployment registration, destructive cleanup authority, Terraform state, or proof that a resource is absent. Commercial plans may map to ratelimiter entitlements, while usage accounting remains an independent concern.

## Policy v2

Policy v2 deliberately favors explicit data over compressed mathematical inference.

```text
PolicySpec
  rate          LimitID
  burst         LimitID
  publishes     LimitID
  duration      DurationID
  concurrency   LimitID
  strategy      Strategy
  features      PolicyFeature bitset
        |
        v
EncodePolicy
        |
        v
PolicyCode uint64
```

`LimitID` and `DurationID` are opaque stable wire identifiers. Their numeric IDs have no magnitude or ordering semantics. Descriptor registries map IDs to concrete limits and durations, and semantic ordering is derived from descriptor values.

Adding a new supported value means assigning a new unused ID and adding a descriptor. Existing IDs do not move.

`ScaleClass` and `DurationClass` remain source-compatibility aliases during migration, but v2 does not use the old exponent/mantissa scale encoding and does not treat duration codes as ordinal enums.

### Wire layout

Policy v2 retains the compact 64-bit envelope:

```text
bits  0..7   rate LimitID
bits  8..15  burst LimitID
bits 16..23  publishes LimitID
bits 24..31  duration DurationID
bits 32..39  concurrency LimitID
bits 40..43  strategy
bits 44..55  features
bits 56..59  reserved, must be zero
bits 60..63  version
```

New encodes use version `2`.

The v1 decoder is migration-only. It translates legacy duration codes explicitly and decodes the old exponent/mantissa limit representation to its actual numeric value before looking that value up in the v2 registry. If no exact v2 descriptor exists, migration fails closed rather than silently changing the policy.

For example, the early v1 duration protocol had `20m = 7` and later appended `10m = 15`. V2 is free to use the clean descriptor IDs `10m = 7`, `20m = 8` because the version field disambiguates the formats.

## Entitlements, tiers, and burst

V2 removes the synthetic cross-axis `EnergyCost` allocator. A plan or security boundary is represented by explicit independent ceilings:

```text
Entitlement
  features
  max rate
  max burst
  max publishes
  max duration
  max concurrency
```

This keeps tiered and usage-based pricing composable instead of embedding pricing math in the wire protocol. A commercial tier can, for example, grant a sustained rate of 100 and a burst ceiling of 500 while usage accounting independently records actual consumption.

Burst is intentionally a separate axis from sustained rate. Representation and entitlement validation do not imply runtime support: a selected profile must advertise `CapabilityBurst` before a burst-bearing policy can be used. Profiles that do not enforce burst fail validation rather than pretending to support it.

The same rule applies to concurrency and other optional axes.

`Strategy` remains a policy/runtime hint. It is no longer used to derive pricing, entitlement, or a synthetic resource currency.

## Requirements and capabilities

Policy requirements and executable profile capabilities are separate axes.

```text
PolicySpec requirements
        |
        v
ValidatePolicy
        ^
        |
selected Profile capabilities
```

A field being representable in `PolicySpec` does not imply every profile can enforce it. Validation rejects unsupported burst, concurrency, timer, callback, or blocked-state requirements.

## Profile composition

| Import | Redis state | Publishes | Lifecycle timers |
| --- | --- | --- | --- |
| `profile/minimal` | window ZSET | nothing | no |
| `profile/preflight` | window ZSET + lifecycle keys | `preflight` | yes |
| `profile/decisions` | window ZSET + blocked streak | `allowed` or `blocked` | no |
| `profile/lifecycle` | window ZSET + blocked streak + lifecycle keys | `preflight`, `allowed`/`blocked`, shutdown | yes |

`ratelimiter.Profile` is opaque. Profile packages are the supported constructors so callers do not couple themselves to Redis library/function names or internal flags.

## Lifecycle policies

Named lifecycle policies such as `smoke-10m` are aliases that compile to canonical `PolicySpec` and versioned `PolicyCode`. Durable owners persist the code plus original activation/deadline; names remain navigation/configuration metadata.

Lifecycle-capable profiles keep live timer state under explicit FCALL keys sharing the bucket's Redis Cluster hash tag.

Durable lifecycle owners persist original activation plus `PolicyCode`, derive the absolute deadline once, and reconstruct live Redis state with `Limiter.ArmTimerAt`.

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

`RedisStore.Bootstrap` performs `FUNCTION LOAD REPLACE` and therefore belongs to privileged bootstrap authority.

Redis Functions execute under the caller ACL. Runtime authority is therefore **not** `+FCALL` alone: lifecycle callers need the exact command set returned by `TimerRuntimeACLCommands(profile)`, plus narrowly scoped key/channel patterns. That declaration excludes bootstrap/admin commands such as `FUNCTION`, `CONFIG`, and `ACL`.

`WorkerKeyspace` builds literal scope-first Redis prefixes for independently ACL-scoped workers/subsystems. It rejects delimiters, glob characters, hash-tag characters, whitespace, empty segments, and silent normalization so an ACL namespace cannot accidentally broaden through user-supplied pattern syntax.

## Design rule

Use mathematics where it describes the infrastructure itself: hashing, partitioning, bounded allocation, subnet sizing, geometric capacity classes, or other mechanically verifiable structure. Do not make a compressed mathematical encoding the source of truth for commercial semantics or policy meaning when explicit descriptors are clearer.

The v2 protocol therefore keeps the useful compactness and bounded registries while making the business/security contract explicit.

## Qualification

Required coverage includes:

- v2 `PolicyCode` round trips and reserved-bit rejection;
- unknown descriptor IDs fail closed;
- v1 migration fixtures, including the historical `10m = 15` case;
- semantic ordering derived independently of wire IDs;
- named lifecycle policy compilation;
- original-activation absolute deadline reconstruction;
- independent entitlement ceiling and profile capability rejection;
- burst independent from sustained rate;
- Redis lifecycle arm/tick/cancel behavior;
- subscriber-required shutdown delivery;
- runtime ACL execution with unrelated key/admin-command denial;
- strict scope-first keyspace validation;
- local exact Logma + ratelimiter + Redis composition smoke.

`.github/requests/test.txt` is the push pseudo-dispatch trigger. A source commit is not qualified merely because it exists; consumers should pin a revision contained in an exact successful qualification run.
