# ratelimiter

`github.com/dash-xd/ratelimiter` is the authoritative public Go component for encoded rate/lifecycle policy and Redis-owned live enforcement state. `main` is the consolidation line. Historical branches may remain available for reproducibility and smoke-test dependencies, but new consumers should pin an exact `main` revision.

Redis/Lua mechanics live under `internal/`, executables live under `cmd/`, and executable behavior is selected through opaque profile packages.

## Authority boundaries

Ratelimiter owns:

- stable `PolicyCode` encoding/decoding;
- policy requirements, entitlement validation, and allocation;
- opaque profile capability declarations;
- Redis Function definitions for rate and lifecycle state;
- absolute timer arm, tick, and idempotent cancel semantics;
- the runtime Redis command contract needed to execute timer Functions.

Ratelimiter does **not** own durable deployment registration, destructive cleanup authority, Terraform state, or proof that a resource is absent. Those belong to lifecycle supervisors such as Logma/Huram and their cleanup consumers.

## Policy model

`PolicyCode` is a compact durable machine declaration. Its fields are protocol, not ordinary Go enum ordering.

```text
PolicySpec
  rate          ScaleClass
  burst         ScaleClass
  publishes     ScaleClass
  duration      DurationClass wire code
  concurrency   ScaleClass
  strategy      Strategy
  features      PolicyFeature bitset
        |
        v
EncodePolicy
        |
        v
PolicyCode uint64
```

`DurationClass` values are explicit stable wire codes. Semantic duration, allocation order, and energy weight are descriptor data. New human durations receive unused wire values rather than renumbering persisted codes.

Named lifecycle policies such as `smoke-10m` are aliases that compile to canonical `PolicySpec` and `PolicyCode`. Durable owners persist the code plus original activation/deadline; names remain navigation/configuration metadata.

## Requirements and capabilities

Policy requirements and executable profile capabilities are separate axes.

```text
PolicyFeature / PolicySpec requirements
        |
        v
ValidatePolicy
        ^
        |
selected Profile capabilities
```

A field being representable in `PolicySpec` does not imply every profile can enforce it. Validation rejects unsupported Burst, Concurrency, timer, callback, or blocked-state requirements.

## Profile composition

| Import | Redis state | Publishes | Lifecycle timers |
| --- | --- | --- | --- |
| `profile/minimal` | window ZSET | nothing | no |
| `profile/preflight` | window ZSET + lifecycle keys | `preflight` | yes |
| `profile/decisions` | window ZSET + blocked streak | `allowed` or `blocked` | no |
| `profile/lifecycle` | window ZSET + blocked streak + lifecycle keys | `preflight`, `allowed`/`blocked`, shutdown | yes |

`ratelimiter.Profile` is opaque. Profile packages are the supported constructors so callers do not couple themselves to Redis library/function names or internal flags.

## Redis lifecycle timer

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

## Qualification

The lifecycle lineage originates from:

```text
211738d48e33364431a4e4b0613ceac5ea593737
Arm lifecycle timers from absolute deadlines
```

The historical `lifecycle-handoff` and `preflight-lifecycle` branches remain useful provenance/test lines. `main` is the consolidated authority and carries the compatible implementation forward without rewriting those branches.

Required coverage includes:

- `PolicyCode` round trips and reserved-bit rejection;
- historical duration-byte fixtures;
- semantic duration ordering independent of wire values;
- named lifecycle policy compilation;
- original-activation absolute deadline reconstruction;
- entitlement/profile capability rejection;
- scale/allocation edge cases;
- Redis lifecycle arm/tick/cancel behavior;
- subscriber-required shutdown delivery;
- runtime ACL execution with unrelated key/admin-command denial;
- strict scope-first keyspace validation;
- local exact Logma + ratelimiter + Redis composition smoke.

`.github/requests/test.txt` is the push pseudo-dispatch trigger. A source commit is not qualified merely because it exists; consumers should pin a revision that is contained in an exact successful qualification run. The local composition job pins the Logma side by immutable SHA and uses a Go workspace so Logma runs against the ratelimiter checkout being qualified rather than whatever ratelimiter version its `go.mod` happened to record.
