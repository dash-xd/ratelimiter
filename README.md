# ratelimiter: lifecycle handoff line

This branch preserves the retained lifecycle-policy lineage used by Huram/Logma and extends it without renumbering durable `PolicyCode` values.

`github.com/dash-xd/ratelimiter` is the public Go package. Redis/Lua mechanics live under `internal/`, executables live under `cmd/`, and executable behavior is selected through opaque profile packages.

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

`DurationClass` values are explicit stable wire codes. Semantic properties are separate descriptor data:

```text
wire code   actual duration   policy energy weight
```

This means a new duration can be added between two existing durations without renumbering persisted codes. For example, `10m` is semantically between `5m` and `20m` but uses a newly allocated wire value rather than shifting the old `20m` code.

Named lifecycle policies such as `smoke-10m` are human-facing aliases. They compile to `PolicySpec`, which compiles to the canonical `PolicyCode`. Callers should persist the code and original activation/deadline; names are navigation/configuration metadata.

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

A field being representable in `PolicySpec` does not mean every profile can enforce it. In particular, Burst and Concurrency are reserved policy axes until a selected profile advertises `CapabilityBurst` or `CapabilityConcurrency`; validation must reject unsupported combinations.

## Profile composition

| Import | Redis state | Publishes | Lifecycle timers |
| --- | --- | --- | --- |
| `profile/minimal` | window ZSET | nothing | no |
| `profile/preflight` | window ZSET + lifecycle keys | `preflight` | yes |
| `profile/decisions` | window ZSET + blocked streak | `allowed` or `blocked` | no |
| `profile/lifecycle` | window ZSET + blocked streak + lifecycle keys | `preflight`, `allowed`/`blocked`, shutdown | yes |

`ratelimiter.Profile` is opaque. Profile packages are the supported constructors, so callers do not couple themselves to Redis library/function names or internal behavior flags.

## Redis lifecycle timer

Lifecycle-capable profiles keep live timer state in Redis under explicit FCALL keys sharing the bucket's Redis Cluster hash tag.

An initial preflight timer can be armed relative to Redis time through `Limiter.Check`. Durable lifecycle owners should persist the original activation plus `PolicyCode`, derive the absolute deadline once, and reconstruct live Redis state with `Limiter.ArmTimerAt`.

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

Reconstruction with `reset=false` does not extend an existing timer. If a process dies after timer insertion but before callback-payload storage, a later reconstruction can repair the missing payload without changing the deadline.

`Limiter.Tick` provides only a clock pulse. Redis owns due evaluation and dispatch. A due timer with missing/malformed callback state remains pending. A shutdown target with no Pub/Sub subscriber also remains pending. The timer is removed only after shutdown delivery succeeds for its configured targets.

`Limiter.CancelTimer` is idempotent and removes both timer and callback context.

## Bootstrap and runtime authority

`RedisStore.Bootstrap` uses `FUNCTION LOAD REPLACE` and should use bootstrap credentials distinct from restricted runtime credentials when practical. Runtime callers should receive only the FCALL/key/channel authority required by their selected profile and scope.

Redis keys are passed explicitly to FCALL and are namespaced by `RedisConfig.Keyspace` plus the caller's bucket hash tag.

## Qualification

The durable lifecycle line originates from ratelimiter commit:

```text
211738d48e33364431a4e4b0613ceac5ea593737
Arm lifecycle timers from absolute deadlines
```

The `lifecycle-handoff` branch extends that exact lineage. Its tests must include:

- `PolicyCode` round trips;
- historical duration-byte fixtures;
- semantic duration ordering independent of wire values;
- named lifecycle policy compilation;
- original-activation absolute deadline reconstruction;
- entitlement/profile capability rejection;
- Redis lifecycle timer and Logma integration behavior.

The branch uses `.github/requests/test.txt` as its push pseudo-dispatch trigger. A code change is not considered qualified merely because it was committed; an exact successful test run must be recorded before Huram consumes the revision as a lifecycle component.
