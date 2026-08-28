# ratelimiter: preflight lifecycle branch

This branch is an experimental package redesign. The production `main` branch is intentionally unchanged.

## Repository layout

The module keeps the public package at the repository root so callers continue to import `github.com/dash-xd/ratelimiter`. Infrastructure-only implementation details live under `internal/`, and executable bootstrap tooling lives under `cmd/`:

```text
.
├── cmd/
│   └── ratelimiter-bootstrap/
├── internal/
│   ├── redisfunc/
│   └── redisstore/
├── integration_test.go
├── doc.go
├── events.go
├── limiter.go
├── profile.go
├── store.go
├── targets.go
├── types.go
├── go.mod
└── go.sum
```

There is intentionally no `pkg/` directory: the module root is already the canonical public Go package.


The package wraps Redis in two roles:

1. **bootstrap** one or more named Redis Function profiles;
2. **execute** an exact sliding-window decision against those functions.

It does not assume HTTP. A Cloud Function, queue consumer, RPC handler, CLI, or other caller normalizes its work into `ratelimiter.Input`.

## Shape

```
caller
  |
  | Input + Limit
  v
ratelimiter.Limiter
  |
  | FCALL
  v
Redis Function
  |
  +-- exact sliding-window admission decision
  |
  +-- optional best-effort lifecycle PUBLISH
        |
        +--> logma-serverless
        +--> metrics
        +--> logs
        +--> cache warming
        +--> anomaly analysis
        +--> adaptive-policy feedback
        +--> tracing
        +--> speculative work
        +--> request shadowing
```

Pub/Sub is deliberately an observation/preflight plane, not a durability plane. Do not make billing, accounting, authorization, guaranteed audit, one-time job execution, authoritative invalidation, or data mutation depend solely on these events.

## Profiles

Profiles are constructors rather than behavior flags:

| Profile | Redis state | Pub/Sub |
| --- | --- | --- |
| `Minimal()` | window ZSET | none |
| `Preflight(resolver)` | window ZSET | `preflight` |
| `Decisions(resolver)` | window ZSET + blocked streak | `allowed` or `blocked` |
| `Lifecycle(resolver)` | window ZSET + blocked streak | `preflight` plus `allowed` or `blocked` |

Each profile is loaded as a separate Redis Function library. A deployment can bootstrap one profile, several, or all of them without replacing another profile's registered function.

```go
resolver := ratelimiter.NamespaceStageTargets(
    "logs:rate_limiters",
    ratelimiter.PurposeMetrics,
    ratelimiter.Metadata{"source": "cloud-function"},
)

observed := ratelimiter.Lifecycle(resolver)

store, err := ratelimiter.NewRedisStore(client, ratelimiter.RedisConfig{
    Keyspace: "prod:ratelimit",
})
if err != nil {
    return err
}

if err := store.Bootstrap(ctx, ratelimiter.Minimal(), observed); err != nil {
    return err
}

limiter, err := store.Limiter(observed)
if err != nil {
    return err
}

decision, err := limiter.Check(ctx, ratelimiter.Input{
    Bucket: "project-a:client-42",
    Request: ratelimiter.Request{
        ID:        requestID,
        Subject:   "client-42",
        Operation: "render",
        Resource:  "dashboard-7",
        Namespace: ratelimiter.Namespace{
            Environment: "prod",
            Parent:      "bootstrap",
            Child:       "global",
        },
    },
    CallbackData: ratelimiter.Metadata{
        "tenant": "project-a",
    },
}, ratelimiter.Limit{
    MaxRequests: 20,
    Window:      time.Minute,
})
if err != nil {
    return err
}

if !decision.Allowed {
    return decision.Err()
}
```

### Bootstrap command

Deployment code can bootstrap Redis Functions without embedding bootstrap logic in an application binary:

```bash
REDIS_URI=127.0.0.1:6379 \
  go run ./cmd/ratelimiter-bootstrap \
  -profiles minimal,lifecycle
```

The command defaults to loading all profiles and uses the same `REDIS_URI` / `REDISCLI_AUTH` convention as the package helper.

### Bootstrap permissions

`Bootstrap` performs `FUNCTION LOAD REPLACE` and should be treated as a privileged deployment/startup operation. A production deployment can use separate Redis credentials for bootstrap and runtime.

The runtime only needs the Redis commands required by its selected function profile. Callback profiles additionally need permission to publish to their allowed channel patterns. A Pub/Sub command error is caught with `redis.pcall`; rate limiting still returns its decision and increments `Decision.PublishFailures`.

## Dynamic callbacks

A target can be predetermined:

```go
resolver := ratelimiter.StaticTargets(map[ratelimiter.Stage][]ratelimiter.Target{
    ratelimiter.StageBlocked: {
        {
            Channel: "prod:security:rate-limit",
            Purpose: ratelimiter.PurposeAnomaly,
        },
    },
})
```

Or resolved from each incoming unit of work:

```go
resolver := ratelimiter.TargetResolverFunc(
    func(in ratelimiter.Input, stage ratelimiter.Stage) []ratelimiter.Target {
        if in.Request.Operation != "render" {
            return nil
        }

        return []ratelimiter.Target{{
            Channel: "render:rate-limit:" + string(stage),
            Purpose: ratelimiter.PurposeCacheWarm,
            Data: ratelimiter.Metadata{
                "resource": in.Request.Resource,
            },
        }}
    },
)
```

`Target.Data` is predetermined data. `Input.CallbackData` is request-specific data and wins on duplicate keys.

The callback envelope is versioned as `dashxd.ratelimiter.event.v1`:

```json
{
  "schema": "dashxd.ratelimiter.event.v1",
  "type": "rate_limit.allowed",
  "stage": "allowed",
  "sent_time_unix_ms": 1787880000123,
  "request": {
    "id": "req-1",
    "subject": "client-42",
    "operation": "render",
    "resource": "dashboard-7"
  },
  "rate_limit": {
    "bucket": "project-a:client-42",
    "max_requests": 20,
    "window_ms": 60000,
    "decision": "allowed",
    "count": 4,
    "remaining": 16
  },
  "callback": {
    "purpose": "metrics",
    "data": {
      "tenant": "project-a"
    }
  }
}
```

## Input bounds

Callback input is intentionally flat and bounded before it reaches Redis:

- bucket: 512 bytes maximum;
- channel: 256 bytes maximum;
- 8 targets per lifecycle stage;
- 32 callback metadata entries;
- metadata keys: 64 bytes maximum;
- metadata values: 512 bytes maximum;
- serialized event context: 16 KiB maximum.

A small native Lua 5.1 validator mirrors the Go-side checks. Tableshape is not embedded because this schema is intentionally narrow; bringing a general schema library into every loaded function library would add code and execution overhead without improving this contract.

## Sliding-window behavior

The Redis function:

1. reads Redis `TIME` with microsecond precision;
2. removes entries at or before the rolling-window boundary;
3. counts the remaining accepted requests;
4. rejects when the count is already at the limit;
5. inserts only accepted requests;
6. expires the ZSET using millisecond TTLs.

Rejected requests never enter the ZSET, so a blocked client cannot extend its own lockout or consume memory proportional to rejected request volume.

Decision/lifecycle profiles keep a separate expiring blocked-streak key. Minimal/preflight profiles do not allocate it.

Keys are explicit function key arguments and share a Redis Cluster hash tag:

```
ratelimit:{project-a:client-42}:window
ratelimit:{project-a:client-42}:blocked
```

## Small Redis instances

The integration workflow starts Redis with:

```
--save ""
--appendonly no
--maxmemory 40mb
--maxmemory-policy noeviction
```

`noeviction` is intentional for admission state: silently evicting active rate-limit buckets would create accidental fail-open behavior. If Redis cannot perform a required write, `Check` returns an infrastructure error and the caller can explicitly choose its own fail-open or fail-closed policy.

For a small instance, memory is primarily proportional to **accepted requests still inside active windows**, not rejected traffic. Keep limits/windows reasonable and avoid unbounded bucket cardinality.

## Integration test

CI checks out:

- `xd-dash/sus-redis` and runs its packaged `redis-server` directly when compatible, with a Redis container as fallback;
- `xd-dash/logma-serverless` and uses its real reconnecting `pubsub.Subscribe` implementation.

The root-level `integration_test.go` is build-tagged with `integration`, uses the external `ratelimiter_test` package, bootstraps Redis Functions, makes one allowed and one blocked request, and verifies Logma receives:

```
req-1: preflight + allowed
req-2: preflight + blocked
```

The test intentionally does not impose a global order across different Pub/Sub channels; each channel has its own subscriber goroutine.
