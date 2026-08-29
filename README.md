# ratelimiter: preflight lifecycle branch

This branch is an experimental package redesign. Production `main` remains unchanged.

`github.com/dash-xd/ratelimiter` is the stable public rate-limiter API. Redis/Lua mechanics live under `internal/`, executables live under `cmd/`, and each rate-limiter composition is selected by importing a profile package.

## Layout

```text
.
├── cmd/
│   └── ratelimiter-bootstrap/
├── internal/
│   ├── profiledef/
│   ├── redisfunc/
│   └── redisstore/
├── profile/
│   ├── minimal/
│   ├── preflight/
│   ├── decisions/
│   └── lifecycle/
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

There is intentionally no `pkg/` or `api/` directory. The module root is the public Go package. The `profile/...` packages exist because the profile choice is a real composability boundary, not merely a visibility boundary.

## Profile composition

Choose the Redis Function + Pub/Sub behavior by importing only the profile you want:

| Import | Redis state | Publishes |
| --- | --- | --- |
| `profile/minimal` | window ZSET | nothing |
| `profile/preflight` | window ZSET | `preflight` |
| `profile/decisions` | window ZSET + blocked streak | `allowed` or `blocked` |
| `profile/lifecycle` | window ZSET + blocked streak | `preflight` and final `allowed`/`blocked` |

`ratelimiter.Profile` is opaque. The profile packages are the supported constructors, so callers cannot couple themselves to Redis library names, Lua wrapper names, or internal behavior flags.

### Minimal

```go
import (
    "github.com/dash-xd/ratelimiter"
    minimalprofile "github.com/dash-xd/ratelimiter/profile/minimal"
)

profile := minimalprofile.New()

store, err := ratelimiter.NewRedisStore(client, ratelimiter.RedisConfig{
    Keyspace: "prod:ratelimit",
})
if err != nil {
    return err
}

if err := store.Bootstrap(ctx, profile); err != nil {
    return err
}

limiter, err := store.Limiter(profile)
```

### Lifecycle

```go
import (
    "github.com/dash-xd/ratelimiter"
    lifecycleprofile "github.com/dash-xd/ratelimiter/profile/lifecycle"
)

resolver := ratelimiter.NamespaceStageTargets(
    "logs:rate_limiters",
    ratelimiter.PurposeMetrics,
    ratelimiter.Metadata{"source": "cloud-function"},
)

profile := lifecycleprofile.New(resolver)

store, err := ratelimiter.NewRedisStore(client, ratelimiter.RedisConfig{
    Keyspace: "prod:ratelimit",
})
if err != nil {
    return err
}

if err := store.Bootstrap(ctx, profile); err != nil {
    return err
}

limiter, err := store.Limiter(profile)
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

The same `RedisStore` can bootstrap multiple imported profiles when one Redis instance serves callers with different observation requirements.

## Execution model

```text
caller
  |
  | Input + Limit
  v
ratelimiter.Limiter
  |
  | FCALL selected by imported profile
  v
Redis Function
  |
  +-- exact sliding-window admission decision
  |
  +-- optional best-effort PUBLISH selected by profile
        |
        +--> metrics / logs
        +--> cache warming
        +--> anomaly analysis
        +--> adaptive policy
        +--> tracing
        +--> request shadowing
```

Pub/Sub remains an observation/preflight plane, not a durability plane. Billing, authorization, guaranteed audit, authoritative mutation, and one-time jobs must not depend solely on these events.

Rejected requests do not enter the sliding-window ZSET, so rejected traffic cannot extend its own lockout. Decision/lifecycle profiles maintain a separate expiring blocked-streak key. Redis keys are explicit FCALL key arguments and share a Cluster hash tag.

## Bootstrap command

```bash
REDIS_URI=127.0.0.1:6379 \
  go run ./cmd/ratelimiter-bootstrap \
  -profiles minimal,lifecycle
```

The command composes the same public profile packages used by applications. `Bootstrap` performs `FUNCTION LOAD REPLACE` and should use deployment/bootstrap credentials distinct from restricted runtime credentials when practical.

## Integration test

`integration_test.go` is build-tagged with `integration` and uses `package ratelimiter_test`, so it exercises the package as an external consumer. CI starts a small Redis instance, uses the real `logma-serverless` subscriber, and verifies lifecycle events for an allowed and blocked request.


## Redis-owned preflight shutdown timer

The preflight and lifecycle profiles can arm a shutdown timer while the rate-limit
preflight is executing. The deadline and its original shutdown context live in
Redis; application code only provides a periodic clock pulse with `Limiter.Tick`.

```go
resolver := ratelimiter.StaticTargets(map[ratelimiter.Stage][]ratelimiter.Target{
    ratelimiter.StageShutdown: {{
        Channel: "news:worker:shutdown",
        Purpose: ratelimiter.PurposeLifecycleControl,
    }},
})

profile := preflightprofile.New(resolver)

in := ratelimiter.Input{
    Bucket: "news:worker-7",
    Preflight: ratelimiter.PreflightOptions{
        Shutdown: ratelimiter.ShutdownConditions{
            Timer: &ratelimiter.TimerCondition{
                After: 30 * time.Minute,
            },
        },
    },
}

_, err := limiter.Check(ctx, in, limit)
```

Timer state is stored under the same Redis Cluster hash tag as the rate-limit
bucket. Repeating preflight does not extend an existing timer unless
`TimerCondition.Reset` is explicitly set.

A long-running process such as news, Logma, or a Logma serverless wrapper can
provide the clock pulse at an interval appropriate to its shutdown precision:

```go
result, err := limiter.Tick(ctx, "news:worker-7")
if err != nil {
    return err
}
if result.Pending > 0 {
    // The deadline is due but at least one configured shutdown channel had
    // no subscriber. A later tick will retry.
}
```

When the deadline is due, Redis publishes a `dashxd.ratelimiter.lifecycle.v1`
signal with `type=lifecycle.shutdown` and `condition=timer`. Redis removes the
timer only after every configured shutdown target has at least one Pub/Sub
subscriber for that dispatch. The callback is therefore only a clock source;
deadline evaluation and shutdown dispatch remain in the Redis Function.

The timer member is named `shutdown:timer`. Future shutdown conditions such as
quote counts or streamed-byte limits can use sibling members and the same
lifecycle signal path without changing callers that consume shutdown signals.


## Authentication providers

Authentication/authorization providers are separate from rate-limiter execution
profiles. Consumers may use ratelimiter without an auth provider.

The managed Redis ACL provider is available from:

```go
import managedauth "github.com/dash-xd/ratelimiter/auth/profile/managed"
```

It compiles tenant-scoped Redis usernames, key patterns, Pub/Sub channel
patterns, optional FCALL capability, and explicit command grants. It deliberately
does not grant EVAL/EVALSHA, FUNCTION administration, ACL administration,
KEYS/SCAN, FLUSH*, CONFIG, MODULE, or broad Redis command categories.

This lets applications such as Logma use ratelimiter as the provider of the
authorization scheme while retaining their own transport authentication and
application-specific namespace configuration.
