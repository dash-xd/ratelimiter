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
