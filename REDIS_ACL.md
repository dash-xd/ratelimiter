# Redis ACL enforcement boundary

`redisacl` compiles **local Redis execution identities**. It is intentionally not a distributed identity provider and does not own organization authorization policy.

The expected Fatline layering is:

```text
Prajapati
  semantic identity + authorization
        |
        v
Logma / service runtime
        |
        v
ratelimiter/redisacl
  compile local Redis username + ACL rules
        |
        v
Redis
```

Ratelimiter continues to own machine rate/lifecycle policy through `PolicyBinding`. `redisacl` is a separate enforcement helper for Redis-backed runtimes.

Do not use Redis usernames/passwords as portable Fatline principals. A principal such as `ed25519:logma/world-17` is authenticated and authorized above this layer; the approved operation may then execute through a constrained local Redis identity such as `logma-tenant-acme` or a publisher/subscriber profile.

Current managed profiles are:

- `tenant`: scoped data + publish + subscribe
- `tenant-functions`: tenant plus runtime FCALL
- `publisher`: publish only
- `subscriber`: subscribe only

Profiles start from `-@all` and add explicit commands. They do not grant ACL administration, FUNCTION administration, EVAL/EVALSHA, KEYS/SCAN, FLUSH, CONFIG, MODULE, or broad Redis command categories.

Marai does **not** use this package for its security boundary. Marai owns its own deliberately static `marai-app` / `marai-admin` ACL split.
