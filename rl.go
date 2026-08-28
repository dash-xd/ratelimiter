package ratelimiter

// This branch intentionally replaces the legacy HTTP/JWT-specific implementation
// with the generic RedisStore + Limiter API. The production implementation remains
// unchanged on main.
