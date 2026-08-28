// Package ratelimiter provides an exact Redis-backed sliding-window rate limiter
// with optional, best-effort lifecycle Pub/Sub events.
//
// The package does not assume HTTP. Callers normalize whatever they are handling
// into Input, choose a Profile, bootstrap that profile's Redis Function once per
// deployment, and call Limiter.Check for each unit of work.
package ratelimiter
