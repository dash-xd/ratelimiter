//go:build integration

package ratelimiter_test

import (
	"testing"
	"time"

	ratelimiter "github.com/dash-xd/ratelimiter"
	burstprofile "github.com/dash-xd/ratelimiter/profile/burst"
)

func TestBurstTokenBucketCapacityAndRefill(t *testing.T) {
	ctx, commands := integrationRedis(t)
	if err := commands.FlushDB(ctx).Err(); err != nil {
		t.Fatal(err)
	}

	profile := burstprofile.New()
	store, err := ratelimiter.NewRedisStore(commands, ratelimiter.RedisConfig{Keyspace: "test:burst"})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Bootstrap(ctx, profile); err != nil {
		t.Fatal(err)
	}
	limiter, err := store.Limiter(profile)
	if err != nil {
		t.Fatal(err)
	}

	in := ratelimiter.Input{Bucket: "tenant-a:client-7"}
	limit := ratelimiter.BurstLimit{RequestsPerSecond: 1, Capacity: 2}

	first, err := limiter.CheckBurst(ctx, in, limit)
	if err != nil || !first.Allowed || first.Remaining != 1 {
		t.Fatalf("first = %#v, %v", first, err)
	}
	second, err := limiter.CheckBurst(ctx, in, limit)
	if err != nil || !second.Allowed || second.Remaining != 0 {
		t.Fatalf("second = %#v, %v", second, err)
	}
	third, err := limiter.CheckBurst(ctx, in, limit)
	if err != nil {
		t.Fatal(err)
	}
	if third.Allowed || third.RetryAfter <= 0 || third.RetryAfter > time.Second {
		t.Fatalf("third = %#v, want blocked with bounded retry", third)
	}

	time.Sleep(1100 * time.Millisecond)
	refilled, err := limiter.CheckBurst(ctx, in, limit)
	if err != nil || !refilled.Allowed {
		t.Fatalf("refilled = %#v, %v", refilled, err)
	}
}

func TestBurstProfileACLDescriptorIsMinimal(t *testing.T) {
	commands := ratelimiter.BurstRuntimeACLCommands(burstprofile.New())
	want := map[string]bool{"fcall": true, "time": true, "hmget": true, "hset": true, "pexpire": true}
	if len(commands) != len(want) {
		t.Fatalf("commands = %#v", commands)
	}
	for _, command := range commands {
		if !want[command] {
			t.Fatalf("unexpected burst runtime command %q", command)
		}
	}
}
