//go:build integration

package ratelimiter_test

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	ratelimiter "github.com/dash-xd/ratelimiter"
	lifecycleprofile "github.com/dash-xd/ratelimiter/profile/lifecycle"
	"github.com/redis/go-redis/v9"
)

func TestAbsoluteLifecycleTimerFCALLContract(t *testing.T) {
	ctx, client := lifecycleTimerRedis(t)
	if err := client.FlushDB(ctx).Err(); err != nil {
		t.Fatal(err)
	}

	const (
		bucket   = "deployment:timer-fcall"
		channel  = "test:lifecycle:shutdown"
		keyspace = "test:lifecycle"
	)
	resolver := ratelimiter.TargetResolverFunc(func(in ratelimiter.Input, stage ratelimiter.Stage) []ratelimiter.Target {
		if stage != ratelimiter.StageShutdown {
			return nil
		}
		return []ratelimiter.Target{{Channel: channel, Purpose: ratelimiter.PurposeLifecycleControl}}
	})
	profile := lifecycleprofile.New(resolver)
	store, err := ratelimiter.NewRedisStore(client, ratelimiter.RedisConfig{Keyspace: keyspace})
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

	pubsub := client.Subscribe(ctx, channel)
	defer pubsub.Close()
	if _, err := pubsub.Receive(ctx); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().UTC().Add(300 * time.Millisecond).Truncate(time.Millisecond)
	in := ratelimiter.Input{
		Bucket: bucket,
		Request: ratelimiter.Request{
			ID:        "timer-fcall",
			Subject:   "deployment",
			Operation: "lifecycle.shutdown",
			Resource:  "timer-fcall",
		},
		CallbackData: ratelimiter.Metadata{"deployment_id": "timer-fcall"},
	}
	armed, err := limiter.ArmTimerAt(ctx, in, deadline, false)
	if err != nil || !armed {
		t.Fatalf("initial arm = %v, %v", armed, err)
	}

	timerKey := keyspace + ":{" + bucket + "}:lifecycle:timers"
	payloadKey := keyspace + ":{" + bucket + "}:lifecycle:payloads"
	const member = "shutdown:timer"
	assertTimerScore(t, ctx, client, timerKey, member, deadline.UnixMilli())

	later := deadline.Add(10 * time.Minute)
	armed, err = limiter.ArmTimerAt(ctx, in, later, false)
	if err != nil || armed {
		t.Fatalf("non-reset rearm = %v, %v", armed, err)
	}
	assertTimerScore(t, ctx, client, timerKey, member, deadline.UnixMilli())

	if err := client.HDel(ctx, payloadKey, member).Err(); err != nil {
		t.Fatal(err)
	}
	armed, err = limiter.ArmTimerAt(ctx, in, later, false)
	if err != nil || armed {
		t.Fatalf("payload repair rearm = %v, %v", armed, err)
	}
	assertTimerScore(t, ctx, client, timerKey, member, deadline.UnixMilli())
	if exists, err := client.HExists(ctx, payloadKey, member).Result(); err != nil || !exists {
		t.Fatalf("payload repaired = %v, %v", exists, err)
	}

	for time.Now().Before(deadline.Add(20 * time.Millisecond)) {
		time.Sleep(5 * time.Millisecond)
	}
	result, err := limiter.Tick(ctx, bucket)
	if err != nil {
		t.Fatal(err)
	}
	if result.Dispatched != 1 || result.Pending != 0 {
		t.Fatalf("tick result = %#v", result)
	}

	select {
	case message := <-pubsub.Channel():
		var envelope ratelimiter.LifecycleSignalMessage
		if err := json.Unmarshal([]byte(message.Payload), &envelope); err != nil {
			t.Fatal(err)
		}
		if envelope.Message.DeadlineUnixMS != deadline.UnixMilli() {
			t.Fatalf("shutdown deadline = %d, want %d", envelope.Message.DeadlineUnixMS, deadline.UnixMilli())
		}
	case <-time.After(time.Second):
		t.Fatal("shutdown signal was not delivered")
	}

	removed, err := limiter.CancelTimer(ctx, bucket)
	if err != nil {
		t.Fatal(err)
	}
	if removed {
		t.Fatal("already-dispatched timer reported as removed")
	}
}

func TestLifecycleTimerRuntimeACLDescriptorIsExecutable(t *testing.T) {
	ctx, admin := lifecycleTimerRedis(t)
	if err := admin.FlushDB(ctx).Err(); err != nil {
		t.Fatal(err)
	}

	const (
		username = "ratelimiter-lifecycle-runtime-test"
		password = "ratelimiter-lifecycle-runtime-password"
		bucket   = "deployment:acl-runtime"
		keyspace = "test:lifecycle:acl"
		channel  = "test:lifecycle:acl:shutdown"
	)
	resolver := ratelimiter.StaticTargets(map[ratelimiter.Stage][]ratelimiter.Target{
		ratelimiter.StageShutdown: {{Channel: channel, Purpose: ratelimiter.PurposeLifecycleControl}},
	})
	profile := lifecycleprofile.New(resolver)
	adminStore, err := ratelimiter.NewRedisStore(admin, ratelimiter.RedisConfig{Keyspace: keyspace})
	if err != nil {
		t.Fatal(err)
	}
	if err := adminStore.Bootstrap(ctx, profile); err != nil {
		t.Fatal(err)
	}

	acl := []any{"ACL", "SETUSER", username, "reset", "on", ">" + password, "-@all", "+ping"}
	for _, command := range ratelimiter.TimerRuntimeACLCommands(profile) {
		acl = append(acl, "+"+command)
	}
	acl = append(acl, "~"+keyspace+":*", "&"+channel)
	if err := admin.Do(ctx, acl...).Err(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = admin.Do(context.Background(), "ACL", "DELUSER", username).Err() })

	runtime := redis.NewClient(&redis.Options{Addr: admin.Options().Addr, Username: username, Password: password})
	t.Cleanup(func() { _ = runtime.Close() })
	if err := runtime.Ping(ctx).Err(); err != nil {
		t.Fatalf("runtime ping: %v", err)
	}
	if err := runtime.Do(ctx, "FUNCTION", "LIST").Err(); err == nil || !strings.Contains(err.Error(), "NOPERM") {
		t.Fatalf("runtime FUNCTION LIST = %v, want NOPERM", err)
	}
	if err := runtime.HSet(ctx, "test:unrelated:acl-runtime", "x", "y").Err(); err == nil || !strings.Contains(err.Error(), "NOPERM") {
		t.Fatalf("runtime unrelated HSET = %v, want NOPERM", err)
	}

	store, err := ratelimiter.NewRedisStore(runtime, ratelimiter.RedisConfig{Keyspace: keyspace})
	if err != nil {
		t.Fatal(err)
	}
	limiter, err := store.Limiter(profile)
	if err != nil {
		t.Fatal(err)
	}
	in := ratelimiter.Input{
		Bucket: bucket,
		Request: ratelimiter.Request{ID: "acl-runtime", Subject: "deployment", Operation: "lifecycle.shutdown", Resource: "acl-runtime"},
	}
	deadline := time.Now().UTC().Add(-time.Millisecond)
	if armed, err := limiter.ArmTimerAt(ctx, in, deadline, false); err != nil || !armed {
		t.Fatalf("restricted runtime arm = %v, %v", armed, err)
	}
	result, err := limiter.Tick(ctx, bucket)
	if err != nil {
		t.Fatalf("restricted runtime tick: %v", err)
	}
	if result.Dispatched != 0 || result.Pending != 1 {
		t.Fatalf("restricted runtime tick without subscriber = %#v", result)
	}
	if removed, err := limiter.CancelTimer(ctx, bucket); err != nil || !removed {
		t.Fatalf("restricted runtime cancel = %v, %v", removed, err)
	}
}

func TestLifecycleTimerRequiresSubscriberAndCancelIsIdempotent(t *testing.T) {
	ctx, client := lifecycleTimerRedis(t)
	if err := client.FlushDB(ctx).Err(); err != nil {
		t.Fatal(err)
	}

	const (
		bucket  = "deployment:subscriber-gate"
		channel = "test:lifecycle:subscriber-gate"
	)
	resolver := ratelimiter.StaticTargets(map[ratelimiter.Stage][]ratelimiter.Target{
		ratelimiter.StageShutdown: {{Channel: channel, Purpose: ratelimiter.PurposeLifecycleControl}},
	})
	profile := lifecycleprofile.New(resolver)
	store, err := ratelimiter.NewRedisStore(client, ratelimiter.RedisConfig{Keyspace: "test:lifecycle:gate"})
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

	in := ratelimiter.Input{Bucket: bucket, Request: ratelimiter.Request{ID: "subscriber-gate"}}
	if armed, err := limiter.ArmTimerAt(ctx, in, time.Now().UTC().Add(-time.Millisecond), false); err != nil || !armed {
		t.Fatalf("arm due timer = %v, %v", armed, err)
	}
	result, err := limiter.Tick(ctx, bucket)
	if err != nil {
		t.Fatal(err)
	}
	if result.Dispatched != 0 || result.Pending != 1 {
		t.Fatalf("tick without subscriber = %#v", result)
	}

	pubsub := client.Subscribe(ctx, channel)
	defer pubsub.Close()
	if _, err := pubsub.Receive(ctx); err != nil {
		t.Fatal(err)
	}
	result, err = limiter.Tick(ctx, bucket)
	if err != nil {
		t.Fatal(err)
	}
	if result.Dispatched != 1 || result.Pending != 0 {
		t.Fatalf("tick with subscriber = %#v", result)
	}

	future := time.Now().UTC().Add(time.Minute)
	if armed, err := limiter.ArmTimerAt(ctx, in, future, false); err != nil || !armed {
		t.Fatalf("rearm after dispatch = %v, %v", armed, err)
	}
	removed, err := limiter.CancelTimer(ctx, bucket)
	if err != nil || !removed {
		t.Fatalf("first cancel = %v, %v", removed, err)
	}
	removed, err = limiter.CancelTimer(ctx, bucket)
	if err != nil || removed {
		t.Fatalf("second cancel = %v, %v", removed, err)
	}
}

func lifecycleTimerRedis(t *testing.T) (context.Context, *redis.Client) {
	t.Helper()
	addr := os.Getenv("RATELIMITER_REDIS_ADDR")
	if addr == "" {
		t.Skip("RATELIMITER_REDIS_ADDR is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	client := redis.NewClient(&redis.Options{Addr: addr})
	t.Cleanup(func() { _ = client.Close() })
	if err := client.Ping(ctx).Err(); err != nil {
		t.Fatalf("ping test Redis %s: %v", addr, err)
	}
	return ctx, client
}

func assertTimerScore(t *testing.T, ctx context.Context, client *redis.Client, key, member string, want int64) {
	t.Helper()
	score, err := client.ZScore(ctx, key, member).Result()
	if err != nil {
		t.Fatal(err)
	}
	if int64(score) != want {
		t.Fatalf("timer score = %d, want %d", int64(score), want)
	}
}

