//go:build integration

package integration_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	ratelimiter "github.com/dash-xd/ratelimiter"
	logmapubsub "github.com/xd-dash/logma-serverless/pubsub"
	"github.com/redis/go-redis/v9"
)

func TestLifecycleEventsReachLogmaServerlessSubscriber(t *testing.T) {
	addr := os.Getenv("RATELIMITER_REDIS_ADDR")
	if addr == "" {
		t.Skip("RATELIMITER_REDIS_ADDR is not set")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	commands := redis.NewClient(&redis.Options{Addr: addr})
	defer commands.Close()
	if err := commands.FlushDB(ctx).Err(); err != nil {
		t.Fatal(err)
	}

	subscribers := redis.NewClient(&redis.Options{Addr: addr})
	defer subscribers.Close()

	channels := []string{"test:preflight", "test:allowed", "test:blocked"}
	events := make(chan ratelimiter.Event, 8)
	stopped := make([]<-chan struct{}, 0, len(channels))
	for _, channel := range channels {
		sub := logmapubsub.Subscribe(ctx, subscribers, channel, func(payload string) {
			var event ratelimiter.Event
			if err := json.Unmarshal([]byte(payload), &event); err != nil {
				t.Errorf("unmarshal event: %v", err)
				return
			}
			events <- event
		})
		stopped = append(stopped, sub.Stopped())
	}
	waitForSubscribers(t, ctx, commands, channels)

	resolver := ratelimiter.TargetResolverFunc(func(in ratelimiter.Input, stage ratelimiter.Stage) []ratelimiter.Target {
		return []ratelimiter.Target{{
			Channel: "test:" + string(stage),
			Purpose: ratelimiter.PurposeTracing,
			Data: ratelimiter.Metadata{
				"resolved_from": in.Request.Operation,
			},
		}}
	})
	profile := ratelimiter.Lifecycle(resolver)
	store, err := ratelimiter.NewRedisStore(commands, ratelimiter.RedisConfig{Keyspace: "test:ratelimit"})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Bootstrap(ctx, ratelimiter.Minimal(), profile); err != nil {
		t.Fatal(err)
	}
	limiter, err := store.Limiter(profile)
	if err != nil {
		t.Fatal(err)
	}

	in := ratelimiter.Input{
		Bucket: "tenant-a:client-7",
		Request: ratelimiter.Request{
			ID:        "req-1",
			Subject:   "client-7",
			Operation: "render",
			Resource:  "dashboard-42",
			Namespace: ratelimiter.Namespace{Environment: "test", Parent: "bootstrap", Child: "global"},
		},
		CallbackData: ratelimiter.Metadata{"tenant": "tenant-a"},
	}
	limit := ratelimiter.Limit{MaxRequests: 1, Window: time.Minute}

	first, err := limiter.Check(ctx, in, limit)
	if err != nil {
		t.Fatal(err)
	}
	if !first.Allowed || first.Count != 1 || first.Remaining != 0 {
		t.Fatalf("unexpected first decision: %#v", first)
	}

	in.Request.ID = "req-2"
	second, err := limiter.Check(ctx, in, limit)
	if err != nil {
		t.Fatal(err)
	}
	if second.Allowed || second.BlockedCount != 1 || second.RetryAfter <= 0 {
		t.Fatalf("unexpected second decision: %#v", second)
	}

	got := collectEvents(t, ctx, events, 4)
	wantStages := []ratelimiter.Stage{
		ratelimiter.StagePreflight,
		ratelimiter.StageAllowed,
		ratelimiter.StagePreflight,
		ratelimiter.StageBlocked,
	}
	for i, event := range got {
		if event.Schema != ratelimiter.EventSchema {
			t.Fatalf("event %d schema = %q", i, event.Schema)
		}
		if event.Stage != wantStages[i] {
			t.Fatalf("event %d stage = %q, want %q", i, event.Stage, wantStages[i])
		}
		if event.Callback.Purpose != ratelimiter.PurposeTracing {
			t.Fatalf("event %d purpose = %q", i, event.Callback.Purpose)
		}
		if event.Callback.Data["tenant"] != "tenant-a" || event.Callback.Data["resolved_from"] != "render" {
			t.Fatalf("event %d callback data = %#v", i, event.Callback.Data)
		}
	}

	cancel()
	for _, done := range stopped {
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("logma subscriber did not stop")
		}
	}
}

func waitForSubscribers(t *testing.T, ctx context.Context, client *redis.Client, channels []string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		counts, err := client.PubSubNumSub(ctx, channels...).Result()
		if err == nil {
			ready := true
			for _, channel := range channels {
				if counts[channel] < 1 {
					ready = false
					break
				}
			}
			if ready {
				return
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("logma subscribers did not become ready")
}

func collectEvents(t *testing.T, ctx context.Context, events <-chan ratelimiter.Event, count int) []ratelimiter.Event {
	t.Helper()
	out := make([]ratelimiter.Event, 0, count)
	for len(out) < count {
		select {
		case event := <-events:
			out = append(out, event)
		case <-ctx.Done():
			t.Fatal(fmt.Errorf("collect events: %w", ctx.Err()))
		}
	}
	return out
}
