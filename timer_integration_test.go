//go:build integration

package ratelimiter_test

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	ratelimiter "github.com/dash-xd/ratelimiter"
	preflightprofile "github.com/dash-xd/ratelimiter/profile/preflight"
	logmapubsub "github.com/xd-dash/logma-serverless/pubsub"
	"github.com/redis/go-redis/v9"
)

func TestPreflightTimerDispatchesShutdownThroughLogmaServerless(t *testing.T) {
	ctx, commands := integrationRedis(t)
	if err := commands.FlushDB(ctx).Err(); err != nil {
		t.Fatal(err)
	}

	const channel = "serverless:shutdown"

	subCtx, stopSubscriber := context.WithCancel(ctx)
	defer stopSubscriber()

	subscribers := redis.NewClient(&redis.Options{Addr: os.Getenv("RATELIMITER_REDIS_ADDR")})
	defer subscribers.Close()

	signals := make(chan ratelimiter.LifecycleSignal, 2)
	sub := logmapubsub.Subscribe(subCtx, subscribers, channel, func(payload string) {
		var message ratelimiter.LifecycleSignalMessage
		if err := json.Unmarshal([]byte(payload), &message); err != nil {
			t.Errorf("unmarshal lifecycle signal: %v", err)
			return
		}
		if message.Type != "Signal" || message.Channel != channel {
			t.Errorf("unexpected lifecycle envelope: %#v", message)
			return
		}
		signals <- message.Message
	})
	waitForSubscribers(t, ctx, commands, []string{channel})

	resolver := ratelimiter.StaticTargets(map[ratelimiter.Stage][]ratelimiter.Target{
		ratelimiter.StageShutdown: {{
			Channel: channel,
			Purpose: ratelimiter.PurposeLifecycleControl,
			Data:    ratelimiter.Metadata{"owner": "timer-test"},
		}},
	})
	profile := preflightprofile.New(resolver)
	store, err := ratelimiter.NewRedisStore(commands, ratelimiter.RedisConfig{
		Keyspace: "test:timer:ratelimit",
	})
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

	in := lifecycleInput("timer-req-1", "tenant-timer:worker-1")
	in.Preflight = ratelimiter.PreflightOptions{
		Shutdown: ratelimiter.ShutdownConditions{
			Timer: &ratelimiter.TimerCondition{After: 250 * time.Millisecond},
		},
	}
	limit := ratelimiter.Limit{MaxRequests: 10, Window: time.Minute}

	if decision, err := limiter.Check(ctx, in, limit); err != nil || !decision.Allowed {
		t.Fatalf("first preflight decision = %#v, %v", decision, err)
	}

	time.Sleep(150 * time.Millisecond)

	// A normal repeated preflight must not extend the original timer.
	in.Request.ID = "timer-req-2"
	if decision, err := limiter.Check(ctx, in, limit); err != nil || !decision.Allowed {
		t.Fatalf("second preflight decision = %#v, %v", decision, err)
	}

	time.Sleep(130 * time.Millisecond)

	result, err := limiter.Tick(ctx, in.Bucket)
	if err != nil {
		t.Fatal(err)
	}
	if result.Dispatched != 1 || result.Pending != 0 || result.PublishFailures != 0 {
		t.Fatalf("unexpected tick result: %#v", result)
	}

	select {
	case signal := <-signals:
		if signal.Schema != ratelimiter.LifecycleSignalSchema {
			t.Fatalf("signal schema = %q", signal.Schema)
		}
		if signal.Type != "lifecycle.shutdown" || signal.Signal != "shutdown" || signal.Condition != "timer" {
			t.Fatalf("unexpected signal: %#v", signal)
		}
		if signal.Request.ID != "timer-req-1" {
			t.Fatalf("timer was unexpectedly reset; request id = %q", signal.Request.ID)
		}
		if signal.Callback.Purpose != ratelimiter.PurposeLifecycleControl {
			t.Fatalf("callback purpose = %q", signal.Callback.Purpose)
		}
		if signal.DeadlineUnixMS <= 0 || signal.SentTimeUnixMS < signal.DeadlineUnixMS {
			t.Fatalf("invalid timer timestamps: %#v", signal)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}

	again, err := limiter.Tick(ctx, in.Bucket)
	if err != nil {
		t.Fatal(err)
	}
	if again.Dispatched != 0 || again.Pending != 0 {
		t.Fatalf("timer dispatched more than once: %#v", again)
	}

	stopSubscriber()
	select {
	case <-sub.Stopped():
	case <-time.After(2 * time.Second):
		t.Fatal("logma-serverless shutdown subscriber did not stop")
	}
}
