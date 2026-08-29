//go:build integration

package ratelimiter_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"
	"time"

	ratelimiter "github.com/dash-xd/ratelimiter"
	decisionsprofile "github.com/dash-xd/ratelimiter/profile/decisions"
	lifecycleprofile "github.com/dash-xd/ratelimiter/profile/lifecycle"
	minimalprofile "github.com/dash-xd/ratelimiter/profile/minimal"
	preflightprofile "github.com/dash-xd/ratelimiter/profile/preflight"
	logmapubsub "github.com/xd-dash/logma-serverless/pubsub"
	"github.com/redis/go-redis/v9"
)

func TestLifecycleEventsReachLogmaServerlessSubscriber(t *testing.T) {
	ctx, commands := integrationRedis(t)
	if err := commands.FlushDB(ctx).Err(); err != nil {
		t.Fatal(err)
	}

	subCtx, stopSubscribers := context.WithCancel(ctx)
	subscribers := redis.NewClient(&redis.Options{Addr: os.Getenv("RATELIMITER_REDIS_ADDR")})
	defer subscribers.Close()

	channels := []string{"serverless:preflight", "serverless:allowed", "serverless:blocked"}
	events := make(chan ratelimiter.Event, 8)
	stopped := make([]<-chan struct{}, 0, len(channels))
	for _, channel := range channels {
		sub := logmapubsub.Subscribe(subCtx, subscribers, channel, func(payload string) {
			var message ratelimiter.PubSubMessage
			if err := json.Unmarshal([]byte(payload), &message); err != nil {
				t.Errorf("unmarshal pubsub message: %v", err)
				return
			}
			if message.Type != "Event" || message.Channel == "" {
				t.Errorf("unexpected pubsub envelope: %#v", message)
				return
			}
			events <- message.Message
		})
		stopped = append(stopped, sub.Stopped())
	}
	waitForSubscribers(t, ctx, commands, channels)

	resolver := ratelimiter.TargetResolverFunc(func(in ratelimiter.Input, stage ratelimiter.Stage) []ratelimiter.Target {
		return []ratelimiter.Target{{
			Channel: "serverless:" + string(stage),
			Purpose: ratelimiter.PurposeTracing,
			Data: ratelimiter.Metadata{"resolved_from": in.Request.Operation},
		}}
	})
	store, profiles := bootstrapProfiles(t, ctx, commands, resolver, "test:serverless:ratelimit")
	limiter, err := store.Limiter(profiles.lifecycle)
	if err != nil {
		t.Fatal(err)
	}

	in := lifecycleInput("req-1", "tenant-a:client-7")
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

	assertLifecycleEvents(t, collectEvents(t, ctx, events, 4))

	minimal, err := store.Limiter(profiles.minimal)
	if err != nil {
		t.Fatal(err)
	}
	minimalInput := ratelimiter.Input{Bucket: "minimal-client"}
	minimalLimit := ratelimiter.Limit{MaxRequests: 1, Window: time.Minute}
	minimalAllowed, err := minimal.Check(ctx, minimalInput, minimalLimit)
	if err != nil {
		t.Fatal(err)
	}
	if !minimalAllowed.Allowed || minimalAllowed.PublishFailures != 0 || minimalAllowed.BlockedCount != 0 {
		t.Fatalf("unexpected minimal allowed decision: %#v", minimalAllowed)
	}
	minimalBlocked, err := minimal.Check(ctx, minimalInput, minimalLimit)
	if err != nil {
		t.Fatal(err)
	}
	if minimalBlocked.Allowed || minimalBlocked.PublishFailures != 0 || minimalBlocked.BlockedCount != 0 {
		t.Fatalf("unexpected minimal blocked decision: %#v", minimalBlocked)
	}

	stopSubscribers()
	for _, done := range stopped {
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("logma-serverless subscriber did not stop")
		}
	}
}

func TestLifecycleEventsReachStatefulLogmaSubscription(t *testing.T) {
	logmaURL := os.Getenv("RATELIMITER_LOGMA_URL")
	apiKey := os.Getenv("RATELIMITER_LOGMA_API_KEY")
	if logmaURL == "" || apiKey == "" {
		t.Skip("stateful Logma integration is not configured")
	}

	ctx, commands := integrationRedis(t)
	if err := commands.FlushDB(ctx).Err(); err != nil {
		t.Fatal(err)
	}

	messages := make(chan ratelimiter.PubSubMessage, 8)
	callback := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		var message ratelimiter.PubSubMessage
		if err := json.NewDecoder(r.Body).Decode(&message); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		messages <- message
		w.WriteHeader(http.StatusNoContent)
	}))
	defer callback.Close()

	channel := "stateful:lifecycle"
	subscribeURL := logmaURL + "/channels/" + url.PathEscape(channel) + "/subscribe"
	postJSON(t, ctx, subscribeURL, apiKey, map[string]string{"callbackURL": callback.URL})
	waitForStateKey(t, ctx, commands, "active_subscriptions:*:"+channel)
	waitForSubscribers(t, ctx, commands, []string{channel})

	resolver := ratelimiter.StaticTargets(map[ratelimiter.Stage][]ratelimiter.Target{
		ratelimiter.StagePreflight: {{Channel: channel, Purpose: ratelimiter.PurposeTracing}},
		ratelimiter.StageAllowed:   {{Channel: channel, Purpose: ratelimiter.PurposeTracing}},
		ratelimiter.StageBlocked:   {{Channel: channel, Purpose: ratelimiter.PurposeTracing}},
	})
	store, profiles := bootstrapProfiles(t, ctx, commands, resolver, "test:stateful:ratelimit")
	limiter, err := store.Limiter(profiles.lifecycle)
	if err != nil {
		t.Fatal(err)
	}

	in := lifecycleInput("req-1", "tenant-stateful:client-7")
	limit := ratelimiter.Limit{MaxRequests: 1, Window: time.Minute}
	if decision, err := limiter.Check(ctx, in, limit); err != nil || !decision.Allowed {
		t.Fatalf("first decision = %#v, %v", decision, err)
	}
	in.Request.ID = "req-2"
	if decision, err := limiter.Check(ctx, in, limit); err != nil || decision.Allowed {
		t.Fatalf("second decision = %#v, %v", decision, err)
	}

	got := make([]ratelimiter.Event, 0, 4)
	for len(got) < 4 {
		select {
		case message := <-messages:
			if message.Type != "Event" {
				t.Fatalf("message type = %q", message.Type)
			}
			if message.Channel != channel {
				t.Fatalf("message channel = %q", message.Channel)
			}
			if message.ParentNamespace != "bootstrap" || message.ChildNamespace != "global" {
				t.Fatalf("message namespace = %q/%q", message.ParentNamespace, message.ChildNamespace)
			}
			got = append(got, message.Message)
		case <-ctx.Done():
			t.Fatal(fmt.Errorf("collect stateful Logma callbacks: %w", ctx.Err()))
		}
	}
	assertLifecycleEvents(t, got)
}

type profileSet struct {
	minimal   ratelimiter.Profile
	preflight ratelimiter.Profile
	decisions ratelimiter.Profile
	lifecycle ratelimiter.Profile
}

func bootstrapProfiles(t *testing.T, ctx context.Context, commands *redis.Client, resolver ratelimiter.TargetResolver, keyspace string) (*ratelimiter.RedisStore, profileSet) {
	t.Helper()
	profiles := profileSet{
		minimal:   minimalprofile.New(),
		preflight: preflightprofile.New(resolver),
		decisions: decisionsprofile.New(resolver),
		lifecycle: lifecycleprofile.New(resolver),
	}
	store, err := ratelimiter.NewRedisStore(commands, ratelimiter.RedisConfig{Keyspace: keyspace})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Bootstrap(ctx, profiles.minimal, profiles.preflight, profiles.decisions, profiles.lifecycle); err != nil {
		t.Fatal(err)
	}
	return store, profiles
}

func integrationRedis(t *testing.T) (context.Context, *redis.Client) {
	t.Helper()
	addr := os.Getenv("RATELIMITER_REDIS_ADDR")
	if addr == "" {
		t.Skip("RATELIMITER_REDIS_ADDR is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	client := redis.NewClient(&redis.Options{Addr: addr})
	t.Cleanup(func() { _ = client.Close() })
	return ctx, client
}

func lifecycleInput(id, bucket string) ratelimiter.Input {
	return ratelimiter.Input{
		Bucket: bucket,
		Request: ratelimiter.Request{
			ID:        id,
			Subject:   "client-7",
			Operation: "render",
			Resource:  "dashboard-42",
			Namespace: ratelimiter.Namespace{Environment: "test", Parent: "bootstrap", Child: "global"},
		},
		CallbackData: ratelimiter.Metadata{"tenant": "tenant-a"},
	}
}

func assertLifecycleEvents(t *testing.T, got []ratelimiter.Event) {
	t.Helper()
	seen := map[string]map[ratelimiter.Stage]int{}
	for i, event := range got {
		if event.Schema != ratelimiter.EventSchema {
			t.Fatalf("event %d schema = %q", i, event.Schema)
		}
		if event.Callback.Purpose != ratelimiter.PurposeTracing {
			t.Fatalf("event %d purpose = %q", i, event.Callback.Purpose)
		}
		if seen[event.Request.ID] == nil {
			seen[event.Request.ID] = map[ratelimiter.Stage]int{}
		}
		seen[event.Request.ID][event.Stage]++
	}
	assertStages(t, seen["req-1"], ratelimiter.StagePreflight, ratelimiter.StageAllowed)
	assertStages(t, seen["req-2"], ratelimiter.StagePreflight, ratelimiter.StageBlocked)
}

func assertStages(t *testing.T, got map[ratelimiter.Stage]int, stages ...ratelimiter.Stage) {
	t.Helper()
	if len(got) != len(stages) {
		t.Fatalf("unexpected stage set: %#v", got)
	}
	for _, stage := range stages {
		if got[stage] != 1 {
			t.Fatalf("stage %q count = %d, want 1; all stages: %#v", stage, got[stage], got)
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
	t.Fatal("Redis subscribers did not become ready")
}

func waitForStateKey(t *testing.T, ctx context.Context, client *redis.Client, pattern string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		keys, _, err := client.Scan(ctx, 0, pattern, 10).Result()
		if err == nil && len(keys) != 0 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("Logma state key %q was not created", pattern)
}

func postJSON(t *testing.T, ctx context.Context, endpoint, apiKey string, body any) {
	t.Helper()
	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(encoded))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", apiKey)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		t.Fatalf("POST %s returned %s", endpoint, resp.Status)
	}
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
