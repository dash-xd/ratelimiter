package redisstore

import "testing"

func TestKeysShareClusterHashTag(t *testing.T) {
	store := &Store{keyspace: "prod:ratelimit"}
	window, blocked := store.Keys("tenant-a:client-7")
	timers, payloads := store.LifecycleKeys("tenant-a:client-7")

	const wantWindow = "prod:ratelimit:{tenant-a:client-7}:window"
	const wantBlocked = "prod:ratelimit:{tenant-a:client-7}:blocked"
	const wantTimers = "prod:ratelimit:{tenant-a:client-7}:lifecycle:timers"
	const wantPayloads = "prod:ratelimit:{tenant-a:client-7}:lifecycle:payloads"

	if window != wantWindow || blocked != wantBlocked {
		t.Fatalf("unexpected rate-limit keys: %q %q", window, blocked)
	}
	if timers != wantTimers || payloads != wantPayloads {
		t.Fatalf("unexpected lifecycle keys: %q %q", timers, payloads)
	}
}
