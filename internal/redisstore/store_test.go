package redisstore

import "testing"

func TestKeysShareClusterHashTag(t *testing.T) {
	store := &Store{keyspace: "prod:ratelimit"}
	window, blocked := store.Keys("tenant-a:client-7")

	const wantWindow = "prod:ratelimit:{tenant-a:client-7}:window"
	const wantBlocked = "prod:ratelimit:{tenant-a:client-7}:blocked"
	if window != wantWindow || blocked != wantBlocked {
		t.Fatalf("unexpected keys: %q %q", window, blocked)
	}
}
