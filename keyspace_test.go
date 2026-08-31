package ratelimiter

import "testing"

func TestWorkerKeyspace(t *testing.T) {
	got, err := WorkerKeyspace("dev-46c0018509a9a00f", "ratelimiter", "lifecycle")
	if err != nil { t.Fatal(err) }
	want := "dev-46c0018509a9a00f:ratelimiter:lifecycle"
	if got != want { t.Fatalf("WorkerKeyspace=%q want %q", got, want) }
}

func TestWorkerKeyspaceRejectsPatternScope(t *testing.T) {
	if _, err := WorkerKeyspace("dev:*", "ratelimiter"); err == nil { t.Fatal("expected scope validation error") }
}
