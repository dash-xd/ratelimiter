package ratelimiter

import "testing"

func TestWorkerKeyspace(t *testing.T) {
	got, err := WorkerKeyspace("dev-46c0018509a9a00f", "ratelimiter", "lifecycle")
	if err != nil {
		t.Fatal(err)
	}
	const want = "dev-46c0018509a9a00f:ratelimiter:lifecycle"
	if got != want {
		t.Fatalf("WorkerKeyspace() = %q, want %q", got, want)
	}
}

func TestWorkerKeyspaceRejectsAmbiguousSegments(t *testing.T) {
	tests := []struct {
		name      string
		scope     string
		subsystem string
		resource  []string
	}{
		{name: "empty scope", scope: "", subsystem: "ratelimiter"},
		{name: "empty subsystem", scope: "dev", subsystem: ""},
		{name: "empty resource", scope: "dev", subsystem: "ratelimiter", resource: []string{""}},
		{name: "scope delimiter", scope: "dev:worker", subsystem: "ratelimiter"},
		{name: "scope glob", scope: "dev-*", subsystem: "ratelimiter"},
		{name: "subsystem glob", scope: "dev", subsystem: "rate?limiter"},
		{name: "resource class", scope: "dev", subsystem: "ratelimiter", resource: []string{"life[cycle]"}},
		{name: "hash tag", scope: "dev", subsystem: "ratelimiter", resource: []string{"{shared}"}},
		{name: "whitespace", scope: "dev", subsystem: "rate limiter"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := WorkerKeyspace(test.scope, test.subsystem, test.resource...); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestWorkerKeyspaceDoesNotSilentlyRewriteSegments(t *testing.T) {
	for _, input := range []string{" lifecycle", "lifecycle ", ":lifecycle", "lifecycle:"} {
		if _, err := WorkerKeyspace("dev", "ratelimiter", input); err == nil {
			t.Fatalf("WorkerKeyspace accepted ambiguous resource %q", input)
		}
	}
}
