package main

import (
	"slices"
	"testing"
)

func TestParseProfiles(t *testing.T) {
	profiles, err := parseProfiles("minimal, lifecycle, minimal")
	if err != nil {
		t.Fatal(err)
	}
	if len(profiles) != 2 {
		t.Fatalf("got %d profiles, want 2", len(profiles))
	}
}

func TestParseProfilesRejectsUnknownProfile(t *testing.T) {
	if _, err := parseProfiles("minimal,unknown"); err == nil {
		t.Fatal("expected unknown profile to be rejected")
	}
}

func TestTimerRuntimeACLCommands(t *testing.T) {
	profiles, err := parseProfiles("lifecycle")
	if err != nil {
		t.Fatal(err)
	}
	commands := timerRuntimeACLCommands(profiles)
	for _, required := range []string{"fcall", "type", "time", "zadd", "hset", "hexists", "zrangebyscore", "hget", "publish", "zrem", "hdel"} {
		if !slices.Contains(commands, required) {
			t.Fatalf("missing timer runtime ACL command %q in %v", required, commands)
		}
	}
	for _, forbidden := range []string{"function", "config", "acl"} {
		if slices.Contains(commands, forbidden) {
			t.Fatalf("bootstrap/admin command %q leaked into runtime ACL descriptor", forbidden)
		}
	}
}
