package ratelimiter_test

import (
	"testing"

	"github.com/dash-xd/ratelimiter"
	decisionsprofile "github.com/dash-xd/ratelimiter/profile/decisions"
	lifecycleprofile "github.com/dash-xd/ratelimiter/profile/lifecycle"
	minimalprofile "github.com/dash-xd/ratelimiter/profile/minimal"
	preflightprofile "github.com/dash-xd/ratelimiter/profile/preflight"
)

func TestProfilesComposeThroughImports(t *testing.T) {
	resolver := ratelimiter.TargetResolverFunc(func(ratelimiter.Input, ratelimiter.Stage) []ratelimiter.Target {
		return nil
	})

	profiles := []ratelimiter.Profile{
		minimalprofile.New(),
		preflightprofile.New(resolver),
		decisionsprofile.New(resolver),
		lifecycleprofile.New(resolver),
	}

	if len(profiles) != 4 {
		t.Fatalf("got %d profiles, want 4", len(profiles))
	}
}
