package ratelimiter_test

import (
	"testing"
	"time"

	ratelimiter "github.com/dash-xd/ratelimiter"
)

func TestLifecycleDurationClassesRoundTripThroughPolicyCode(t *testing.T) {
	cases := []struct {
		class ratelimiter.DurationClass
		want  time.Duration
	}{
		{ratelimiter.Duration30S, 30 * time.Second},
		{ratelimiter.Duration1M, time.Minute},
		{ratelimiter.Duration24H, 24 * time.Hour},
		{ratelimiter.Duration3D, 3 * 24 * time.Hour},
		{ratelimiter.Duration7D, 7 * 24 * time.Hour},
		{ratelimiter.Duration14D, 14 * 24 * time.Hour},
		{ratelimiter.Duration30D, 30 * 24 * time.Hour},
	}

	for _, tc := range cases {
		if got := tc.class.Duration(); got != tc.want {
			t.Fatalf("duration class %d = %s, want %s", tc.class, got, tc.want)
		}
		policy, err := ratelimiter.LifecyclePolicy(tc.class)
		if err != nil {
			t.Fatal(err)
		}
		code, err := ratelimiter.EncodePolicy(policy)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := ratelimiter.DecodePolicy(code)
		if err != nil {
			t.Fatal(err)
		}
		if decoded.Duration != tc.class {
			t.Fatalf("decoded duration = %d, want %d", decoded.Duration, tc.class)
		}
	}
}

func TestNamedLifecyclePoliciesCompileToFixedDurations(t *testing.T) {
	cases := []struct {
		name ratelimiter.LifecyclePolicyName
		want ratelimiter.DurationClass
	}{
		{ratelimiter.LifecycleSmoke30S, ratelimiter.Duration30S},
		{ratelimiter.LifecycleSmoke1M, ratelimiter.Duration1M},
		{ratelimiter.LifecycleSandbox1D, ratelimiter.Duration24H},
		{ratelimiter.LifecycleSandbox30D, ratelimiter.Duration30D},
	}

	for _, tc := range cases {
		policy, err := ratelimiter.NamedLifecyclePolicy(tc.name)
		if err != nil {
			t.Fatal(err)
		}
		if policy.Duration != tc.want || policy.Strategy != ratelimiter.StrategyFixed {
			t.Fatalf("policy %q = %#v", tc.name, policy)
		}
		if policy.RequiredFeatures()&ratelimiter.FeatureTimer == 0 || policy.RequiredFeatures()&ratelimiter.FeatureCallbacks == 0 {
			t.Fatalf("policy %q missing lifecycle features %#x", tc.name, policy.RequiredFeatures())
		}
	}
}

func TestLifecycleDeadlineUsesOriginalActivationTime(t *testing.T) {
	activated := time.Date(2026, 8, 30, 10, 0, 0, 0, time.UTC)
	policy, err := ratelimiter.NamedLifecyclePolicy(ratelimiter.LifecycleSandbox30D)
	if err != nil {
		t.Fatal(err)
	}
	code, err := ratelimiter.EncodePolicy(policy)
	if err != nil {
		t.Fatal(err)
	}

	deadline, err := ratelimiter.LifecycleDeadline(activated, code)
	if err != nil {
		t.Fatal(err)
	}
	want := activated.Add(30 * 24 * time.Hour)
	if !deadline.Equal(want) {
		t.Fatalf("deadline = %s, want %s", deadline, want)
	}

	// A reconstruction a week later must still resolve the original deadline.
	reconstructed, err := ratelimiter.LifecycleDeadline(activated, code)
	if err != nil {
		t.Fatal(err)
	}
	if !reconstructed.Equal(deadline) {
		t.Fatalf("reconstructed deadline = %s, want %s", reconstructed, deadline)
	}
}
