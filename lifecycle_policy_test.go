package ratelimiter_test

import (
	"testing"
	"time"

	ratelimiter "github.com/dash-xd/ratelimiter"
)

func TestLifecycleDurationIDsRoundTripThroughPolicyCode(t *testing.T) {
	cases := []struct {
		id   ratelimiter.DurationID
		want time.Duration
	}{
		{ratelimiter.Duration30S, 30 * time.Second},
		{ratelimiter.Duration1M, time.Minute},
		{ratelimiter.Duration5M, 5 * time.Minute},
		{ratelimiter.Duration10M, 10 * time.Minute},
		{ratelimiter.Duration20M, 20 * time.Minute},
		{ratelimiter.Duration24H, 24 * time.Hour},
		{ratelimiter.Duration3D, 3 * 24 * time.Hour},
		{ratelimiter.Duration7D, 7 * 24 * time.Hour},
		{ratelimiter.Duration14D, 14 * 24 * time.Hour},
		{ratelimiter.Duration30D, 30 * 24 * time.Hour},
	}

	for _, tc := range cases {
		if got := tc.id.Duration(); got != tc.want {
			t.Fatalf("duration id %d = %s, want %s", tc.id, got, tc.want)
		}
		policy, err := ratelimiter.LifecyclePolicy(tc.id)
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
		if decoded.Duration != tc.id {
			t.Fatalf("decoded duration = %d, want %d", decoded.Duration, tc.id)
		}
	}
}

func TestV2DurationRegistrySlotsTenMinutesNaturally(t *testing.T) {
	want := map[ratelimiter.DurationID]uint64{
		ratelimiter.Duration5M:  6,
		ratelimiter.Duration10M: 7,
		ratelimiter.Duration20M: 8,
		ratelimiter.Duration1H:  9,
		ratelimiter.Duration30D: 15,
	}
	for id, durationByte := range want {
		policy, err := ratelimiter.LifecyclePolicy(id)
		if err != nil {
			t.Fatal(err)
		}
		code, err := ratelimiter.EncodePolicy(policy)
		if err != nil {
			t.Fatal(err)
		}
		if got := uint8(uint64(code) >> 60); got != ratelimiter.PolicyVersion2 {
			t.Fatalf("version = %d, want v2", got)
		}
		if got := (uint64(code) >> 24) & 0xff; got != durationByte {
			t.Fatalf("duration byte for %v = %d, want %d", id, got, durationByte)
		}
	}
}

func TestNamedLifecyclePoliciesCompileToDurations(t *testing.T) {
	cases := []struct {
		name ratelimiter.LifecyclePolicyName
		want ratelimiter.DurationID
	}{
		{ratelimiter.LifecycleSmoke30S, ratelimiter.Duration30S},
		{ratelimiter.LifecycleSmoke1M, ratelimiter.Duration1M},
		{ratelimiter.LifecycleSmoke10M, ratelimiter.Duration10M},
		{ratelimiter.LifecycleSandbox1D, ratelimiter.Duration24H},
		{ratelimiter.LifecycleSandbox30D, ratelimiter.Duration30D},
	}

	for _, tc := range cases {
		policy, err := ratelimiter.NamedLifecyclePolicy(tc.name)
		if err != nil {
			t.Fatal(err)
		}
		if policy.Duration != tc.want {
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

	reconstructed, err := ratelimiter.LifecycleDeadline(activated, code)
	if err != nil {
		t.Fatal(err)
	}
	if !reconstructed.Equal(deadline) {
		t.Fatalf("reconstructed deadline = %s, want %s", reconstructed, deadline)
	}
}
