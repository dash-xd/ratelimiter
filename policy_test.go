package ratelimiter_test

import (
	"testing"
	"time"

	ratelimiter "github.com/dash-xd/ratelimiter"
	minimalprofile "github.com/dash-xd/ratelimiter/profile/minimal"
	preflightprofile "github.com/dash-xd/ratelimiter/profile/preflight"
)

func TestPolicyCodeRoundTripUsesTypedDescriptorIDs(t *testing.T) {
	burst, err := ratelimiter.NewCountID(3)
	if err != nil {
		t.Fatal(err)
	}
	publishes, err := ratelimiter.NewCountID(64)
	if err != nil {
		t.Fatal(err)
	}
	rate, err := ratelimiter.NewRateID(10)
	if err != nil {
		t.Fatal(err)
	}

	policy := ratelimiter.PolicySpec{
		Rate:       rate,
		Publishes: publishes,
		Burst:     burst,
		Duration:  ratelimiter.Duration30S,
		Features:  ratelimiter.FeatureCallbacks,
	}
	code, err := ratelimiter.EncodePolicy(policy)
	if err != nil {
		t.Fatal(err)
	}
	if got := uint8(uint64(code) >> 60); got != ratelimiter.PolicyVersion2 {
		t.Fatalf("policy version = %d, want %d", got, ratelimiter.PolicyVersion2)
	}
	decoded, err := ratelimiter.DecodePolicy(code)
	if err != nil {
		t.Fatal(err)
	}
	if decoded != policy {
		t.Fatalf("decoded policy = %#v, want %#v", decoded, policy)
	}
}

func TestCompilePolicyUsesProfileCapabilitiesAndExplicitEntitlement(t *testing.T) {
	resolver := ratelimiter.TargetResolverFunc(func(ratelimiter.Input, ratelimiter.Stage) []ratelimiter.Target { return nil })
	profile := preflightprofile.New(resolver)
	publishes, err := ratelimiter.NewCountID(64)
	if err != nil {
		t.Fatal(err)
	}
	policy := ratelimiter.PolicySpec{
		Publishes: publishes,
		Duration:  ratelimiter.Duration30S,
	}
	compiled, err := ratelimiter.CompilePolicy(profile, policy, ratelimiter.EntitlementFor(policy))
	if err != nil {
		t.Fatal(err)
	}
	if compiled.Publishes != 64 || compiled.Duration != 30*time.Second {
		t.Fatalf("compiled policy = %#v", compiled)
	}

	if _, err := ratelimiter.CompilePolicy(minimalprofile.New(), policy, ratelimiter.EntitlementFor(policy)); err == nil {
		t.Fatal("minimal profile unexpectedly accepted timer policy")
	}
}

func TestEntitlementRejectsFeaturesAndIndependentCeilings(t *testing.T) {
	three, _ := ratelimiter.NewCountID(3)
	two, _ := ratelimiter.NewCountID(2)
	policy := ratelimiter.PolicySpec{
		Publishes: three,
		Burst:     three,
		Duration:  ratelimiter.Duration3S,
		Features:  ratelimiter.FeatureCallbacks,
	}

	entitlement := ratelimiter.EntitlementFor(policy)
	entitlement.Features &^= ratelimiter.FeatureCallbacks
	if err := entitlement.Allows(policy); err == nil {
		t.Fatal("expected feature rejection")
	}

	entitlement = ratelimiter.EntitlementFor(policy)
	entitlement.MaxPublishes = two
	if err := entitlement.Allows(policy); err == nil {
		t.Fatal("expected publish ceiling rejection")
	}

	entitlement = ratelimiter.EntitlementFor(policy)
	entitlement.MaxBurst = two
	if err := entitlement.Allows(policy); err == nil {
		t.Fatal("expected burst ceiling rejection")
	}
}

func TestRateAndBurstAreDifferentUnits(t *testing.T) {
	rate, _ := ratelimiter.NewRateID(10)
	burst, _ := ratelimiter.NewCountID(50)
	policy := ratelimiter.PolicySpec{Rate: rate, Burst: burst}
	entitlement := ratelimiter.EntitlementFor(policy)
	if err := entitlement.Allows(policy); err != nil {
		t.Fatal(err)
	}
	if policy.Rate.RequestsPerSecond() != 10 {
		t.Fatalf("rate = %d req/s", policy.Rate.RequestsPerSecond())
	}
	if policy.Burst.Value() != 50 {
		t.Fatalf("burst = %d", policy.Burst.Value())
	}
}

func TestEntitlementRejectsRateAbovePlan(t *testing.T) {
	rate10, _ := ratelimiter.NewRateID(10)
	rate20, _ := ratelimiter.NewRateID(20)
	policy := ratelimiter.PolicySpec{Rate: rate20}
	entitlement := ratelimiter.Entitlement{MaxRate: rate10}
	if err := entitlement.Allows(policy); err == nil {
		t.Fatal("expected sustained rate ceiling rejection")
	}
}

func TestBurstRequiresAnEnforcingProfile(t *testing.T) {
	burst, _ := ratelimiter.NewCountID(4)
	policy := ratelimiter.PolicySpec{Burst: burst}
	if err := ratelimiter.ValidatePolicy(minimalprofile.New(), policy, ratelimiter.EntitlementFor(policy)); err == nil {
		t.Fatal("expected unsupported burst capability to fail")
	}
}
