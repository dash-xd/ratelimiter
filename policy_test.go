package ratelimiter_test

import (
	"testing"
	"time"

	ratelimiter "github.com/dash-xd/ratelimiter"
	minimalprofile "github.com/dash-xd/ratelimiter/profile/minimal"
	preflightprofile "github.com/dash-xd/ratelimiter/profile/preflight"
)

func TestPolicyCodeRoundTripUsesExplicitLimitIDs(t *testing.T) {
	three, err := ratelimiter.NewLimitID(3)
	if err != nil {
		t.Fatal(err)
	}
	sixtyFour, err := ratelimiter.NewLimitID(64)
	if err != nil {
		t.Fatal(err)
	}
	if three.Value() != 3 || sixtyFour.Value() != 64 {
		t.Fatalf("limit decode = %d, %d", three.Value(), sixtyFour.Value())
	}

	policy := ratelimiter.PolicySpec{
		Publishes: sixtyFour,
		Burst:     three,
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
	publishes, err := ratelimiter.NewLimitID(64)
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
	three, _ := ratelimiter.NewLimitID(3)
	two, _ := ratelimiter.NewLimitID(2)
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

func TestAllocatePolicyUsesExplicitPlanCeilings(t *testing.T) {
	resolver := ratelimiter.TargetResolverFunc(func(ratelimiter.Input, ratelimiter.Stage) []ratelimiter.Target { return nil })
	profile := preflightprofile.New(resolver)
	rate, _ := ratelimiter.NewLimitID(64)
	burst, _ := ratelimiter.NewLimitID(16)
	publishes, _ := ratelimiter.NewLimitID(100)
	entitlement := ratelimiter.Entitlement{
		Features:     ratelimiter.FeatureTimer,
		MaxRate:      rate,
		MaxBurst:     burst,
		MaxPublishes: publishes,
		MaxDuration:  ratelimiter.Duration20M,
	}

	policy, err := ratelimiter.AllocatePolicy(profile, entitlement, ratelimiter.StrategyBurstFirst)
	if err != nil {
		t.Fatal(err)
	}
	if policy.Rate.Value() != 64 || policy.Burst.Value() != 16 || policy.Publishes.Value() != 100 || policy.Duration.Duration() != 20*time.Minute {
		t.Fatalf("allocated policy = %#v", policy)
	}
}

func TestBurstCanScaleIndependentlyFromSustainedRate(t *testing.T) {
	rate, _ := ratelimiter.NewLimitID(10)
	burst, _ := ratelimiter.NewLimitID(50)
	policy := ratelimiter.PolicySpec{Rate: rate, Burst: burst}
	entitlement := ratelimiter.EntitlementFor(policy)
	if err := entitlement.Allows(policy); err != nil {
		t.Fatal(err)
	}
	if policy.Burst.Value() <= policy.Rate.Value() {
		t.Fatalf("burst=%d should exceed sustained rate=%d", policy.Burst.Value(), policy.Rate.Value())
	}
}

func TestUnsupportedFutureAxesFailProfileValidation(t *testing.T) {
	burst, _ := ratelimiter.NewLimitID(4)
	policy := ratelimiter.PolicySpec{Burst: burst}
	if err := ratelimiter.ValidatePolicy(minimalprofile.New(), policy, ratelimiter.EntitlementFor(policy)); err == nil {
		t.Fatal("expected unsupported burst capability to fail")
	}
}
