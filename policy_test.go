package ratelimiter_test

import (
	"testing"
	"time"

	ratelimiter "github.com/dash-xd/ratelimiter"
	minimalprofile "github.com/dash-xd/ratelimiter/profile/minimal"
	preflightprofile "github.com/dash-xd/ratelimiter/profile/preflight"
)

func TestPolicyCodeRoundTripAndExactScaleClasses(t *testing.T) {
	three, err := ratelimiter.NewScaleClass(3)
	if err != nil {
		t.Fatal(err)
	}
	sixtyFour, err := ratelimiter.NewScaleClass(64)
	if err != nil {
		t.Fatal(err)
	}
	if three.Value() != 3 || sixtyFour.Value() != 64 {
		t.Fatalf("scale decode = %d, %d", three.Value(), sixtyFour.Value())
	}

	policy := ratelimiter.PolicySpec{
		Publishes: sixtyFour,
		Duration:  ratelimiter.Duration30S,
		Features:  ratelimiter.FeatureCallbacks,
	}
	code, err := ratelimiter.EncodePolicy(policy)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := ratelimiter.DecodePolicy(code)
	if err != nil {
		t.Fatal(err)
	}
	if decoded != policy {
		t.Fatalf("decoded policy = %#v, want %#v", decoded, policy)
	}
}

func TestCompilePolicyUsesProfileCapabilitiesAndEntitlement(t *testing.T) {
	resolver := ratelimiter.TargetResolverFunc(func(ratelimiter.Input, ratelimiter.Stage) []ratelimiter.Target { return nil })
	profile := preflightprofile.New(resolver)
	publishes, err := ratelimiter.NewScaleClass(64)
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
	if compiled.Energy != policy.EnergyCost() {
		t.Fatalf("energy = %d, want %d", compiled.Energy, policy.EnergyCost())
	}

	if _, err := ratelimiter.CompilePolicy(minimalprofile.New(), policy, ratelimiter.EntitlementFor(policy)); err == nil {
		t.Fatal("minimal profile unexpectedly accepted timer policy")
	}
}

func TestEntitlementRejectsEnergyFeaturesAndCeilings(t *testing.T) {
	three, _ := ratelimiter.NewScaleClass(3)
	policy := ratelimiter.PolicySpec{
		Publishes: three,
		Duration:  ratelimiter.Duration3S,
		Features:  ratelimiter.FeatureCallbacks,
	}
	entitlement := ratelimiter.EntitlementFor(policy)
	entitlement.Energy--
	if err := entitlement.Allows(policy); err == nil {
		t.Fatal("expected energy rejection")
	}

	entitlement = ratelimiter.EntitlementFor(policy)
	entitlement.Features &^= ratelimiter.FeatureCallbacks
	if err := entitlement.Allows(policy); err == nil {
		t.Fatal("expected feature rejection")
	}

	entitlement = ratelimiter.EntitlementFor(policy)
	entitlement.MaxPublishes, _ = ratelimiter.NewScaleClass(2)
	if err := entitlement.Allows(policy); err == nil {
		t.Fatal("expected publish ceiling rejection")
	}
}

func TestAllocatePolicyIsMonotonicAcrossEnergy(t *testing.T) {
	resolver := ratelimiter.TargetResolverFunc(func(ratelimiter.Input, ratelimiter.Stage) []ratelimiter.Target { return nil })
	profile := preflightprofile.New(resolver)
	maxRate, _ := ratelimiter.NewScaleClass(64)
	maxPublishes, _ := ratelimiter.NewScaleClass(64)
	base := ratelimiter.Entitlement{
		Features:     ratelimiter.FeatureAdaptive | ratelimiter.FeatureTimer,
		MaxRate:      maxRate,
		MaxPublishes: maxPublishes,
		MaxDuration:  ratelimiter.Duration20M,
	}

	low := base
	low.Energy = 12
	high := base
	high.Energy = 20

	lowPolicy, err := ratelimiter.AllocatePolicy(profile, low, ratelimiter.StrategyBalanced)
	if err != nil {
		t.Fatal(err)
	}
	highPolicy, err := ratelimiter.AllocatePolicy(profile, high, ratelimiter.StrategyBalanced)
	if err != nil {
		t.Fatal(err)
	}
	if highPolicy.Rate.Value() < lowPolicy.Rate.Value() ||
		highPolicy.Publishes.Value() < lowPolicy.Publishes.Value() ||
		highPolicy.Duration < lowPolicy.Duration {
		t.Fatalf("allocation regressed: low=%#v high=%#v", lowPolicy, highPolicy)
	}
}

func TestUnsupportedFutureAxesFailProfileValidation(t *testing.T) {
	burst, _ := ratelimiter.NewScaleClass(4)
	policy := ratelimiter.PolicySpec{Burst: burst}
	if err := ratelimiter.ValidatePolicy(minimalprofile.New(), policy, ratelimiter.EntitlementFor(policy)); err == nil {
		t.Fatal("expected unsupported burst capability to fail")
	}
}
