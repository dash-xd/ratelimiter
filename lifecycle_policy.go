package ratelimiter

import (
	"fmt"
	"time"
)

// LifecyclePolicyName is a stable human-facing alias. It is not part of the
// PolicyCode wire format; the compiled PolicyCode is the canonical machine
// declaration persisted by lifecycle owners.
type LifecyclePolicyName string

const (
	LifecycleSmoke30S   LifecyclePolicyName = "smoke-30s"
	LifecycleSmoke1M    LifecyclePolicyName = "smoke-minute"
	LifecycleSmoke10M   LifecyclePolicyName = "smoke-10m"
	LifecycleSandbox1D  LifecyclePolicyName = "sandbox-day"
	LifecycleSandbox3D  LifecyclePolicyName = "sandbox-3d"
	LifecycleSandbox7D  LifecyclePolicyName = "sandbox-week"
	LifecycleSandbox14D LifecyclePolicyName = "sandbox-14d"
	LifecycleSandbox30D LifecyclePolicyName = "sandbox-month"
)

var namedLifecycleDurations = map[LifecyclePolicyName]DurationClass{
	LifecycleSmoke30S:   Duration30S,
	LifecycleSmoke1M:    Duration1M,
	LifecycleSmoke10M:   Duration10M,
	LifecycleSandbox1D:  Duration24H,
	LifecycleSandbox3D:  Duration3D,
	LifecycleSandbox7D:  Duration7D,
	LifecycleSandbox14D: Duration14D,
	LifecycleSandbox30D: Duration30D,
}

// LifecyclePolicy returns an explicit fixed timer policy. The policy says when
// a lifecycle expires; the caller separately supplies deployment identity and
// shutdown routing, which determine what may receive the lifecycle signal.
func LifecyclePolicy(duration DurationClass) (PolicySpec, error) {
	policy := PolicySpec{
		Duration: duration,
		Strategy: StrategyFixed,
		Features: FeatureCallbacks,
	}
	if duration == DurationNone {
		return PolicySpec{}, fmt.Errorf("lifecycle policy duration is disabled")
	}
	if err := policy.Validate(); err != nil {
		return PolicySpec{}, err
	}
	return policy, nil
}

// NamedLifecyclePolicy compiles a readable alias into the exact PolicySpec that
// is encoded and persisted. Adding or reordering aliases never changes wire
// values; only DurationClass's explicit stable codes do that.
func NamedLifecyclePolicy(name LifecyclePolicyName) (PolicySpec, error) {
	duration, ok := namedLifecycleDurations[name]
	if !ok {
		return PolicySpec{}, fmt.Errorf("unknown lifecycle policy %q", name)
	}
	return LifecyclePolicy(duration)
}

// LifecycleDeadline derives the absolute lifecycle deadline from the original
// activation time and encoded policy. Reconstruction must use the original
// activation time; callers must never rebase a retained lifecycle on restart.
func LifecycleDeadline(activatedAt time.Time, code PolicyCode) (time.Time, error) {
	policy, err := DecodePolicy(code)
	if err != nil {
		return time.Time{}, err
	}
	if policy.Duration == DurationNone {
		return time.Time{}, fmt.Errorf("policy has no lifecycle duration")
	}
	return activatedAt.UTC().Add(policy.Duration.Duration()), nil
}
