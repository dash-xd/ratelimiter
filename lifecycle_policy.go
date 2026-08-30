package ratelimiter

import (
	"fmt"
	"time"
)

// LifecyclePolicyName is the human-facing name of a fixed lifecycle policy.
// The encoded PolicyCode remains the canonical machine declaration.
type LifecyclePolicyName string

const (
	LifecycleSmoke30S  LifecyclePolicyName = "smoke-30s"
	LifecycleSmoke1M   LifecyclePolicyName = "smoke-minute"
	LifecycleSandbox1D LifecyclePolicyName = "sandbox-day"
	LifecycleSandbox3D LifecyclePolicyName = "sandbox-3d"
	LifecycleSandbox7D LifecyclePolicyName = "sandbox-week"
	LifecycleSandbox14D LifecyclePolicyName = "sandbox-14d"
	LifecycleSandbox30D LifecyclePolicyName = "sandbox-month"
)

// LifecyclePolicy returns an explicit fixed timer policy. The policy says when
// a lifecycle expires; the caller separately supplies the deployment identity
// and shutdown target that determine what receives the lifecycle signal.
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

// NamedLifecyclePolicy compiles a readable lifecycle name into the exact
// PolicySpec that is encoded and persisted by callers.
func NamedLifecyclePolicy(name LifecyclePolicyName) (PolicySpec, error) {
	var duration DurationClass
	switch name {
	case LifecycleSmoke30S:
		duration = Duration30S
	case LifecycleSmoke1M:
		duration = Duration1M
	case LifecycleSandbox1D:
		duration = Duration24H
	case LifecycleSandbox3D:
		duration = Duration3D
	case LifecycleSandbox7D:
		duration = Duration7D
	case LifecycleSandbox14D:
		duration = Duration14D
	case LifecycleSandbox30D:
		duration = Duration30D
	default:
		return PolicySpec{}, fmt.Errorf("unknown lifecycle policy %q", name)
	}
	return LifecyclePolicy(duration)
}

// LifecycleDeadline derives the absolute lifecycle deadline from the original
// activation time and encoded policy. Reconstructing a timer after Redis or a
// host restarts must call this with the original activation time; callers must
// not rebase the duration on the restart time.
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
