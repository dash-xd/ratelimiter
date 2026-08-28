package ratelimiter

import "fmt"

type profileKind string

const (
	profileMinimal   profileKind = "minimal"
	profilePreflight profileKind = "preflight"
	profileDecisions profileKind = "decisions"
	profileLifecycle profileKind = "lifecycle"
)

// Target is one best-effort Pub/Sub callback destination for a lifecycle stage.
// Data is predetermined profile data; Input.CallbackData is merged into it per
// request.
type Target struct {
	Channel string
	Purpose Purpose
	Data    Metadata
}

// TargetResolver chooses zero or more Pub/Sub destinations for a request/stage.
// Returning no targets suppresses publication for that stage and request.
type TargetResolver interface {
	ResolveTargets(Input, Stage) []Target
}

// TargetResolverFunc adapts a function into a TargetResolver.
type TargetResolverFunc func(Input, Stage) []Target

func (f TargetResolverFunc) ResolveTargets(in Input, stage Stage) []Target {
	return f(in, stage)
}

// Profile selects a named Redis Function contract and, for observable profiles,
// the callback routing policy used to prepare that function's event context.
type Profile struct {
	kind     profileKind
	resolver TargetResolver
}

// Minimal registers/uses only the exact sliding-window decision function. It
// does not publish and only touches the window ZSET.
func Minimal() Profile {
	return Profile{kind: profileMinimal}
}

// Preflight publishes only the preflight stage, then performs the decision.
func Preflight(resolver TargetResolver) Profile {
	return Profile{kind: profilePreflight, resolver: resolver}
}

// Decisions publishes the allowed or blocked decision stage, but no preflight.
func Decisions(resolver TargetResolver) Profile {
	return Profile{kind: profileDecisions, resolver: resolver}
}

// Lifecycle publishes preflight and the final allowed/blocked stage.
func Lifecycle(resolver TargetResolver) Profile {
	return Profile{kind: profileLifecycle, resolver: resolver}
}

func (p Profile) validate() error {
	switch p.kind {
	case profileMinimal:
		return nil
	case profilePreflight, profileDecisions, profileLifecycle:
		if p.resolver == nil {
			return fmt.Errorf("%s profile requires a target resolver", p.kind)
		}
		return nil
	default:
		return fmt.Errorf("unknown rate limiter profile %q", p.kind)
	}
}

func (p Profile) publishes() bool {
	return p.kind != profileMinimal
}

func (p Profile) usesBlockedKey() bool {
	return p.kind == profileDecisions || p.kind == profileLifecycle
}

func (p Profile) functionName() string {
	switch p.kind {
	case profileMinimal:
		return "dashxd_ratelimit_minimal_v1"
	case profilePreflight:
		return "dashxd_ratelimit_preflight_v1"
	case profileDecisions:
		return "dashxd_ratelimit_decisions_v1"
	case profileLifecycle:
		return "dashxd_ratelimit_lifecycle_v1"
	default:
		return ""
	}
}

func (p Profile) libraryName() string {
	return "dashxd_ratelimiter_" + string(p.kind) + "_v1"
}

func (p Profile) registration() string {
	return fmt.Sprintf("redis.register_function('%s', %s)", p.functionName(), p.luaWrapperName())
}

func (p Profile) luaWrapperName() string {
	switch p.kind {
	case profileMinimal:
		return "rate_limit_minimal"
	case profilePreflight:
		return "rate_limit_preflight"
	case profileDecisions:
		return "rate_limit_decisions"
	case profileLifecycle:
		return "rate_limit_lifecycle"
	default:
		return ""
	}
}
