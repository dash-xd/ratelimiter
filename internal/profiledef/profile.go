package profiledef

import "fmt"

type Kind string

const (
	MinimalKind   Kind = "minimal"
	PreflightKind Kind = "preflight"
	DecisionsKind Kind = "decisions"
	LifecycleKind Kind = "lifecycle"
)

type Capability uint16

const (
	CapabilityWindow Capability = 1 << iota
	CapabilityCallbacks
	CapabilityPreflight
	CapabilityTimer
	CapabilityBlockedState
	CapabilityBurst
	CapabilityConcurrency
)

func (c Capability) HasAll(required Capability) bool {
	return c&required == required
}

// Definition is an opaque rate-limiter composition. Public callers construct
// values through one of the profile packages.
type Definition struct {
	kind     Kind
	resolver any
}

func Minimal() Definition {
	return Definition{kind: MinimalKind}
}

func Preflight(resolver any) Definition {
	return Definition{kind: PreflightKind, resolver: resolver}
}

func Decisions(resolver any) Definition {
	return Definition{kind: DecisionsKind, resolver: resolver}
}

func Lifecycle(resolver any) Definition {
	return Definition{kind: LifecycleKind, resolver: resolver}
}

func Validate(d Definition) error {
	switch d.kind {
	case MinimalKind:
		return nil
	case PreflightKind, DecisionsKind, LifecycleKind:
		if d.resolver == nil {
			return fmt.Errorf("%s profile requires a target resolver", d.kind)
		}
		return nil
	default:
		return fmt.Errorf("unknown rate limiter profile %q", d.kind)
	}
}

func KindOf(d Definition) Kind {
	return d.kind
}

func ResolverOf(d Definition) any {
	return d.resolver
}

func Capabilities(d Definition) Capability {
	switch d.kind {
	case MinimalKind:
		return CapabilityWindow
	case PreflightKind:
		return CapabilityWindow | CapabilityCallbacks | CapabilityPreflight | CapabilityTimer
	case DecisionsKind:
		return CapabilityWindow | CapabilityCallbacks | CapabilityBlockedState
	case LifecycleKind:
		return CapabilityWindow | CapabilityCallbacks | CapabilityPreflight | CapabilityTimer | CapabilityBlockedState
	default:
		return 0
	}
}

func Publishes(d Definition) bool {
	return Capabilities(d).HasAll(CapabilityCallbacks)
}

func UsesBlockedKey(d Definition) bool {
	return Capabilities(d).HasAll(CapabilityBlockedState)
}

func SupportsPreflight(d Definition) bool {
	return Capabilities(d).HasAll(CapabilityPreflight)
}

func FunctionName(d Definition) string {
	switch d.kind {
	case MinimalKind:
		return "dashxd_ratelimit_minimal_v1"
	case PreflightKind:
		return "dashxd_ratelimit_preflight_v1"
	case DecisionsKind:
		return "dashxd_ratelimit_decisions_v1"
	case LifecycleKind:
		return "dashxd_ratelimit_lifecycle_v1"
	default:
		return ""
	}
}

func TimerTickFunctionName(d Definition) string {
	switch d.kind {
	case PreflightKind:
		return "dashxd_ratelimit_preflight_timer_tick_v1"
	case LifecycleKind:
		return "dashxd_ratelimit_lifecycle_timer_tick_v1"
	default:
		return ""
	}
}

func TimerCancelFunctionName(d Definition) string {
	switch d.kind {
	case PreflightKind:
		return "dashxd_ratelimit_preflight_timer_cancel_v1"
	case LifecycleKind:
		return "dashxd_ratelimit_lifecycle_timer_cancel_v1"
	default:
		return ""
	}
}

func LibraryName(d Definition) string {
	if d.kind == "" {
		return ""
	}
	return "dashxd_ratelimiter_" + string(d.kind) + "_v1"
}

func LuaWrapperName(d Definition) string {
	switch d.kind {
	case MinimalKind:
		return "rate_limit_minimal"
	case PreflightKind:
		return "rate_limit_preflight"
	case DecisionsKind:
		return "rate_limit_decisions"
	case LifecycleKind:
		return "rate_limit_lifecycle"
	default:
		return ""
	}
}
