package profiledef

import "fmt"

type Kind string

const (
	MinimalKind   Kind = "minimal"
	PreflightKind Kind = "preflight"
	DecisionsKind Kind = "decisions"
	LifecycleKind Kind = "lifecycle"
)

// Definition is an opaque rate-limiter composition. Callers should construct
// definitions through one of the public profile packages.
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

func (d Definition) Validate() error {
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

func (d Definition) Kind() Kind {
	return d.kind
}

func (d Definition) Resolver() any {
	return d.resolver
}

func (d Definition) Publishes() bool {
	return d.kind != MinimalKind
}

func (d Definition) UsesBlockedKey() bool {
	return d.kind == DecisionsKind || d.kind == LifecycleKind
}

func (d Definition) FunctionName() string {
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

func (d Definition) LibraryName() string {
	if d.kind == "" {
		return ""
	}
	return "dashxd_ratelimiter_" + string(d.kind) + "_v1"
}

func (d Definition) LuaWrapperName() string {
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
