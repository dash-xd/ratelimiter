package ratelimiter

import "github.com/dash-xd/ratelimiter/internal/profiledef"

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

// Profile is an opaque rate-limiter composition. Import one of the profile
// packages under github.com/dash-xd/ratelimiter/profile to construct it.
type Profile = profiledef.Definition
