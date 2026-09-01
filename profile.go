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

// Capability describes execution behavior implemented by a profile. Policies
// use these bits to prove that an allocation can actually be enforced by the
// selected Redis function composition.
type Capability = profiledef.Capability

const (
	CapabilityWindow       Capability = profiledef.CapabilityWindow
	CapabilityCallbacks    Capability = profiledef.CapabilityCallbacks
	CapabilityPreflight    Capability = profiledef.CapabilityPreflight
	CapabilityTimer        Capability = profiledef.CapabilityTimer
	CapabilityBlockedState Capability = profiledef.CapabilityBlockedState
	CapabilityBurst        Capability = profiledef.CapabilityBurst
	CapabilityConcurrency  Capability = profiledef.CapabilityConcurrency
)

func ProfileCapabilities(profile Profile) Capability {
	return profiledef.Capabilities(profile)
}

// TimerRuntimeACLCommands describes the Redis commands required by this
// profile's timer FCALL entry points. Redis checks commands issued from a
// Function against the caller ACL, so deployments must allow these commands in
// addition to scoping keys/channels. Bootstrap/admin commands are excluded.
func TimerRuntimeACLCommands(profile Profile) []string {
	commands := profiledef.TimerRuntimeACLCommands(profile)
	return append([]string(nil), commands...)
}
