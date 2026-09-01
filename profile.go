package ratelimiter

import "github.com/dash-xd/ratelimiter/internal/profiledef"

type Target struct {
	Channel string
	Purpose Purpose
	Data    Metadata
}

type TargetResolver interface {
	ResolveTargets(Input, Stage) []Target
}

type TargetResolverFunc func(Input, Stage) []Target

func (f TargetResolverFunc) ResolveTargets(in Input, stage Stage) []Target {
	return f(in, stage)
}

type Profile = profiledef.Definition
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

func TimerRuntimeACLCommands(profile Profile) []string {
	commands := profiledef.TimerRuntimeACLCommands(profile)
	return append([]string(nil), commands...)
}

// BurstRuntimeACLCommands describes the Redis commands required by the token
// bucket FCALL entry point. Bootstrap/admin commands are excluded.
func BurstRuntimeACLCommands(profile Profile) []string {
	commands := profiledef.BurstRuntimeACLCommands(profile)
	return append([]string(nil), commands...)
}
