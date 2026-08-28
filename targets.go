package ratelimiter

import "strings"

// StaticTargets returns a resolver backed by a fixed stage-to-target mapping.
// Returned targets are copied so callers cannot mutate the profile indirectly.
func StaticTargets(targets map[Stage][]Target) TargetResolver {
	copied := cloneTargetsByStage(targets)
	return TargetResolverFunc(func(_ Input, stage Stage) []Target {
		return cloneTargets(copied[stage])
	})
}

// NamespaceTargets routes every stage to the same hierarchical channel formed
// from non-empty namespace segments followed by suffix.
func NamespaceTargets(suffix string, purpose Purpose, data Metadata) TargetResolver {
	return TargetResolverFunc(func(in Input, _ Stage) []Target {
		return []Target{{
			Channel: namespaceChannel(in.Request.Namespace, suffix),
			Purpose: purpose,
			Data:    cloneMetadata(data),
		}}
	})
}

// NamespaceStageTargets is NamespaceTargets with the lifecycle stage appended
// to the channel, useful when independent subscribers own different stages.
func NamespaceStageTargets(suffix string, purpose Purpose, data Metadata) TargetResolver {
	return TargetResolverFunc(func(in Input, stage Stage) []Target {
		return []Target{{
			Channel: namespaceChannel(in.Request.Namespace, suffix, string(stage)),
			Purpose: purpose,
			Data:    cloneMetadata(data),
		}}
	})
}

func namespaceChannel(ns Namespace, tail ...string) string {
	parts := make([]string, 0, 3+len(tail))
	for _, part := range []string{ns.Environment, ns.Parent, ns.Child} {
		if part != "" {
			parts = append(parts, part)
		}
	}
	for _, part := range tail {
		if part != "" {
			parts = append(parts, part)
		}
	}
	return strings.Join(parts, ":")
}

func cloneTargetsByStage(src map[Stage][]Target) map[Stage][]Target {
	out := make(map[Stage][]Target, len(src))
	for stage, targets := range src {
		out[stage] = cloneTargets(targets)
	}
	return out
}

func cloneTargets(src []Target) []Target {
	out := make([]Target, len(src))
	for i, target := range src {
		out[i] = target
		out[i].Data = cloneMetadata(target.Data)
	}
	return out
}

func cloneMetadata(src Metadata) Metadata {
	if len(src) == 0 {
		return nil
	}
	out := make(Metadata, len(src))
	for key, value := range src {
		out[key] = value
	}
	return out
}
