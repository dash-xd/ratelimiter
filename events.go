package ratelimiter

import (
	"encoding/json"
	"fmt"

	"github.com/dash-xd/ratelimiter/internal/profiledef"
)

const (
	EventSchema           = "dashxd.ratelimiter.event.v1"
	LifecycleSignalSchema = "dashxd.ratelimiter.lifecycle.v1"
)

// PubSubMessage is the Logma-compatible outer Pub/Sub envelope. Stateful Logma
// subscriptions decode and forward this shape while Message retains the stable
// rate-limiter event contract.
type PubSubMessage struct {
	Type            string `json:"type"`
	SentTimeUTC     int64  `json:"sentTimeUtc"`
	Message         Event  `json:"message"`
	ParentNamespace string `json:"parentNamespace,omitempty"`
	ChildNamespace  string `json:"childNamespace,omitempty"`
	Channel         string `json:"channel"`
}

// LifecycleSignalMessage uses the same Logma-compatible envelope for lifecycle
// control signals emitted by Redis-owned preflight conditions.
type LifecycleSignalMessage struct {
	Type            string          `json:"type"`
	SentTimeUTC     int64           `json:"sentTimeUtc"`
	Message         LifecycleSignal `json:"message"`
	ParentNamespace string          `json:"parentNamespace,omitempty"`
	ChildNamespace  string          `json:"childNamespace,omitempty"`
	Channel         string          `json:"channel"`
}

// LifecycleSignal is a generic control-plane signal. Timer uses DeadlineUnixMS;
// future count/byte conditions can use Limit and Observed without changing the
// outer dispatch contract.
type LifecycleSignal struct {
	Schema         string        `json:"schema"`
	Type           string        `json:"type"`
	Signal         string        `json:"signal"`
	Condition      string        `json:"condition"`
	SentTimeUnixMS int64         `json:"sent_time_unix_ms"`
	DeadlineUnixMS int64         `json:"deadline_unix_ms,omitempty"`
	Limit          int64         `json:"limit,omitempty"`
	Observed       int64         `json:"observed,omitempty"`
	Bucket         string        `json:"bucket"`
	Request        Request       `json:"request"`
	Callback       EventCallback `json:"callback"`
}

// Event is the stable rate-limiter event carried inside PubSubMessage.Message.
type Event struct {
	Schema         string         `json:"schema"`
	Type           string         `json:"type"`
	Stage          Stage          `json:"stage"`
	SentTimeUnixMS int64          `json:"sent_time_unix_ms"`
	Request        Request        `json:"request"`
	RateLimit      EventRateLimit `json:"rate_limit"`
	Callback       EventCallback  `json:"callback"`
}

type EventRateLimit struct {
	Bucket       string `json:"bucket"`
	MaxRequests  int64  `json:"max_requests"`
	WindowMS     int64  `json:"window_ms"`
	Decision     string `json:"decision"`
	Count        int64  `json:"count,omitempty"`
	Remaining    int64  `json:"remaining,omitempty"`
	RetryAfterMS int64  `json:"retry_after_ms,omitempty"`
	BlockedCount int64  `json:"blocked_count,omitempty"`
}

type EventCallback struct {
	Purpose Purpose  `json:"purpose"`
	Data    Metadata `json:"data,omitempty"`
}

type wireTarget struct {
	Channel string   `json:"channel"`
	Purpose Purpose  `json:"purpose"`
	Data    Metadata `json:"data,omitempty"`
}

type eventContext struct {
	Bucket  string                 `json:"bucket"`
	Request Request                `json:"request"`
	Targets map[Stage][]wireTarget `json:"targets"`
}

func buildEventContext(profile Profile, in Input) ([]byte, error) {
	resolver, ok := profiledef.ResolverOf(profile).(TargetResolver)
	if !ok || resolver == nil {
		return nil, fmt.Errorf("%s profile has an invalid target resolver", profiledef.KindOf(profile))
	}

	stages := stagesForProfile(profiledef.KindOf(profile))
	ctx := eventContext{
		Bucket:  in.Bucket,
		Request: in.Request,
		Targets: make(map[Stage][]wireTarget, len(stages)),
	}

	for _, stage := range stages {
		targets := resolver.ResolveTargets(in, stage)
		if len(targets) > maxTargetsPerStage {
			return nil, fmt.Errorf("%s stage exceeds %d pubsub targets", stage, maxTargetsPerStage)
		}

		for _, target := range targets {
			if target.Channel == "" {
				return nil, fmt.Errorf("%s target channel is empty", stage)
			}
			if len(target.Channel) > maxChannelLength {
				return nil, fmt.Errorf("%s target channel exceeds %d bytes", stage, maxChannelLength)
			}
			if target.Purpose == "" {
				return nil, fmt.Errorf("%s target purpose is empty", stage)
			}
			if len(target.Purpose) > maxPurposeLength {
				return nil, fmt.Errorf("%s target purpose exceeds %d bytes", stage, maxPurposeLength)
			}
			if err := validateMetadata(target.Data); err != nil {
				return nil, fmt.Errorf("%s target metadata: %w", stage, err)
			}

			data := cloneMetadata(target.Data)
			if data == nil && len(in.CallbackData) != 0 {
				data = make(Metadata, len(in.CallbackData))
			}
			for key, value := range in.CallbackData {
				data[key] = value
			}
			if err := validateMetadata(data); err != nil {
				return nil, fmt.Errorf("%s merged target metadata: %w", stage, err)
			}

			ctx.Targets[stage] = append(ctx.Targets[stage], wireTarget{
				Channel: target.Channel,
				Purpose: target.Purpose,
				Data:    data,
			})
		}
	}

	encoded, err := json.Marshal(ctx)
	if err != nil {
		return nil, fmt.Errorf("marshal event context: %w", err)
	}
	if len(encoded) > maxEventContextBytes {
		return nil, fmt.Errorf("event context exceeds %d bytes", maxEventContextBytes)
	}
	return encoded, nil
}

func stagesForProfile(kind profiledef.Kind) []Stage {
	switch kind {
	case profiledef.PreflightKind:
		return []Stage{StagePreflight, StageShutdown}
	case profiledef.DecisionsKind:
		return []Stage{StageAllowed, StageBlocked}
	case profiledef.LifecycleKind:
		return []Stage{StagePreflight, StageAllowed, StageBlocked, StageShutdown}
	default:
		return nil
	}
}
