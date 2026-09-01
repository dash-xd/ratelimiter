package ratelimiter

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	maxBucketLength       = 512
	maxChannelLength      = 256
	maxPurposeLength      = 64
	maxTargetsPerStage    = 8
	maxMetadataEntries    = 32
	maxMetadataKeyLength  = 64
	maxMetadataValueBytes = 512
	maxEventContextBytes  = 16 * 1024
)

type Stage string

const (
	StagePreflight Stage = "preflight"
	StageAllowed   Stage = "allowed"
	StageBlocked   Stage = "blocked"
	StageShutdown  Stage = "shutdown"
)

type Purpose string

const (
	PurposeMetrics          Purpose = "metrics"
	PurposeLogs             Purpose = "logs"
	PurposeCacheWarm        Purpose = "cache_warm"
	PurposeAnomaly          Purpose = "anomaly_analysis"
	PurposeAdaptivePolicy   Purpose = "adaptive_policy"
	PurposeTracing          Purpose = "tracing"
	PurposeSpeculative      Purpose = "speculative_work"
	PurposeRequestShadow    Purpose = "request_shadow"
	PurposeLifecycleControl Purpose = "lifecycle_control"
)

type Metadata map[string]string

type Namespace struct {
	Environment string `json:"environment,omitempty"`
	Parent      string `json:"parent,omitempty"`
	Child       string `json:"child,omitempty"`
}

type Request struct {
	ID        string    `json:"id,omitempty"`
	Subject   string    `json:"subject,omitempty"`
	Operation string    `json:"operation,omitempty"`
	Resource  string    `json:"resource,omitempty"`
	Namespace Namespace `json:"namespace,omitempty"`
}

type TimerCondition struct {
	After time.Duration
	Reset bool
}

type ShutdownConditions struct {
	Timer *TimerCondition
}

type PreflightOptions struct {
	Shutdown ShutdownConditions
}

type Input struct {
	Bucket string
	Request Request
	CallbackData Metadata
	Preflight PreflightOptions
}

// Limit controls the existing exact rolling-window limiter.
type Limit struct {
	MaxRequests int64
	Window      time.Duration
}

// BurstLimit controls a token bucket. RequestsPerSecond is the sustained refill
// rate and Capacity is the maximum number of immediately spendable tokens.
// The bucket starts full. Redis TIME is authoritative for refill calculations.
type BurstLimit struct {
	RequestsPerSecond int64
	Capacity          int64
}

type Decision struct {
	Allowed         bool
	Count           int64
	Remaining       int64
	RetryAfter      time.Duration
	ObservedAt      time.Time
	BlockedCount    int64
	PublishFailures int64
}

// BurstDecision is intentionally smaller than Decision because token-bucket
// admission has no rolling-window count or callback/blocked-state side effects.
type BurstDecision struct {
	Allowed    bool
	Remaining  int64
	RetryAfter time.Duration
	ObservedAt time.Time
}

type TickResult struct {
	Dispatched      int64
	Pending         int64
	PublishFailures int64
	ObservedAt      time.Time
}

var ErrRateLimited = errors.New("rate limit exceeded")

func (d Decision) Err() error {
	if d.Allowed {
		return nil
	}
	return ErrRateLimited
}

func (d BurstDecision) Err() error {
	if d.Allowed {
		return nil
	}
	return ErrRateLimited
}

func (l Limit) validate() error {
	if l.MaxRequests <= 0 {
		return errors.New("max requests must be greater than zero")
	}
	if l.Window < time.Millisecond {
		return errors.New("window must be at least 1ms")
	}
	if l.Window/time.Millisecond > time.Duration(^uint32(0)) {
		return errors.New("window is unreasonably large")
	}
	return nil
}

func (l BurstLimit) validate() error {
	if l.RequestsPerSecond <= 0 {
		return errors.New("burst requests per second must be greater than zero")
	}
	if l.Capacity <= 0 {
		return errors.New("burst capacity must be greater than zero")
	}
	// Keep arithmetic comfortably inside exact IEEE-754 integer range used by
	// Redis Lua. Policy registries are currently capped far below this bound.
	if l.RequestsPerSecond > 1_000_000_000 || l.Capacity > 1_000_000_000 {
		return errors.New("burst limit is unreasonably large")
	}
	return nil
}

func (in Input) validate() error {
	if in.Bucket == "" {
		return errors.New("bucket is required")
	}
	if len(in.Bucket) > maxBucketLength {
		return fmt.Errorf("bucket exceeds %d bytes", maxBucketLength)
	}
	if strings.ContainsAny(in.Bucket, "{}") {
		return errors.New("bucket must not contain Redis hash-tag braces")
	}
	if err := validateMetadata(in.CallbackData); err != nil {
		return err
	}
	return in.Preflight.validate()
}

func (p PreflightOptions) validate() error {
	if p.Shutdown.Timer == nil {
		return nil
	}
	if p.Shutdown.Timer.After < time.Millisecond {
		return errors.New("preflight shutdown timer must be at least 1ms")
	}
	return nil
}

func (p PreflightOptions) hasConditions() bool {
	return p.Shutdown.Timer != nil
}

func validateMetadata(data Metadata) error {
	if len(data) > maxMetadataEntries {
		return fmt.Errorf("metadata exceeds %d entries", maxMetadataEntries)
	}
	for key, value := range data {
		if key == "" {
			return errors.New("metadata key must not be empty")
		}
		if len(key) > maxMetadataKeyLength {
			return fmt.Errorf("metadata key %q exceeds %d bytes", key, maxMetadataKeyLength)
		}
		if len(value) > maxMetadataValueBytes {
			return fmt.Errorf("metadata value for %q exceeds %d bytes", key, maxMetadataValueBytes)
		}
	}
	return nil
}
