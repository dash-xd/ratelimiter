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

// Stage identifies an observable point in the rate-limiter lifecycle.
type Stage string

const (
	StagePreflight Stage = "preflight"
	StageAllowed   Stage = "allowed"
	StageBlocked   Stage = "blocked"
	StageShutdown  Stage = "shutdown"
)

// Purpose describes the intended non-authoritative use of a Pub/Sub callback.
// Correctness-sensitive work such as billing, authorization, guaranteed audit,
// durable jobs, and data mutation should use a durable transport instead.
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

// Metadata is deliberately string-to-string. Keeping callback metadata flat
// makes event validation cheap and keeps Pub/Sub payloads small and predictable.
type Metadata map[string]string

// Namespace is optional routing metadata. It is not interpreted by the limiter
// itself; channel resolvers can use it to preserve an existing hierarchy.
type Namespace struct {
	Environment string `json:"environment,omitempty"`
	Parent      string `json:"parent,omitempty"`
	Child       string `json:"child,omitempty"`
}

// Request describes the logical work being admitted. None of these fields are
// HTTP-specific and all are optional; ID is strongly recommended for tracing.
type Request struct {
	ID        string    `json:"id,omitempty"`
	Subject   string    `json:"subject,omitempty"`
	Operation string    `json:"operation,omitempty"`
	Resource  string    `json:"resource,omitempty"`
	Namespace Namespace `json:"namespace,omitempty"`
}

// TimerCondition arms a Redis-owned shutdown deadline during preflight.
//
// By default an already-armed timer is left unchanged, so repeated preflight
// calls cannot extend a workload's lifetime. Set Reset to explicitly replace
// the existing deadline and shutdown context.
type TimerCondition struct {
	After time.Duration
	Reset bool
}

// ShutdownConditions contains the conditions that can emit a lifecycle shutdown
// signal. Timer is the first condition; additional counters can be added here
// without changing the lifecycle dispatch path.
type ShutdownConditions struct {
	Timer *TimerCondition
}

// PreflightOptions controls lifecycle work performed at the preflight stage.
type PreflightOptions struct {
	Shutdown ShutdownConditions
}

// Input is the normalized unit passed to the limiter.
type Input struct {
	// Bucket identifies the sliding-window bucket and is the only required field.
	// It becomes the Redis Cluster hash tag, so braces are rejected.
	Bucket string

	Request Request

	// CallbackData is merged into each target's predetermined Data. Values here
	// win on duplicate keys, allowing per-request enrichment without rebuilding a
	// static profile.
	CallbackData Metadata

	// Preflight optionally arms Redis-owned lifecycle conditions. Conditions are
	// supported by the preflight and lifecycle profiles.
	Preflight PreflightOptions
}

// Limit controls the exact rolling window.
type Limit struct {
	MaxRequests int64
	Window      time.Duration
}

// Decision is the result of one atomic Redis Function invocation. Rate limiting
// itself is a decision, not an infrastructure error: Check returns nil error for
// both allowed and blocked requests.
type Decision struct {
	Allowed         bool
	Count           int64
	Remaining       int64
	RetryAfter      time.Duration
	ObservedAt      time.Time
	BlockedCount    int64
	PublishFailures int64
}

// TickResult describes one bounded evaluation of Redis-owned preflight
// lifecycle conditions for a bucket.
type TickResult struct {
	Dispatched      int64
	Pending         int64
	PublishFailures int64
	ObservedAt      time.Time
}

var ErrRateLimited = errors.New("rate limit exceeded")

// Err returns ErrRateLimited only when the request was denied. It is a
// convenience for call sites that still prefer the legacy error-shaped flow.
func (d Decision) Err() error {
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
