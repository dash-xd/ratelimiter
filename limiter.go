package ratelimiter

import (
	"context"
	"fmt"
	"time"

	"github.com/dash-xd/ratelimiter/internal/profiledef"
)

// Limiter binds one imported profile to a RedisStore.
type Limiter struct {
	store   *RedisStore
	profile Profile
}

func (s *RedisStore) Limiter(profile Profile) (*Limiter, error) {
	if s == nil || s.store == nil {
		return nil, fmt.Errorf("redis store is not initialized")
	}
	if err := profiledef.Validate(profile); err != nil {
		return nil, err
	}
	return &Limiter{store: s, profile: profile}, nil
}

func (l *Limiter) Check(ctx context.Context, in Input, limit Limit) (Decision, error) {
	if l == nil || l.store == nil || l.store.store == nil {
		return Decision{}, fmt.Errorf("limiter is not initialized")
	}
	if err := in.validate(); err != nil {
		return Decision{}, fmt.Errorf("validate input: %w", err)
	}
	if err := limit.validate(); err != nil {
		return Decision{}, fmt.Errorf("validate limit: %w", err)
	}
	if in.Preflight.hasConditions() && !profiledef.SupportsPreflight(l.profile) {
		return Decision{}, fmt.Errorf(
			"%s profile does not support preflight lifecycle conditions",
			profiledef.KindOf(l.profile),
		)
	}

	windowKey, blockedKey := l.store.store.Keys(in.Bucket)
	keys := []string{windowKey}
	args := []any{limit.MaxRequests, limit.Window.Milliseconds()}

	if profiledef.Publishes(l.profile) {
		ctxJSON, err := buildEventContext(l.profile, in)
		if err != nil {
			return Decision{}, err
		}
		if profiledef.UsesBlockedKey(l.profile) {
			keys = append(keys, blockedKey)
		}
		if profiledef.SupportsPreflight(l.profile) {
			timerKey, payloadKey := l.store.store.LifecycleKeys(in.Bucket)
			keys = append(keys, timerKey, payloadKey)
		}

		args = append(args, string(ctxJSON))
		if profiledef.SupportsPreflight(l.profile) {
			var timerAfterMS int64
			var timerReset int64
			if timer := in.Preflight.Shutdown.Timer; timer != nil {
				timerAfterMS = timer.After.Milliseconds()
				if timer.Reset {
					timerReset = 1
				}
			}
			args = append(args, timerAfterMS, timerReset)
		}
	}

	values, err := l.store.store.Call(ctx, profiledef.FunctionName(l.profile), keys, args...)
	if err != nil {
		return Decision{}, err
	}
	return decodeDecision(values)
}

// ArmTimerAt reconstructs or initially registers a Redis-owned lifecycle timer
// from an absolute deadline. The caller persists the original activation time
// and policy code elsewhere; Redis owns the live deadline and due evaluation.
// With reset=false, an already-armed timer keeps its existing deadline.
func (l *Limiter) ArmTimerAt(
	ctx context.Context,
	in Input,
	deadline time.Time,
	reset bool,
) (bool, error) {
	if l == nil || l.store == nil || l.store.store == nil {
		return false, fmt.Errorf("limiter is not initialized")
	}
	if !profiledef.SupportsPreflight(l.profile) {
		return false, fmt.Errorf(
			"%s profile does not support lifecycle timers",
			profiledef.KindOf(l.profile),
		)
	}
	if deadline.IsZero() {
		return false, fmt.Errorf("lifecycle deadline is required")
	}

	// buildEventContext includes shutdown targets only when lifecycle conditions
	// are present. A synthetic bounded condition marks this as lifecycle context;
	// the absolute deadline below, not this duration, is what Redis stores.
	contextInput := in
	contextInput.Preflight.Shutdown.Timer = &TimerCondition{After: time.Millisecond}
	if err := contextInput.validate(); err != nil {
		return false, fmt.Errorf("validate input: %w", err)
	}
	ctxJSON, err := buildEventContext(l.profile, contextInput)
	if err != nil {
		return false, err
	}

	timerKey, payloadKey := l.store.store.LifecycleKeys(in.Bucket)
	resetArg := int64(0)
	if reset {
		resetArg = 1
	}
	values, err := l.store.store.Call(
		ctx,
		profiledef.TimerArmAbsoluteFunctionName(l.profile),
		[]string{timerKey, payloadKey},
		string(ctxJSON),
		deadline.UTC().UnixMilli(),
		resetArg,
	)
	if err != nil {
		return false, err
	}
	if len(values) != 1 {
		return false, fmt.Errorf("unexpected lifecycle timer arm response length %d", len(values))
	}
	armed, ok := values[0].(int64)
	if !ok {
		return false, fmt.Errorf("unexpected timer arm response type %T", values[0])
	}
	return armed == 1, nil
}

// Tick performs one bounded evaluation of the Redis-owned preflight lifecycle
// conditions for bucket. Callers provide the clock pulse; Redis owns the
// deadline, condition state, and shutdown dispatch decision.
func (l *Limiter) Tick(ctx context.Context, bucket string) (TickResult, error) {
	if l == nil || l.store == nil || l.store.store == nil {
		return TickResult{}, fmt.Errorf("limiter is not initialized")
	}
	if !profiledef.SupportsPreflight(l.profile) {
		return TickResult{}, fmt.Errorf(
			"%s profile does not support preflight lifecycle conditions",
			profiledef.KindOf(l.profile),
		)
	}
	if err := (Input{Bucket: bucket}).validate(); err != nil {
		return TickResult{}, fmt.Errorf("validate bucket: %w", err)
	}

	timerKey, payloadKey := l.store.store.LifecycleKeys(bucket)
	values, err := l.store.store.Call(
		ctx,
		profiledef.TimerTickFunctionName(l.profile),
		[]string{timerKey, payloadKey},
	)
	if err != nil {
		return TickResult{}, err
	}
	return decodeTickResult(values)
}

// CancelTimer removes an armed shutdown timer and its retained callback context.
func (l *Limiter) CancelTimer(ctx context.Context, bucket string) (bool, error) {
	if l == nil || l.store == nil || l.store.store == nil {
		return false, fmt.Errorf("limiter is not initialized")
	}
	if !profiledef.SupportsPreflight(l.profile) {
		return false, fmt.Errorf(
			"%s profile does not support preflight lifecycle conditions",
			profiledef.KindOf(l.profile),
		)
	}
	if err := (Input{Bucket: bucket}).validate(); err != nil {
		return false, fmt.Errorf("validate bucket: %w", err)
	}

	timerKey, payloadKey := l.store.store.LifecycleKeys(bucket)
	values, err := l.store.store.Call(
		ctx,
		profiledef.TimerCancelFunctionName(l.profile),
		[]string{timerKey, payloadKey},
	)
	if err != nil {
		return false, err
	}
	if len(values) != 1 {
		return false, fmt.Errorf("unexpected lifecycle timer cancel response length %d", len(values))
	}
	removed, ok := values[0].(int64)
	if !ok {
		return false, fmt.Errorf("unexpected timer cancel response type %T", values[0])
	}
	return removed == 1, nil
}

func decodeDecision(values []any) (Decision, error) {
	if len(values) != 7 {
		return Decision{}, fmt.Errorf("unexpected rate limiter response length %d", len(values))
	}

	ints := make([]int64, len(values))
	for i, value := range values {
		v, ok := value.(int64)
		if !ok {
			return Decision{}, fmt.Errorf("unexpected response value %d type %T", i, value)
		}
		ints[i] = v
	}

	return Decision{
		Allowed:         ints[0] == 0,
		Count:           ints[1],
		Remaining:       ints[2],
		RetryAfter:      time.Duration(ints[3]) * time.Millisecond,
		ObservedAt:      time.UnixMilli(ints[4]).UTC(),
		BlockedCount:    ints[5],
		PublishFailures: ints[6],
	}, nil
}

func decodeTickResult(values []any) (TickResult, error) {
	if len(values) != 4 {
		return TickResult{}, fmt.Errorf("unexpected lifecycle tick response length %d", len(values))
	}

	ints := make([]int64, len(values))
	for i, value := range values {
		v, ok := value.(int64)
		if !ok {
			return TickResult{}, fmt.Errorf("unexpected tick response value %d type %T", i, value)
		}
		ints[i] = v
	}

	return TickResult{
		Dispatched:      ints[0],
		Pending:         ints[1],
		PublishFailures: ints[2],
		ObservedAt:      time.UnixMilli(ints[3]).UTC(),
	}, nil
}
