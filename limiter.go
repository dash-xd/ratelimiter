package ratelimiter

import (
	"context"
	"fmt"
	"time"
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
	if err := profile.Validate(); err != nil {
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

	windowKey, blockedKey := l.store.store.Keys(in.Bucket)
	keys := []string{windowKey}
	args := []any{limit.MaxRequests, limit.Window.Milliseconds()}

	if l.profile.Publishes() {
		ctxJSON, err := buildEventContext(l.profile, in)
		if err != nil {
			return Decision{}, err
		}
		if l.profile.UsesBlockedKey() {
			keys = append(keys, blockedKey)
		}
		args = append(args, string(ctxJSON))
	}

	values, err := l.store.store.Call(ctx, l.profile.FunctionName(), keys, args...)
	if err != nil {
		return Decision{}, err
	}
	return decodeDecision(values)
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
