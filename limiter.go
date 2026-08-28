package ratelimiter

import (
	"context"
	"fmt"
	"time"
)

// Limiter binds one of the named profiles to a RedisStore.
type Limiter struct {
	store   *RedisStore
	profile Profile
}

func (s *RedisStore) Limiter(profile Profile) (*Limiter, error) {
	if err := profile.validate(); err != nil {
		return nil, err
	}
	return &Limiter{store: s, profile: profile}, nil
}

func (l *Limiter) Check(ctx context.Context, in Input, limit Limit) (Decision, error) {
	if err := in.validate(); err != nil {
		return Decision{}, fmt.Errorf("validate input: %w", err)
	}
	if err := limit.validate(); err != nil {
		return Decision{}, fmt.Errorf("validate limit: %w", err)
	}

	windowKey, blockedKey := l.store.keys(in.Bucket)
	windowMS := limit.Window.Milliseconds()

	args := []any{
		"FCALL",
		l.profile.functionName(),
	}

	if l.profile.publishes() {
		ctxJSON, err := buildEventContext(l.profile, in)
		if err != nil {
			return Decision{}, err
		}
		if l.profile.usesBlockedKey() {
			args = append(args, 2, windowKey, blockedKey, limit.MaxRequests, windowMS, string(ctxJSON))
		} else {
			args = append(args, 1, windowKey, limit.MaxRequests, windowMS, string(ctxJSON))
		}
	} else {
		args = append(args, 1, windowKey, limit.MaxRequests, windowMS)
	}

	values, err := l.store.client.Do(ctx, args...).Slice()
	if err != nil {
		return Decision{}, fmt.Errorf("fcall %s: %w", l.profile.functionName(), err)
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
