package ratelimiter

import (
	"context"
	"fmt"
	"time"

	"github.com/dash-xd/ratelimiter/internal/profiledef"
)

// CheckBurst performs one atomic token-bucket admission decision. Redis TIME is
// the authoritative clock and the bucket starts full on first use or after safe
// idle expiry.
func (l *Limiter) CheckBurst(ctx context.Context, in Input, limit BurstLimit) (BurstDecision, error) {
	if l == nil || l.store == nil || l.store.store == nil {
		return BurstDecision{}, fmt.Errorf("limiter is not initialized")
	}
	if err := in.validate(); err != nil {
		return BurstDecision{}, fmt.Errorf("validate input: %w", err)
	}
	if in.Preflight.hasConditions() {
		return BurstDecision{}, fmt.Errorf("burst profile does not accept lifecycle preflight conditions")
	}
	if err := limit.validate(); err != nil {
		return BurstDecision{}, fmt.Errorf("validate burst limit: %w", err)
	}
	if !profiledef.SupportsBurst(l.profile) {
		return BurstDecision{}, fmt.Errorf("%s profile does not support burst admission", profiledef.KindOf(l.profile))
	}

	values, err := l.store.store.Call(
		ctx,
		profiledef.FunctionName(l.profile),
		[]string{l.store.store.BurstKey(in.Bucket)},
		limit.RequestsPerSecond,
		limit.Capacity,
	)
	if err != nil {
		return BurstDecision{}, err
	}
	return decodeBurstDecision(values)
}

func decodeBurstDecision(values []any) (BurstDecision, error) {
	if len(values) != 4 {
		return BurstDecision{}, fmt.Errorf("unexpected burst limiter response length %d", len(values))
	}
	ints := make([]int64, len(values))
	for i, value := range values {
		v, ok := value.(int64)
		if !ok {
			return BurstDecision{}, fmt.Errorf("unexpected burst response value %d type %T", i, value)
		}
		ints[i] = v
	}
	return BurstDecision{
		Allowed:    ints[0] == 0,
		Remaining:  ints[1],
		RetryAfter: time.Duration(ints[2]) * time.Millisecond,
		ObservedAt: time.UnixMilli(ints[3]).UTC(),
	}, nil
}
