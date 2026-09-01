package ratelimiter_test

import (
	"testing"
	"time"

	ratelimiter "github.com/dash-xd/ratelimiter"
)

func TestDurationClassWireProtocolFixtures(t *testing.T) {
	fixtures := []struct {
		class    ratelimiter.DurationClass
		wire     uint64
		duration time.Duration
	}{
		{ratelimiter.DurationNone, 0, 0},
		{ratelimiter.Duration1S, 1, time.Second},
		{ratelimiter.Duration3S, 2, 3 * time.Second},
		{ratelimiter.Duration10S, 3, 10 * time.Second},
		{ratelimiter.Duration30S, 4, 30 * time.Second},
		{ratelimiter.Duration1M, 5, time.Minute},
		{ratelimiter.Duration5M, 6, 5 * time.Minute},
		{ratelimiter.Duration20M, 7, 20 * time.Minute},
		{ratelimiter.Duration1H, 8, time.Hour},
		{ratelimiter.Duration6H, 9, 6 * time.Hour},
		{ratelimiter.Duration24H, 10, 24 * time.Hour},
		{ratelimiter.Duration3D, 11, 3 * 24 * time.Hour},
		{ratelimiter.Duration7D, 12, 7 * 24 * time.Hour},
		{ratelimiter.Duration14D, 13, 14 * 24 * time.Hour},
		{ratelimiter.Duration30D, 14, 30 * 24 * time.Hour},
		// 10m was added later and therefore deliberately uses appended wire code 15.
		{ratelimiter.Duration10M, 15, 10 * time.Minute},
	}

	for _, fixture := range fixtures {
		if got := fixture.class.Duration(); got != fixture.duration {
			t.Fatalf("DurationClass(%d).Duration() = %s, want %s", fixture.class, got, fixture.duration)
		}
		code, err := ratelimiter.EncodePolicy(ratelimiter.PolicySpec{Duration: fixture.class})
		if err != nil {
			t.Fatalf("EncodePolicy(DurationClass(%d)): %v", fixture.class, err)
		}
		if got := (uint64(code) >> 24) & 0xff; got != fixture.wire {
			t.Fatalf("DurationClass(%d) wire byte = %d, want %d", fixture.class, got, fixture.wire)
		}
		decoded, err := ratelimiter.DecodePolicy(code)
		if err != nil {
			t.Fatalf("DecodePolicy(DurationClass(%d)): %v", fixture.class, err)
		}
		if decoded.Duration != fixture.class {
			t.Fatalf("decoded duration = %d, want %d", decoded.Duration, fixture.class)
		}
	}
}

func TestPolicyProtocolRejectsUnknownDurationAndReservedBits(t *testing.T) {
	unknownDuration := ratelimiter.PolicyCode(uint64(ratelimiter.PolicyVersion1)<<60 | uint64(0xff)<<24)
	if _, err := ratelimiter.DecodePolicy(unknownDuration); err == nil {
		t.Fatal("DecodePolicy accepted unknown duration wire value")
	}

	reservedBit := ratelimiter.PolicyCode(uint64(ratelimiter.PolicyVersion1)<<60 | uint64(1)<<56)
	if _, err := ratelimiter.DecodePolicy(reservedBit); err == nil {
		t.Fatal("DecodePolicy accepted non-zero reserved bits")
	}
}

func TestScaleClassRejectsNonRepresentableValues(t *testing.T) {
	if _, err := ratelimiter.NewScaleClass(17); err == nil {
		t.Fatal("NewScaleClass accepted non-representable value 17")
	}
}
