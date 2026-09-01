package ratelimiter_test

import (
	"testing"
	"time"

	ratelimiter "github.com/dash-xd/ratelimiter"
)

func TestDurationIDV2WireProtocolFixtures(t *testing.T) {
	fixtures := []struct {
		id       ratelimiter.DurationID
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
		{ratelimiter.Duration10M, 7, 10 * time.Minute},
		{ratelimiter.Duration20M, 8, 20 * time.Minute},
		{ratelimiter.Duration1H, 9, time.Hour},
		{ratelimiter.Duration6H, 10, 6 * time.Hour},
		{ratelimiter.Duration24H, 11, 24 * time.Hour},
		{ratelimiter.Duration3D, 12, 3 * 24 * time.Hour},
		{ratelimiter.Duration7D, 13, 7 * 24 * time.Hour},
		{ratelimiter.Duration14D, 14, 14 * 24 * time.Hour},
		{ratelimiter.Duration30D, 15, 30 * 24 * time.Hour},
	}

	for _, fixture := range fixtures {
		if got := fixture.id.Duration(); got != fixture.duration {
			t.Fatalf("DurationID(%d).Duration() = %s, want %s", fixture.id, got, fixture.duration)
		}
		code, err := ratelimiter.EncodePolicy(ratelimiter.PolicySpec{Duration: fixture.id})
		if err != nil {
			t.Fatalf("EncodePolicy(DurationID(%d)): %v", fixture.id, err)
		}
		if got := uint8(uint64(code) >> 60); got != ratelimiter.PolicyVersion2 {
			t.Fatalf("version = %d, want %d", got, ratelimiter.PolicyVersion2)
		}
		if got := (uint64(code) >> 24) & 0xff; got != fixture.wire {
			t.Fatalf("DurationID(%d) wire byte = %d, want %d", fixture.id, got, fixture.wire)
		}
	}
}

func TestV1DurationCodesMigrateIntoV2Descriptors(t *testing.T) {
	legacy := []struct {
		wire uint64
		want ratelimiter.DurationID
	}{
		{7, ratelimiter.Duration20M},
		{15, ratelimiter.Duration10M},
	}
	for _, fixture := range legacy {
		code := ratelimiter.PolicyCode(uint64(ratelimiter.PolicyVersion1)<<60 | fixture.wire<<24)
		decoded, err := ratelimiter.DecodePolicy(code)
		if err != nil {
			t.Fatal(err)
		}
		if decoded.Duration != fixture.want {
			t.Fatalf("v1 duration %d migrated to %d, want %d", fixture.wire, decoded.Duration, fixture.want)
		}
	}
}

func TestV1ScaleClassMigratesByValueNotRawCode(t *testing.T) {
	// v1 raw 6 encoded the value 6. v2 assigns the descriptor ID for value 5
	// to 5 and the descriptor ID for value 8 to 6, so raw identity is no longer
	// semantic identity. Use v1 raw 12, which represented value 12 and is not in
	// the curated v2 registry, to prove migration fails closed rather than silently
	// changing the limit.
	code := ratelimiter.PolicyCode(uint64(ratelimiter.PolicyVersion1)<<60 | uint64(12))
	if _, err := ratelimiter.DecodePolicy(code); err == nil {
		t.Fatal("DecodePolicy accepted legacy limit with no explicit v2 descriptor")
	}
}

func TestPolicyProtocolRejectsUnknownIDsAndReservedBits(t *testing.T) {
	unknownDuration := ratelimiter.PolicyCode(uint64(ratelimiter.PolicyVersion2)<<60 | uint64(0xff)<<24)
	if _, err := ratelimiter.DecodePolicy(unknownDuration); err == nil {
		t.Fatal("DecodePolicy accepted unknown duration ID")
	}

	unknownLimit := ratelimiter.PolicyCode(uint64(ratelimiter.PolicyVersion2)<<60 | uint64(0xff))
	if _, err := ratelimiter.DecodePolicy(unknownLimit); err == nil {
		t.Fatal("DecodePolicy accepted unknown limit ID")
	}

	reservedBit := ratelimiter.PolicyCode(uint64(ratelimiter.PolicyVersion2)<<60 | uint64(1)<<56)
	if _, err := ratelimiter.DecodePolicy(reservedBit); err == nil {
		t.Fatal("DecodePolicy accepted non-zero reserved bits")
	}
}

func TestLimitRegistryIsExplicit(t *testing.T) {
	if _, err := ratelimiter.NewLimitID(17); err == nil {
		t.Fatal("NewLimitID accepted unregistered value 17")
	}
	id, err := ratelimiter.NewLimitID(64)
	if err != nil {
		t.Fatal(err)
	}
	if id.Value() != 64 {
		t.Fatalf("LimitID.Value() = %d, want 64", id.Value())
	}
}
