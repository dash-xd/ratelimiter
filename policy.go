package ratelimiter

import (
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/dash-xd/ratelimiter/internal/profiledef"
)

const (
	// PolicyVersion1 is retained only so early-development policy codes can be
	// decoded during the transition. New policies are always encoded as v2.
	PolicyVersion1 uint8 = 1
	PolicyVersion2 uint8 = 2
)

type PolicyCode uint64
type PolicyFeature uint16

const (
	FeatureCallbacks PolicyFeature = 1 << iota
	FeatureTimer
	FeatureBlockedState
)

// CountID is an opaque wire identifier for a supported bounded count. It is
// used for burst capacity, publish totals, and concurrency ceilings. The ID is
// identity only; numeric ordering comes from the descriptor value.
type CountID uint8

// LimitID and ScaleClass are migration aliases. V2 no longer has a generic
// mathematical scale class; callers should prefer CountID for bounded counts.
type LimitID = CountID
type ScaleClass = CountID

type countDescriptor struct {
	ID    CountID
	Value uint64
}

var countDescriptors = []countDescriptor{
	{0, 0},
	{1, 1},
	{2, 2},
	{3, 3},
	{4, 4},
	{5, 5},
	{6, 8},
	{7, 10},
	{8, 16},
	{9, 20},
	{10, 32},
	{11, 50},
	{12, 64},
	{13, 100},
	{14, 128},
	{15, 200},
	{16, 256},
	{17, 500},
	{18, 512},
	{19, 1000},
	{20, 1024},
	{21, 2000},
	{22, 4096},
	{23, 5000},
	{24, 8192},
	{25, 10000},
	{26, 16384},
	{27, 20000},
	{28, 32768},
	{29, 50000},
	{30, 65536},
	{31, 100000},
	{32, 131072},
	{33, 250000},
	{34, 262144},
	{35, 500000},
	{36, 524288},
	{37, 1000000},
}

func countDescriptorFor(id CountID) (countDescriptor, bool) {
	for _, descriptor := range countDescriptors {
		if descriptor.ID == id {
			return descriptor, true
		}
	}
	return countDescriptor{}, false
}

func NewCountID(value uint64) (CountID, error) {
	for _, descriptor := range countDescriptors {
		if descriptor.Value == value {
			return descriptor.ID, nil
		}
	}
	return 0, fmt.Errorf("count %d is not in the supported count registry", value)
}

func NewLimitID(value uint64) (LimitID, error)       { return NewCountID(value) }
func NewScaleClass(value uint64) (ScaleClass, error) { return NewCountID(value) }

func (id CountID) Value() uint64 {
	descriptor, ok := countDescriptorFor(id)
	if !ok {
		return 0
	}
	return descriptor.Value
}

// RateID is an opaque wire identifier for a sustained requests-per-second
// ceiling. It is intentionally a different type from CountID: a rate has units
// and must not be compared to a burst capacity or total publish count.
type RateID uint8

type rateDescriptor struct {
	ID                RateID
	RequestsPerSecond uint64
}

// Rate IDs are independent protocol identities even where their numeric IDs
// happen to match CountIDs today. New rates append new IDs; callers compare the
// descriptor's RequestsPerSecond value, never the ID.
var rateDescriptors = []rateDescriptor{
	{0, 0},
	{1, 1},
	{2, 2},
	{3, 3},
	{4, 4},
	{5, 5},
	{6, 8},
	{7, 10},
	{8, 16},
	{9, 20},
	{10, 32},
	{11, 50},
	{12, 64},
	{13, 100},
	{14, 128},
	{15, 200},
	{16, 256},
	{17, 500},
	{18, 512},
	{19, 1000},
	{20, 1024},
	{21, 2000},
	{22, 4096},
	{23, 5000},
	{24, 8192},
	{25, 10000},
	{26, 16384},
	{27, 20000},
	{28, 32768},
	{29, 50000},
	{30, 65536},
	{31, 100000},
	{32, 131072},
	{33, 250000},
	{34, 262144},
	{35, 500000},
	{36, 524288},
	{37, 1000000},
}

func rateDescriptorFor(id RateID) (rateDescriptor, bool) {
	for _, descriptor := range rateDescriptors {
		if descriptor.ID == id {
			return descriptor, true
		}
	}
	return rateDescriptor{}, false
}

func NewRateID(requestsPerSecond uint64) (RateID, error) {
	for _, descriptor := range rateDescriptors {
		if descriptor.RequestsPerSecond == requestsPerSecond {
			return descriptor.ID, nil
		}
	}
	return 0, fmt.Errorf("rate %d requests/second is not in the supported rate registry", requestsPerSecond)
}

func (id RateID) RequestsPerSecond() uint64 {
	descriptor, ok := rateDescriptorFor(id)
	if !ok {
		return 0
	}
	return descriptor.RequestsPerSecond
}

// DurationID is an opaque v2 wire identifier. IDs are cleanly assigned in
// semantic order today, but callers must still compare Duration(), not IDs.
type DurationID uint8
type DurationClass = DurationID

const (
	DurationNone DurationID = iota
	Duration1S
	Duration3S
	Duration10S
	Duration30S
	Duration1M
	Duration5M
	Duration10M
	Duration20M
	Duration1H
	Duration6H
	Duration24H
	Duration3D
	Duration7D
	Duration14D
	Duration30D
)

type durationDescriptor struct {
	ID       DurationID
	Duration time.Duration
}

var durationDescriptors = []durationDescriptor{
	{DurationNone, 0},
	{Duration1S, time.Second},
	{Duration3S, 3 * time.Second},
	{Duration10S, 10 * time.Second},
	{Duration30S, 30 * time.Second},
	{Duration1M, time.Minute},
	{Duration5M, 5 * time.Minute},
	{Duration10M, 10 * time.Minute},
	{Duration20M, 20 * time.Minute},
	{Duration1H, time.Hour},
	{Duration6H, 6 * time.Hour},
	{Duration24H, 24 * time.Hour},
	{Duration3D, 3 * 24 * time.Hour},
	{Duration7D, 7 * 24 * time.Hour},
	{Duration14D, 14 * 24 * time.Hour},
	{Duration30D, 30 * 24 * time.Hour},
}

func durationDescriptorFor(id DurationID) (durationDescriptor, bool) {
	for _, descriptor := range durationDescriptors {
		if descriptor.ID == id {
			return descriptor, true
		}
	}
	return durationDescriptor{}, false
}

func (id DurationID) Duration() time.Duration {
	descriptor, ok := durationDescriptorFor(id)
	if !ok {
		return 0
	}
	return descriptor.Duration
}

func DurationIDFor(duration time.Duration) (DurationID, error) {
	for _, descriptor := range durationDescriptors {
		if descriptor.Duration == duration {
			return descriptor.ID, nil
		}
	}
	return 0, fmt.Errorf("duration %s is not in the supported duration registry", duration)
}

func DurationClassFor(duration time.Duration) (DurationClass, error) { return DurationIDFor(duration) }

// PolicySpec contains only machine-enforceable policy dimensions. Pricing tier
// names and allocation strategies intentionally live outside the wire protocol.
type PolicySpec struct {
	Rate        RateID
	Burst       CountID
	Publishes   CountID
	Duration    DurationID
	Concurrency CountID
	Features    PolicyFeature
}

func (p PolicySpec) Validate() error {
	if _, ok := rateDescriptorFor(p.Rate); !ok {
		return fmt.Errorf("unknown rate id %d", p.Rate)
	}
	for name, id := range map[string]CountID{
		"burst": p.Burst, "publishes": p.Publishes, "concurrency": p.Concurrency,
	} {
		if _, ok := countDescriptorFor(id); !ok {
			return fmt.Errorf("unknown %s count id %d", name, id)
		}
	}
	if _, ok := durationDescriptorFor(p.Duration); !ok {
		return fmt.Errorf("unknown duration id %d", p.Duration)
	}
	return nil
}

func (p PolicySpec) RequiredFeatures() PolicyFeature {
	features := p.Features
	if p.Duration != DurationNone {
		features |= FeatureTimer
	}
	return features
}

func (p PolicySpec) Requirements() Capability {
	required := Capability(0)
	if p.Rate != 0 || p.Publishes != 0 {
		required |= CapabilityWindow
	}
	if p.Burst != 0 {
		required |= CapabilityBurst
	}
	if p.Concurrency != 0 {
		required |= CapabilityConcurrency
	}
	features := p.RequiredFeatures()
	if features&FeatureTimer != 0 {
		required |= CapabilityTimer
	}
	if features&FeatureCallbacks != 0 {
		required |= CapabilityCallbacks
	}
	if features&FeatureBlockedState != 0 {
		required |= CapabilityBlockedState
	}
	return required
}

// Entitlement is an explicit security/pricing boundary. A commercial plan may
// map to an entitlement while usage accounting and billing remain independent.
type Entitlement struct {
	Features       PolicyFeature
	MaxRate        RateID
	MaxBurst       CountID
	MaxPublishes   CountID
	MaxDuration    DurationID
	MaxConcurrency CountID
}

func EntitlementFor(policy PolicySpec) Entitlement {
	return Entitlement{
		Features:       policy.RequiredFeatures(),
		MaxRate:        policy.Rate,
		MaxBurst:       policy.Burst,
		MaxPublishes:   policy.Publishes,
		MaxDuration:    policy.Duration,
		MaxConcurrency: policy.Concurrency,
	}
}

func (e Entitlement) Allows(policy PolicySpec) error {
	if err := policy.Validate(); err != nil {
		return err
	}
	if _, ok := rateDescriptorFor(e.MaxRate); !ok {
		return fmt.Errorf("unknown entitlement max rate id %d", e.MaxRate)
	}
	for name, id := range map[string]CountID{
		"max burst": e.MaxBurst, "max publishes": e.MaxPublishes, "max concurrency": e.MaxConcurrency,
	} {
		if _, ok := countDescriptorFor(id); !ok {
			return fmt.Errorf("unknown entitlement %s id %d", name, id)
		}
	}
	if _, ok := durationDescriptorFor(e.MaxDuration); !ok {
		return fmt.Errorf("unknown entitlement duration id %d", e.MaxDuration)
	}
	if required := policy.RequiredFeatures(); required&^e.Features != 0 {
		return fmt.Errorf("policy features %#x exceed entitlement features %#x", required, e.Features)
	}
	if policy.Rate.RequestsPerSecond() > e.MaxRate.RequestsPerSecond() {
		return errors.New("policy rate exceeds entitlement ceiling")
	}
	if policy.Burst.Value() > e.MaxBurst.Value() {
		return errors.New("policy burst exceeds entitlement ceiling")
	}
	if policy.Publishes.Value() > e.MaxPublishes.Value() {
		return errors.New("policy publish limit exceeds entitlement ceiling")
	}
	if policy.Duration.Duration() > e.MaxDuration.Duration() {
		return errors.New("policy duration exceeds entitlement ceiling")
	}
	if policy.Concurrency.Value() > e.MaxConcurrency.Value() {
		return errors.New("policy concurrency exceeds entitlement ceiling")
	}
	return nil
}

func ValidatePolicy(profile Profile, policy PolicySpec, entitlement Entitlement) error {
	if err := profiledef.Validate(profile); err != nil {
		return err
	}
	if err := entitlement.Allows(policy); err != nil {
		return err
	}
	required := policy.Requirements()
	available := ProfileCapabilities(profile)
	if !available.HasAll(required) {
		return fmt.Errorf("%s profile capabilities %#x do not satisfy policy requirements %#x", profiledef.KindOf(profile), available, required)
	}
	return nil
}

// V2 wire layout:
//   bits  0..7   rate RateID (requests/second descriptor)
//   bits  8..15  burst CountID
//   bits 16..23  publishes CountID
//   bits 24..31  duration DurationID
//   bits 32..39  concurrency CountID
//   bits 40..55  feature mask
//   bits 56..59  reserved (zero)
//   bits 60..63  version
func EncodePolicy(p PolicySpec) (PolicyCode, error) {
	if err := p.Validate(); err != nil {
		return 0, err
	}
	code := uint64(PolicyVersion2) << 60
	code |= uint64(p.Rate)
	code |= uint64(p.Burst) << 8
	code |= uint64(p.Publishes) << 16
	code |= uint64(p.Duration) << 24
	code |= uint64(p.Concurrency) << 32
	code |= uint64(p.Features) << 40
	return PolicyCode(code), nil
}

func DecodePolicy(code PolicyCode) (PolicySpec, error) {
	version := uint8(uint64(code) >> 60)
	if uint64(code)&(uint64(0x0f)<<56) != 0 {
		return PolicySpec{}, errors.New("policy reserved bits are non-zero")
	}
	switch version {
	case PolicyVersion2:
		policy := PolicySpec{
			Rate:        RateID(uint64(code) & 0xff),
			Burst:       CountID((uint64(code) >> 8) & 0xff),
			Publishes:   CountID((uint64(code) >> 16) & 0xff),
			Duration:    DurationID((uint64(code) >> 24) & 0xff),
			Concurrency: CountID((uint64(code) >> 32) & 0xff),
			Features:    PolicyFeature((uint64(code) >> 40) & 0xffff),
		}
		return policy, policy.Validate()
	case PolicyVersion1:
		return decodePolicyV1(code)
	default:
		return PolicySpec{}, fmt.Errorf("unsupported policy encoding version %d", version)
	}
}

// decodePolicyV1 is migration-only. Legacy ScaleClass values are translated to
// their actual numeric values, then looked up in the appropriate v2 registry.
// Legacy allocation strategy bits are intentionally discarded because v2 does
// not encode pricing/allocation strategy.
func decodePolicyV1(code PolicyCode) (PolicySpec, error) {
	legacyValue := func(raw uint8) uint64 {
		if raw == 0 {
			return 0
		}
		packed := raw - 1
		return uint64((packed&0x0f)+1) << (packed >> 4)
	}
	legacyCount := func(raw uint8) (CountID, error) {
		return NewCountID(legacyValue(raw))
	}
	legacyRate := func(raw uint8) (RateID, error) {
		return NewRateID(legacyValue(raw))
	}
	legacyDuration := func(raw uint8) (DurationID, error) {
		switch raw {
		case 0:
			return DurationNone, nil
		case 1:
			return Duration1S, nil
		case 2:
			return Duration3S, nil
		case 3:
			return Duration10S, nil
		case 4:
			return Duration30S, nil
		case 5:
			return Duration1M, nil
		case 6:
			return Duration5M, nil
		case 7:
			return Duration20M, nil
		case 8:
			return Duration1H, nil
		case 9:
			return Duration6H, nil
		case 10:
			return Duration24H, nil
		case 11:
			return Duration3D, nil
		case 12:
			return Duration7D, nil
		case 13:
			return Duration14D, nil
		case 14:
			return Duration30D, nil
		case 15:
			return Duration10M, nil
		default:
			return 0, fmt.Errorf("unknown v1 duration code %d", raw)
		}
	}

	rate, err := legacyRate(uint8(uint64(code) & 0xff))
	if err != nil {
		return PolicySpec{}, fmt.Errorf("decode v1 rate: %w", err)
	}
	burst, err := legacyCount(uint8((uint64(code) >> 8) & 0xff))
	if err != nil {
		return PolicySpec{}, fmt.Errorf("decode v1 burst: %w", err)
	}
	publishes, err := legacyCount(uint8((uint64(code) >> 16) & 0xff))
	if err != nil {
		return PolicySpec{}, fmt.Errorf("decode v1 publishes: %w", err)
	}
	duration, err := legacyDuration(uint8((uint64(code) >> 24) & 0xff))
	if err != nil {
		return PolicySpec{}, err
	}
	concurrency, err := legacyCount(uint8((uint64(code) >> 32) & 0xff))
	if err != nil {
		return PolicySpec{}, fmt.Errorf("decode v1 concurrency: %w", err)
	}
	policy := PolicySpec{
		Rate:        rate,
		Burst:       burst,
		Publishes:   publishes,
		Duration:    duration,
		Concurrency: concurrency,
		Features:    PolicyFeature((uint64(code) >> 44) & 0x0fff),
	}
	return policy, policy.Validate()
}

type CompiledPolicy struct {
	Code              PolicyCode
	RequestsPerSecond uint64
	Burst             uint64
	Publishes         uint64
	Duration          time.Duration
	Concurrency       uint64
	Features          PolicyFeature
}

func CompilePolicy(profile Profile, policy PolicySpec, entitlement Entitlement) (CompiledPolicy, error) {
	if err := ValidatePolicy(profile, policy, entitlement); err != nil {
		return CompiledPolicy{}, err
	}
	code, err := EncodePolicy(policy)
	if err != nil {
		return CompiledPolicy{}, err
	}
	return CompiledPolicy{
		Code:              code,
		RequestsPerSecond: policy.Rate.RequestsPerSecond(),
		Burst:             policy.Burst.Value(),
		Publishes:         policy.Publishes.Value(),
		Duration:          policy.Duration.Duration(),
		Concurrency:       policy.Concurrency.Value(),
		Features:          policy.RequiredFeatures(),
	}, nil
}

func OrderedCountIDs() []CountID {
	descriptors := append([]countDescriptor(nil), countDescriptors...)
	sort.Slice(descriptors, func(i, j int) bool { return descriptors[i].Value < descriptors[j].Value })
	out := make([]CountID, len(descriptors))
	for i, descriptor := range descriptors {
		out[i] = descriptor.ID
	}
	return out
}

func OrderedLimitIDs() []LimitID { return OrderedCountIDs() }

func OrderedRateIDs() []RateID {
	descriptors := append([]rateDescriptor(nil), rateDescriptors...)
	sort.Slice(descriptors, func(i, j int) bool {
		return descriptors[i].RequestsPerSecond < descriptors[j].RequestsPerSecond
	})
	out := make([]RateID, len(descriptors))
	for i, descriptor := range descriptors {
		out[i] = descriptor.ID
	}
	return out
}

func OrderedDurationIDs() []DurationID {
	descriptors := append([]durationDescriptor(nil), durationDescriptors...)
	sort.Slice(descriptors, func(i, j int) bool { return descriptors[i].Duration < descriptors[j].Duration })
	out := make([]DurationID, len(descriptors))
	for i, descriptor := range descriptors {
		out[i] = descriptor.ID
	}
	return out
}
