package ratelimiter

import (
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/dash-xd/ratelimiter/internal/profiledef"
)

const (
	// PolicyVersion1 is retained only so persisted early-development policy codes
	// can be decoded during the transition. New policies are always encoded as v2.
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

// LimitID is an opaque wire identifier for a supported numeric limit. It is
// deliberately not an ordinal and must never be compared numerically. The
// descriptor registry is the source of truth for the actual value.
type LimitID uint8

// ScaleClass is kept as a source-compatibility alias while downstream callers
// migrate to LimitID. It no longer has exponent/mantissa semantics in v2.
type ScaleClass = LimitID

type limitDescriptor struct {
	ID    LimitID
	Value uint64
}

// The v2 registry intentionally favors common operational values. Adding a new
// value means appending a new stable ID; existing IDs never move. Ordering is
// derived from Value, never from ID.
var limitDescriptors = []limitDescriptor{
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

func limitDescriptorFor(id LimitID) (limitDescriptor, bool) {
	for _, descriptor := range limitDescriptors {
		if descriptor.ID == id {
			return descriptor, true
		}
	}
	return limitDescriptor{}, false
}

func NewLimitID(value uint64) (LimitID, error) {
	for _, descriptor := range limitDescriptors {
		if descriptor.Value == value {
			return descriptor.ID, nil
		}
	}
	return 0, fmt.Errorf("limit %d is not in the supported limit registry", value)
}

// NewScaleClass is the compatibility spelling for NewLimitID.
func NewScaleClass(value uint64) (ScaleClass, error) { return NewLimitID(value) }

func (id LimitID) Value() uint64 {
	descriptor, ok := limitDescriptorFor(id)
	if !ok {
		return 0
	}
	return descriptor.Value
}

// DurationID is an opaque v2 wire identifier. v2 IDs are cleanly assigned in
// semantic order today, but callers must still compare Duration(), not IDs.
type DurationID uint8

// DurationClass is retained as a source-compatibility alias.
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

// Strategy remains a policy hint, not a pricing algorithm. v2 does not derive
// entitlements or pricing from Strategy.
type Strategy uint8

const (
	StrategyFixed Strategy = iota
	StrategyBalanced
	StrategyRateFirst
	StrategyDurationFirst
	StrategyBurstFirst
)

type PolicySpec struct {
	Rate        LimitID
	Burst       LimitID
	Publishes   LimitID
	Duration    DurationID
	Concurrency LimitID
	Strategy    Strategy
	Features    PolicyFeature
}

func (p PolicySpec) Validate() error {
	for name, id := range map[string]LimitID{
		"rate": p.Rate, "burst": p.Burst, "publishes": p.Publishes, "concurrency": p.Concurrency,
	} {
		if _, ok := limitDescriptorFor(id); !ok {
			return fmt.Errorf("unknown %s limit id %d", name, id)
		}
	}
	if _, ok := durationDescriptorFor(p.Duration); !ok {
		return fmt.Errorf("unknown duration id %d", p.Duration)
	}
	if p.Strategy > StrategyBurstFirst {
		return fmt.Errorf("unknown strategy %d", p.Strategy)
	}
	if p.Features&^PolicyFeature(0x0fff) != 0 {
		return errors.New("policy feature mask exceeds 12 bits")
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

// Entitlement is deliberately boring: it is an explicit security/pricing
// boundary. A commercial plan may map to one entitlement and usage can be
// billed independently; there is no synthetic "energy" currency in v2.
type Entitlement struct {
	Features       PolicyFeature
	MaxRate        LimitID
	MaxBurst       LimitID
	MaxPublishes   LimitID
	MaxDuration    DurationID
	MaxConcurrency LimitID
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
	for name, id := range map[string]LimitID{
		"max rate": e.MaxRate, "max burst": e.MaxBurst, "max publishes": e.MaxPublishes, "max concurrency": e.MaxConcurrency,
	} {
		if _, ok := limitDescriptorFor(id); !ok {
			return fmt.Errorf("unknown entitlement %s id %d", name, id)
		}
	}
	if _, ok := durationDescriptorFor(e.MaxDuration); !ok {
		return fmt.Errorf("unknown entitlement duration id %d", e.MaxDuration)
	}
	if required := policy.RequiredFeatures(); required&^e.Features != 0 {
		return fmt.Errorf("policy features %#x exceed entitlement features %#x", required, e.Features)
	}
	if policy.Rate.Value() > e.MaxRate.Value() {
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

// v2 keeps the compact 64-bit envelope but changes the four 8-bit numeric
// fields into descriptor IDs. Layout:
//   bits  0..7   rate LimitID
//   bits  8..15  burst LimitID
//   bits 16..23  publishes LimitID
//   bits 24..31  duration DurationID
//   bits 32..39  concurrency LimitID
//   bits 40..43  strategy
//   bits 44..55  features
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
	code |= uint64(p.Strategy&0x0f) << 40
	code |= uint64(p.Features&0x0fff) << 44
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
			Rate:        LimitID(uint64(code) & 0xff),
			Burst:       LimitID((uint64(code) >> 8) & 0xff),
			Publishes:   LimitID((uint64(code) >> 16) & 0xff),
			Duration:    DurationID((uint64(code) >> 24) & 0xff),
			Concurrency: LimitID((uint64(code) >> 32) & 0xff),
			Strategy:    Strategy((uint64(code) >> 40) & 0x0f),
			Features:    PolicyFeature((uint64(code) >> 44) & 0x0fff),
		}
		return policy, policy.Validate()
	case PolicyVersion1:
		return decodePolicyV1(code)
	default:
		return PolicySpec{}, fmt.Errorf("unsupported policy encoding version %d", version)
	}
}

// decodePolicyV1 is migration-only. v1 ScaleClass values are translated into
// explicit v2 registry IDs and fail closed if a legacy value has no v2 entry.
func decodePolicyV1(code PolicyCode) (PolicySpec, error) {
	legacyLimit := func(raw uint8) (LimitID, error) {
		if raw == 0 {
			return 0, nil
		}
		packed := raw - 1
		value := uint64((packed&0x0f)+1) << (packed >> 4)
		return NewLimitID(value)
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

	rate, err := legacyLimit(uint8(uint64(code) & 0xff))
	if err != nil {
		return PolicySpec{}, fmt.Errorf("decode v1 rate: %w", err)
	}
	burst, err := legacyLimit(uint8((uint64(code) >> 8) & 0xff))
	if err != nil {
		return PolicySpec{}, fmt.Errorf("decode v1 burst: %w", err)
	}
	publishes, err := legacyLimit(uint8((uint64(code) >> 16) & 0xff))
	if err != nil {
		return PolicySpec{}, fmt.Errorf("decode v1 publishes: %w", err)
	}
	duration, err := legacyDuration(uint8((uint64(code) >> 24) & 0xff))
	if err != nil {
		return PolicySpec{}, err
	}
	concurrency, err := legacyLimit(uint8((uint64(code) >> 32) & 0xff))
	if err != nil {
		return PolicySpec{}, fmt.Errorf("decode v1 concurrency: %w", err)
	}
	policy := PolicySpec{
		Rate:        rate,
		Burst:       burst,
		Publishes:   publishes,
		Duration:    duration,
		Concurrency: concurrency,
		Strategy:    Strategy((uint64(code) >> 40) & 0x0f),
		Features:    PolicyFeature((uint64(code) >> 44) & 0x0fff),
	}
	return policy, policy.Validate()
}

type CompiledPolicy struct {
	Code        PolicyCode
	Rate        uint64
	Burst       uint64
	Publishes   uint64
	Duration    time.Duration
	Concurrency uint64
	Strategy    Strategy
	Features    PolicyFeature
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
		Code:        code,
		Rate:        policy.Rate.Value(),
		Burst:       policy.Burst.Value(),
		Publishes:   policy.Publishes.Value(),
		Duration:    policy.Duration.Duration(),
		Concurrency: policy.Concurrency.Value(),
		Strategy:    policy.Strategy,
		Features:    policy.RequiredFeatures(),
	}, nil
}

// AllocatePolicy remains as a convenience for callers that want a policy at
// their entitlement ceilings. v2 intentionally does not invent a cross-axis
// mathematical budget. Strategy is retained only as a runtime hint.
func AllocatePolicy(profile Profile, entitlement Entitlement, strategy Strategy) (PolicySpec, error) {
	if strategy == StrategyFixed {
		return PolicySpec{}, errors.New("fixed strategy requires an explicit policy")
	}
	policy := PolicySpec{
		Rate:        entitlement.MaxRate,
		Burst:       entitlement.MaxBurst,
		Publishes:   entitlement.MaxPublishes,
		Duration:    entitlement.MaxDuration,
		Concurrency: entitlement.MaxConcurrency,
		Strategy:    strategy,
	}
	policy.Features = entitlement.Features &^ FeatureTimer
	if err := ValidatePolicy(profile, policy, entitlement); err != nil {
		return PolicySpec{}, err
	}
	return policy, nil
}

// OrderedLimitIDs and OrderedDurationIDs expose semantic order without leaking
// wire-ID ordering assumptions into callers.
func OrderedLimitIDs() []LimitID {
	descriptors := append([]limitDescriptor(nil), limitDescriptors...)
	sort.Slice(descriptors, func(i, j int) bool { return descriptors[i].Value < descriptors[j].Value })
	out := make([]LimitID, len(descriptors))
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
