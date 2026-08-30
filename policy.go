package ratelimiter

import (
	"errors"
	"fmt"
	"math/bits"
	"time"

	"github.com/dash-xd/ratelimiter/internal/profiledef"
)

const PolicyVersion1 uint8 = 1

type PolicyCode uint64

type PolicyFeature uint16

const (
	FeatureCallbacks PolicyFeature = 1 << iota
	FeatureTimer
	FeatureBlockedState
	FeatureAdaptive
)

type Strategy uint8

const (
	StrategyFixed Strategy = iota
	StrategyBalanced
	StrategyRateFirst
	StrategyDurationFirst
	StrategyBurstFirst
)

// ScaleClass is a compact positive integer class. Zero means disabled. For a
// non-zero class, raw-1 is interpreted as [4-bit exponent | 4-bit mantissa] and
// expands to (mantissa+1)<<exponent. This keeps small limits dense while still
// covering large limits with one byte.
type ScaleClass uint8

func NewScaleClass(value uint64) (ScaleClass, error) {
	if value == 0 {
		return 0, nil
	}
	for raw := 1; raw <= 255; raw++ {
		class := ScaleClass(raw)
		if class.Value() == value {
			return class, nil
		}
	}
	return 0, fmt.Errorf("value %d is not representable as a scale class", value)
}

func (c ScaleClass) Value() uint64 {
	if c == 0 {
		return 0
	}
	packed := uint8(c) - 1
	exponent := packed >> 4
	mantissa := packed & 0x0f
	return uint64(mantissa+1) << exponent
}

func (c ScaleClass) energyMagnitude() uint16 {
	value := c.Value()
	if value == 0 {
		return 0
	}
	return uint16(bits.Len64(value))
}

type DurationClass uint8

const (
	DurationNone DurationClass = iota
	Duration1S
	Duration3S
	Duration10S
	Duration30S
	Duration1M
	Duration5M
	Duration20M
	Duration1H
	Duration6H
	Duration24H
	Duration3D
	Duration7D
	Duration14D
	Duration30D
)

func (c DurationClass) Duration() time.Duration {
	switch c {
	case DurationNone:
		return 0
	case Duration1S:
		return time.Second
	case Duration3S:
		return 3 * time.Second
	case Duration10S:
		return 10 * time.Second
	case Duration30S:
		return 30 * time.Second
	case Duration1M:
		return time.Minute
	case Duration5M:
		return 5 * time.Minute
	case Duration20M:
		return 20 * time.Minute
	case Duration1H:
		return time.Hour
	case Duration6H:
		return 6 * time.Hour
	case Duration24H:
		return 24 * time.Hour
	case Duration3D:
		return 3 * 24 * time.Hour
	case Duration7D:
		return 7 * 24 * time.Hour
	case Duration14D:
		return 14 * 24 * time.Hour
	case Duration30D:
		return 30 * 24 * time.Hour
	default:
		return 0
	}
}

func DurationClassFor(duration time.Duration) (DurationClass, error) {
	for class := DurationNone; class <= Duration30D; class++ {
		if class.Duration() == duration {
			return class, nil
		}
	}
	return 0, fmt.Errorf("duration %s is not a supported duration class", duration)
}

type PolicySpec struct {
	Rate        ScaleClass
	Burst       ScaleClass
	Publishes   ScaleClass
	Duration    DurationClass
	Concurrency ScaleClass
	Strategy    Strategy
	Features    PolicyFeature
}

func (p PolicySpec) Validate() error {
	if p.Duration > Duration30D {
		return fmt.Errorf("unknown duration class %d", p.Duration)
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
	if p.Strategy != StrategyFixed {
		features |= FeatureAdaptive
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

func (p PolicySpec) EnergyCost() uint16 {
	return p.Rate.energyMagnitude()*3 +
		p.Burst.energyMagnitude() +
		p.Publishes.energyMagnitude()*2 +
		uint16(p.Duration)*2 +
		p.Concurrency.energyMagnitude()*4
}

func EncodePolicy(p PolicySpec) (PolicyCode, error) {
	if err := p.Validate(); err != nil {
		return 0, err
	}
	code := uint64(PolicyVersion1) << 60
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
	if version != PolicyVersion1 {
		return PolicySpec{}, fmt.Errorf("unsupported policy encoding version %d", version)
	}
	if uint64(code)&(uint64(0x0f)<<56) != 0 {
		return PolicySpec{}, errors.New("policy reserved bits are non-zero")
	}
	policy := PolicySpec{
		Rate:        ScaleClass(uint64(code) & 0xff),
		Burst:       ScaleClass((uint64(code) >> 8) & 0xff),
		Publishes:   ScaleClass((uint64(code) >> 16) & 0xff),
		Duration:    DurationClass((uint64(code) >> 24) & 0xff),
		Concurrency: ScaleClass((uint64(code) >> 32) & 0xff),
		Strategy:    Strategy((uint64(code) >> 40) & 0x0f),
		Features:    PolicyFeature((uint64(code) >> 44) & 0x0fff),
	}
	return policy, policy.Validate()
}

type Entitlement struct {
	Energy         uint16
	Features       PolicyFeature
	MaxRate        ScaleClass
	MaxBurst       ScaleClass
	MaxPublishes   ScaleClass
	MaxDuration    DurationClass
	MaxConcurrency ScaleClass
}

func EntitlementFor(policy PolicySpec) Entitlement {
	return Entitlement{
		Energy:         policy.EnergyCost(),
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
	requiredFeatures := policy.RequiredFeatures()
	if requiredFeatures&^e.Features != 0 {
		return fmt.Errorf("policy features %#x exceed entitlement features %#x", requiredFeatures, e.Features)
	}
	if policy.EnergyCost() > e.Energy {
		return fmt.Errorf("policy energy %d exceeds entitlement energy %d", policy.EnergyCost(), e.Energy)
	}
	if exceedsScale(policy.Rate, e.MaxRate) {
		return errors.New("policy rate exceeds entitlement ceiling")
	}
	if exceedsScale(policy.Burst, e.MaxBurst) {
		return errors.New("policy burst exceeds entitlement ceiling")
	}
	if exceedsScale(policy.Publishes, e.MaxPublishes) {
		return errors.New("policy publish limit exceeds entitlement ceiling")
	}
	if policy.Duration > e.MaxDuration {
		return errors.New("policy duration exceeds entitlement ceiling")
	}
	if exceedsScale(policy.Concurrency, e.MaxConcurrency) {
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

type CompiledPolicy struct {
	Code        PolicyCode
	Rate        uint64
	Burst       uint64
	Publishes   uint64
	Duration    time.Duration
	Concurrency uint64
	Energy      uint16
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
		Energy:      policy.EnergyCost(),
		Strategy:    policy.Strategy,
		Features:    policy.RequiredFeatures(),
	}, nil
}

func AllocatePolicy(profile Profile, entitlement Entitlement, strategy Strategy) (PolicySpec, error) {
	if strategy == StrategyFixed {
		return PolicySpec{}, errors.New("fixed strategy requires an explicit policy")
	}
	if strategy > StrategyBurstFirst {
		return PolicySpec{}, fmt.Errorf("unknown strategy %d", strategy)
	}
	if err := profiledef.Validate(profile); err != nil {
		return PolicySpec{}, err
	}

	policy := PolicySpec{Strategy: strategy}
	order := allocationOrder(strategy)
	for {
		progressed := false
		for _, dimension := range order {
			candidate, changed := advancePolicy(policy, entitlement, dimension)
			if !changed {
				continue
			}
			if candidate.EnergyCost() > entitlement.Energy {
				return policy, ValidatePolicy(profile, policy, entitlement)
			}
			if !ProfileCapabilities(profile).HasAll(candidate.Requirements()) {
				continue
			}
			policy = candidate
			progressed = true
		}
		if !progressed {
			break
		}
	}
	return policy, ValidatePolicy(profile, policy, entitlement)
}

type allocationDimension uint8

const (
	allocationRate allocationDimension = iota
	allocationBurst
	allocationPublishes
	allocationDuration
	allocationConcurrency
)

func allocationOrder(strategy Strategy) []allocationDimension {
	switch strategy {
	case StrategyRateFirst:
		return []allocationDimension{allocationRate, allocationRate, allocationBurst, allocationPublishes, allocationDuration, allocationConcurrency}
	case StrategyDurationFirst:
		return []allocationDimension{allocationDuration, allocationDuration, allocationRate, allocationPublishes, allocationBurst, allocationConcurrency}
	case StrategyBurstFirst:
		return []allocationDimension{allocationBurst, allocationBurst, allocationRate, allocationPublishes, allocationDuration, allocationConcurrency}
	default:
		return []allocationDimension{allocationRate, allocationDuration, allocationPublishes, allocationBurst, allocationConcurrency}
	}
}

func advancePolicy(policy PolicySpec, entitlement Entitlement, dimension allocationDimension) (PolicySpec, bool) {
	candidate := policy
	switch dimension {
	case allocationRate:
		next, ok := nextScaleClass(policy.Rate, entitlement.MaxRate)
		candidate.Rate = next
		return candidate, ok
	case allocationBurst:
		next, ok := nextScaleClass(policy.Burst, entitlement.MaxBurst)
		candidate.Burst = next
		return candidate, ok
	case allocationPublishes:
		next, ok := nextScaleClass(policy.Publishes, entitlement.MaxPublishes)
		candidate.Publishes = next
		return candidate, ok
	case allocationDuration:
		if policy.Duration >= entitlement.MaxDuration {
			return policy, false
		}
		candidate.Duration++
		return candidate, true
	case allocationConcurrency:
		next, ok := nextScaleClass(policy.Concurrency, entitlement.MaxConcurrency)
		candidate.Concurrency = next
		return candidate, ok
	default:
		return policy, false
	}
}

func nextScaleClass(current, ceiling ScaleClass) (ScaleClass, bool) {
	maxValue := ceiling.Value()
	if maxValue == 0 {
		return current, false
	}
	currentValue := current.Value()
	if currentValue >= maxValue {
		return current, false
	}
	nextValue := uint64(1)
	if currentValue > 0 {
		nextValue = currentValue << 1
	}
	if nextValue > maxValue {
		nextValue = maxValue
	}
	next, err := NewScaleClass(nextValue)
	if err != nil {
		return current, false
	}
	return next, true
}

func exceedsScale(value, ceiling ScaleClass) bool {
	return value.Value() > ceiling.Value()
}
