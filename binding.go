package ratelimiter

import (
	"fmt"
	"strconv"
)

// PolicyBinding is the provider-neutral machine reference stored by a Fatline
// binding. PolicyCode is decimal text so JSON consumers do not lose uint64
// precision. Profile identifies the execution shape, not a business tier.
type PolicyBinding struct {
	Profile    string `json:"profile"`
	PolicyCode string `json:"policy_code"`
}

func NewPolicyBinding(profile Profile, code PolicyCode, entitlement Entitlement) (PolicyBinding, error) {
	policy, err := DecodePolicy(code)
	if err != nil {
		return PolicyBinding{}, err
	}
	if err := ValidatePolicy(profile, policy, entitlement); err != nil {
		return PolicyBinding{}, err
	}
	return PolicyBinding{
		Profile:    ProfileID(profile),
		PolicyCode: strconv.FormatUint(uint64(code), 10),
	}, nil
}

func (b PolicyBinding) ParseCode() (PolicyCode, error) {
	if b.PolicyCode == "" {
		return 0, fmt.Errorf("policy_code is required")
	}
	raw, err := strconv.ParseUint(b.PolicyCode, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parse policy_code: %w", err)
	}
	code := PolicyCode(raw)
	if _, err := DecodePolicy(code); err != nil {
		return 0, err
	}
	return code, nil
}

func (b PolicyBinding) Validate(profile Profile, entitlement Entitlement) error {
	if b.Profile != ProfileID(profile) {
		return fmt.Errorf("binding profile %q does not match selected profile %q", b.Profile, ProfileID(profile))
	}
	code, err := b.ParseCode()
	if err != nil {
		return err
	}
	policy, err := DecodePolicy(code)
	if err != nil {
		return err
	}
	return ValidatePolicy(profile, policy, entitlement)
}
