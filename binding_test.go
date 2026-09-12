package ratelimiter_test

import (
	"encoding/json"
	"testing"

	ratelimiter "github.com/dash-xd/ratelimiter"
	"github.com/dash-xd/ratelimiter/profile/lifecycle"
)

func TestPolicyBindingUsesExactStringCode(t *testing.T) {
	policy, err := ratelimiter.NamedLifecyclePolicy(ratelimiter.LifecycleSmoke10M)
	if err != nil {
		t.Fatal(err)
	}
	code, err := ratelimiter.EncodePolicy(policy)
	if err != nil {
		t.Fatal(err)
	}
	entitlement := ratelimiter.EntitlementFor(policy)
	profile := lifecycle.New(ratelimiter.TargetResolverFunc(func(ratelimiter.Input, ratelimiter.Stage) []ratelimiter.Target { return nil }))
	binding, err := ratelimiter.NewPolicyBinding(profile, code, entitlement)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(binding)
	if err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		Profile string `json:"profile"`
		Code    string `json:"policy_code"`
	}
	if err := json.Unmarshal(payload, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Code == "" || decoded.Profile != "lifecycle" {
		t.Fatalf("unexpected binding %#v", decoded)
	}
	if err := binding.Validate(profile, entitlement); err != nil {
		t.Fatal(err)
	}
}
