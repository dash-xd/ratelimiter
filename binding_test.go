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
	binding, err := ratelimiter.NewPolicyBinding(lifecycle.Profile(nil), code, entitlement)
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
	if err := binding.Validate(lifecycle.Profile(nil), entitlement); err != nil {
		t.Fatal(err)
	}
}
