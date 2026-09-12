package redisacl

import (
	"slices"
	"testing"
)

func TestCompilerScopesTenantResources(t *testing.T) {
	compiler, err := New(Config{
		Admin:           "admin",
		UsernamePrefix: "logma-tenant-",
		KeyPrefix:      "logma:tenant:",
		ChannelPrefix:  "tenant:",
		FunctionPrefix: "logma_",
	})
	if err != nil {
		t.Fatal(err)
	}
	scope, err := compiler.Scope("acme", "")
	if err != nil {
		t.Fatal(err)
	}
	if scope.Username != "logma-tenant-acme" || scope.KeyPrefix != "logma:tenant:acme:" || scope.ChannelPrefix != "tenant:acme:" || scope.FunctionPrefix != "logma_acme__" {
		t.Fatalf("unexpected scope: %#v", scope)
	}
}

func TestCompilerDoesNotGrantAdministration(t *testing.T) {
	compiler, err := New(Config{Admin: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	policy, err := compiler.Policy("tenant-functions")
	if err != nil {
		t.Fatal(err)
	}
	rules, err := compiler.Rules(UserSpec{Tenant: "acme", Password: "secret", Policy: policy, Reset: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"+fcall", "+fcall_ro", "+publish", "+subscribe", "+time", "+zremrangebyscore"} {
		if !slices.Contains(rules, want) {
			t.Fatalf("missing %q in %#v", want, rules)
		}
	}
	for _, forbidden := range []string{"+eval", "+evalsha", "+function", "+function|load", "+acl", "+keys", "+scan", "+@all"} {
		if slices.Contains(rules, forbidden) {
			t.Fatalf("unexpected grant %q", forbidden)
		}
	}
}

func TestPublisherAndSubscriberStayDistinct(t *testing.T) {
	compiler, err := New(Config{Admin: "admin", ChannelPrefix: "tenant:"})
	if err != nil {
		t.Fatal(err)
	}
	publisher, _ := compiler.Policy("publisher")
	subscriber, _ := compiler.Policy("subscriber")
	pubRules, err := compiler.Rules(UserSpec{Tenant: "acme", Password: "secret", Policy: publisher, Reset: true})
	if err != nil {
		t.Fatal(err)
	}
	subRules, err := compiler.Rules(UserSpec{Tenant: "acme", Password: "secret", Policy: subscriber, Reset: true})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(pubRules, "+publish") || slices.Contains(pubRules, "+subscribe") {
		t.Fatalf("publisher rules are not narrow: %#v", pubRules)
	}
	if slices.Contains(subRules, "+publish") || !slices.Contains(subRules, "+subscribe") {
		t.Fatalf("subscriber rules are not narrow: %#v", subRules)
	}
}
