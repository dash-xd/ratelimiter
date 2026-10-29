package redisacl

import (
	"slices"
	"testing"
)

func TestCompilerScopesTenantResources(t *testing.T) {
	compiler, err := New(Config{
		Admin:          "admin",
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
	if scope.Username != "logma-tenant-acme" {
		t.Fatalf("username = %q", scope.Username)
	}
	if scope.KeyPrefix != "logma:tenant:acme:" {
		t.Fatalf("key prefix = %q", scope.KeyPrefix)
	}
	if scope.ChannelPrefix != "tenant:acme:" {
		t.Fatalf("channel prefix = %q", scope.ChannelPrefix)
	}
	if scope.FunctionPrefix != "logma_acme__" {
		t.Fatalf("function prefix = %q", scope.FunctionPrefix)
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
	rules, err := compiler.Rules(UserSpec{
		Tenant:   "acme",
		Password: "secret",
		Policy:   policy,
		Reset:    true,
	})
	if err != nil {
		t.Fatal(err)
	}

	for _, want := range []string{
		"+fcall",
		"+fcall_ro",
		"+publish",
		"+subscribe",
		"+time",
		"+zremrangebyscore",
	} {
		if !slices.Contains(rules, want) {
			t.Fatalf("missing %q in %#v", want, rules)
		}
	}

	for _, forbidden := range []string{
		"+eval",
		"+evalsha",
		"+function",
		"+function|load",
		"+acl",
		"+keys",
		"+scan",
		"+@all",
	} {
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
	publisher, err := compiler.Policy("publisher")
	if err != nil {
		t.Fatal(err)
	}
	subscriber, err := compiler.Policy("subscriber")
	if err != nil {
		t.Fatal(err)
	}
	pubRules, err := compiler.Rules(UserSpec{
		Tenant:   "acme",
		Password: "secret",
		Policy:   publisher,
		Reset:    true,
	})
	if err != nil {
		t.Fatal(err)
	}
	subRules, err := compiler.Rules(UserSpec{
		Tenant:   "acme",
		Password: "secret",
		Policy:   subscriber,
		Reset:    true,
	})
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

func TestCompilerCombinesProviderRequirementsWithinTenantScope(t *testing.T) {
	compiler, err := New(Config{Admin: "admin", UsernamePrefix: "fatline-tenant-"})
	if err != nil {
		t.Fatal(err)
	}
	rules, err := compiler.Rules(UserSpec{
		Tenant:        "acme",
		Password:      "secret",
		ResourceScope: "fatline-prod-acme",
		Requirements: &ProviderRequirements{
			KeyPatterns: []string{
				"~fatline-prod-acme:logma:pubsub:*",
				"~fatline-prod-acme:skymill:stream:github.webhooks",
			},
			ChannelPatterns: []string{"&fatline-prod-acme:logma:events:*"},
			Commands:        []string{"hget", "xadd", "select"},
		},
		Reset: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"~fatline-prod-acme:logma:pubsub:*",
		"~fatline-prod-acme:skymill:stream:github.webhooks",
		"&fatline-prod-acme:logma:events:*",
		"+hget", "+xadd", "+select",
	} {
		if !slices.Contains(rules, want) {
			t.Fatalf("missing %q in %#v", want, rules)
		}
	}
	for _, forbidden := range []string{
		"~fatline-prod:*", "~fatline-prod-other:logma:pubsub:*",
		"+acl", "+config", "+function", "+keys", "+scan", "+@all",
	} {
		if slices.Contains(rules, forbidden) {
			t.Fatalf("unexpected grant %q in %#v", forbidden, rules)
		}
	}
}

func TestCompilerRejectsProviderRequirementsOutsideTenantScope(t *testing.T) {
	compiler, err := New(Config{Admin: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	for name, requirements := range map[string]*ProviderRequirements{
		"foreign tenant key": {
			KeyPatterns: []string{"~fatline-prod-other:logma:pubsub:*"},
			Commands:    []string{"hget"},
		},
		"foreign tenant channel": {
			ChannelPatterns: []string{"&fatline-prod-other:events:*"},
			Commands:        []string{"subscribe"},
		},
		"administration": {
			KeyPatterns: []string{"~fatline-prod-acme:logma:pubsub:*"},
			Commands:    []string{"acl|setuser"},
		},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := compiler.Rules(UserSpec{
				Tenant: "acme", Password: "secret", ResourceScope: "fatline-prod-acme",
				Requirements: requirements,
			})
			if err == nil {
				t.Fatal("expected provider authority to be rejected")
			}
		})
	}
}

func TestCompilerRejectsResourceScopeForDifferentTenant(t *testing.T) {
	compiler, err := New(Config{Admin: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = compiler.Rules(UserSpec{
		Tenant:        "other",
		Password:      "secret",
		ResourceScope: "fatline-prod-acme",
		Requirements: &ProviderRequirements{
			KeyPatterns: []string{"~fatline-prod-acme:logma:pubsub:*"},
			Commands:    []string{"hget"},
		},
		Reset: true,
	})
	if err == nil {
		t.Fatal("expected a resource scope bound to another tenant to be rejected")
	}
}
