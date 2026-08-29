package auth

import (
	"slices"
	"testing"
)

func TestRedisACLProviderScopesTenantResources(t *testing.T) {
	provider, err := NewRedisACLProvider(RedisACLConfig{
		Admin:           "admin",
		UsernamePrefix: "logma-tenant-",
		KeyPrefix:      "logma:tenant:",
		ChannelPrefix:  "tenant:",
		FunctionPrefix: "logma_",
	})
	if err != nil {
		t.Fatal(err)
	}

	scope, err := provider.Scope("acme", "")
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

func TestRedisACLProviderDoesNotGrantAdministration(t *testing.T) {
	provider, err := NewRedisACLProvider(RedisACLConfig{Admin: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	policy, err := provider.Policy("tenant-functions")
	if err != nil {
		t.Fatal(err)
	}
	rules, err := provider.Rules(UserSpec{
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
