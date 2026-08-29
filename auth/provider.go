// Package auth defines reusable authorization providers for Redis-backed services.
//
// The package is intentionally transport-agnostic. A consumer such as Logma may
// authenticate HTTP requests however it chooses, then use a Provider to compile
// Redis usernames, key/channel/function namespaces, and ACL rules.
package auth

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

type Capability uint32

const (
	CapabilityData Capability = 1 << iota
	CapabilityPublish
	CapabilitySubscribe
	CapabilityFunctions
)

type Policy struct {
	Name         string
	Capabilities Capability
}

func (p Policy) Has(cap Capability) bool {
	return p.Capabilities&cap == cap
}

type Scope struct {
	Tenant         string
	Username       string
	KeyPrefix      string
	ChannelPrefix  string
	FunctionPrefix string
}

type UserSpec struct {
	Tenant   string
	Username string
	Password string
	Policy   Policy
	Reset    bool
}

type Provider interface {
	Name() string
	AdminUser() string
	Scope(tenant, username string) (Scope, error)
	Rules(UserSpec) ([]string, error)
	Policy(name string) (Policy, error)
}

type RedisACLConfig struct {
	Name           string
	Admin           string
	UsernamePrefix string
	KeyPrefix      string
	ChannelPrefix  string
	FunctionPrefix string
}

type RedisACLProvider struct {
	config RedisACLConfig
}

var identifierRE = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

func ValidateIdentifier(value string) error {
	if value == "" || len(value) > 64 || !identifierRE.MatchString(value) {
		return errors.New("identifier must be 1-64 ASCII letters, digits, '.', '_' or '-'")
	}
	return nil
}

func NewRedisACLProvider(config RedisACLConfig) (*RedisACLProvider, error) {
	if strings.TrimSpace(config.Name) == "" {
		config.Name = "redis-acl"
	}
	if strings.TrimSpace(config.Admin) == "" {
		return nil, errors.New("admin user is required")
	}
	if config.UsernamePrefix == "" {
		config.UsernamePrefix = "tenant-"
	}
	if config.KeyPrefix == "" {
		config.KeyPrefix = "tenant:"
	}
	if config.ChannelPrefix == "" {
		config.ChannelPrefix = "tenant:"
	}
	if config.FunctionPrefix == "" {
		config.FunctionPrefix = "tenant_"
	}
	return &RedisACLProvider{config: config}, nil
}

func (p *RedisACLProvider) Name() string {
	if p == nil {
		return ""
	}
	return p.config.Name
}

func (p *RedisACLProvider) AdminUser() string {
	if p == nil {
		return ""
	}
	return p.config.Admin
}

func (p *RedisACLProvider) Scope(tenant, username string) (Scope, error) {
	if p == nil {
		return Scope{}, errors.New("auth provider is nil")
	}
	tenant = strings.TrimSpace(tenant)
	if err := ValidateIdentifier(tenant); err != nil {
		return Scope{}, fmt.Errorf("tenant: %w", err)
	}
	username = strings.TrimSpace(username)
	if username == "" {
		username = p.config.UsernamePrefix + tenant
	}
	if err := ValidateIdentifier(username); err != nil {
		return Scope{}, fmt.Errorf("username: %w", err)
	}
	functionTenant := strings.ReplaceAll(tenant, ".", "_")
	return Scope{
		Tenant:         tenant,
		Username:       username,
		KeyPrefix:      p.config.KeyPrefix + tenant + ":",
		ChannelPrefix:  p.config.ChannelPrefix + tenant + ":",
		FunctionPrefix: p.config.FunctionPrefix + functionTenant + "__",
	}, nil
}

func (p *RedisACLProvider) Policy(name string) (Policy, error) {
	switch strings.TrimSpace(name) {
	case "", "tenant":
		return Policy{
			Name: "tenant",
			Capabilities: CapabilityData |
				CapabilityPublish |
				CapabilitySubscribe,
		}, nil
	case "tenant-functions":
		return Policy{
			Name: "tenant-functions",
			Capabilities: CapabilityData |
				CapabilityPublish |
				CapabilitySubscribe |
				CapabilityFunctions,
		}, nil
	case "publisher":
		return Policy{
			Name:         "publisher",
			Capabilities: CapabilityPublish,
		}, nil
	case "subscriber":
		return Policy{
			Name:         "subscriber",
			Capabilities: CapabilitySubscribe,
		}, nil
	default:
		return Policy{}, fmt.Errorf("unknown auth policy %q", name)
	}
}

// DataCommands is deliberately explicit. Broad +@read/+@write grants are not
// used because Redis command categories can grow between major releases and
// database-wide commands are not constrained by key patterns.
var DataCommands = []string{
	"+get", "+set", "+setnx", "+getset", "+mget", "+mset", "+msetnx",
	"+del", "+unlink", "+exists", "+expire", "+expireat", "+pexpire",
	"+pexpireat", "+persist", "+ttl", "+pttl", "+type", "+touch",
	"+getdel", "+getex", "+append", "+strlen", "+getrange", "+setrange",
	"+incr", "+incrby", "+incrbyfloat", "+decr", "+decrby",
	"+hget", "+hset", "+hdel", "+hexists", "+hgetall", "+hincrby",
	"+hincrbyfloat", "+hkeys", "+hlen", "+hmget", "+hmset", "+hscan",
	"+sadd", "+srem", "+smembers", "+sismember", "+smismember", "+scard",
	"+spop", "+srandmember", "+sscan",
	"+zadd", "+zrem", "+zrange", "+zrangebyscore", "+zrevrange", "+zscore",
	"+zmscore", "+zcard", "+zcount", "+zincrby", "+zscan",
	"+lpush", "+rpush", "+lpop", "+rpop", "+llen", "+lrange", "+lset",
	"+ltrim", "+lindex", "+lrem",
	"+xadd", "+xack", "+xdel", "+xlen", "+xrange", "+xrevrange", "+xtrim",
	"+xread", "+xreadgroup", "+xgroup",
	"+multi", "+exec", "+discard", "+watch", "+unwatch",
}

func (p *RedisACLProvider) Rules(spec UserSpec) ([]string, error) {
	if p == nil {
		return nil, errors.New("auth provider is nil")
	}
	scope, err := p.Scope(spec.Tenant, spec.Username)
	if err != nil {
		return nil, err
	}
	if spec.Password == "" {
		return nil, errors.New("password is required")
	}
	if strings.TrimSpace(spec.Policy.Name) == "" {
		spec.Policy, err = p.Policy("tenant")
		if err != nil {
			return nil, err
		}
	}

	rules := make([]string, 0, 10+len(DataCommands))
	if spec.Reset {
		rules = append(rules, "reset")
	} else {
		rules = append(rules, "-@all", "resetkeys", "resetchannels", "clearselectors", "resetpass")
	}
	rules = append(rules, "on", ">"+spec.Password, "-@all", "resetkeys", "resetchannels", "+ping")

	if spec.Policy.Has(CapabilityData) {
		rules = append(rules, "%RW~"+scope.KeyPrefix+"*")
		rules = append(rules, DataCommands...)
	}
	if spec.Policy.Has(CapabilityPublish) {
		rules = append(rules, "&"+scope.ChannelPrefix+"*", "+publish")
	}
	if spec.Policy.Has(CapabilitySubscribe) {
		if !spec.Policy.Has(CapabilityPublish) {
			rules = append(rules, "&"+scope.ChannelPrefix+"*")
		}
		rules = append(rules, "+subscribe", "+unsubscribe", "+psubscribe", "+punsubscribe")
	}
	if spec.Policy.Has(CapabilityFunctions) {
		rules = append(rules, "+fcall", "+fcall_ro")
	}

	return rules, nil
}

func FunctionName(scope Scope, name string) (string, error) {
	if err := ValidateIdentifier(name); err != nil {
		return "", fmt.Errorf("function name: %w", err)
	}
	if scope.FunctionPrefix == "" {
		return "", errors.New("function prefix is empty")
	}
	return scope.FunctionPrefix + name, nil
}

func LibraryName(scope Scope, name string) (string, error) {
	fn, err := FunctionName(scope, name)
	if err != nil {
		return "", err
	}
	return "lib_" + fn, nil
}
