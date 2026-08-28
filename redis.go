package ratelimiter

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/redis/go-redis/v9"
)

const defaultKeyspace = "ratelimit"

// RedisConfig controls only key naming. Keeping it small is intentional: Redis
// connection policy belongs to go-redis or the caller's infrastructure layer.
type RedisConfig struct {
	Keyspace string
}

// RedisStore is the package's wrapper around go-redis. It owns bootstrap and
// creates profile-bound limiters, but it does not own or close the supplied
// client.
type RedisStore struct {
	client   redis.UniversalClient
	keyspace string
}

func NewRedisStore(client redis.UniversalClient, cfg RedisConfig) (*RedisStore, error) {
	if client == nil {
		return nil, errors.New("redis client is required")
	}
	keyspace := cfg.Keyspace
	if keyspace == "" {
		keyspace = defaultKeyspace
	}
	if strings.ContainsAny(keyspace, "{}") {
		return nil, errors.New("keyspace must not contain Redis hash-tag braces")
	}
	return &RedisStore{client: client, keyspace: strings.TrimSuffix(keyspace, ":")}, nil
}

// NewClientFromEnv preserves the existing deployment convention while accepting
// either host:port or a redis:// / rediss:// URL. REDISCLI_AUTH overrides a URL
// password when supplied.
func NewClientFromEnv() (*redis.Client, error) {
	addr := strings.TrimSpace(os.Getenv("REDIS_URI"))
	if addr == "" {
		return nil, errors.New("REDIS_URI is not set")
	}

	password := os.Getenv("REDISCLI_AUTH")
	if strings.Contains(addr, "://") {
		if _, err := url.ParseRequestURI(addr); err != nil {
			return nil, fmt.Errorf("parse REDIS_URI: %w", err)
		}
		opts, err := redis.ParseURL(addr)
		if err != nil {
			return nil, fmt.Errorf("parse REDIS_URI: %w", err)
		}
		if password != "" {
			opts.Password = password
		}
		return redis.NewClient(opts), nil
	}

	return redis.NewClient(&redis.Options{
		Addr:     addr,
		Password: password,
		DB:       0,
	}), nil
}

// Ping is a small deployment/bootstrap convenience.
func (s *RedisStore) Ping(ctx context.Context) error {
	if err := s.client.Ping(ctx).Err(); err != nil {
		return fmt.Errorf("ping redis: %w", err)
	}
	return nil
}

func (s *RedisStore) keys(bucket string) (windowKey, blockedKey string) {
	tag := "{" + bucket + "}"
	return s.keyspace + ":" + tag + ":window", s.keyspace + ":" + tag + ":blocked"
}
