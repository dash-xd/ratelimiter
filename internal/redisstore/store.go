package redisstore

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/redis/go-redis/v9"
)

const DefaultKeyspace = "ratelimit"

type Store struct {
	client   redis.UniversalClient
	keyspace string
}

func New(client redis.UniversalClient, keyspace string) (*Store, error) {
	if client == nil {
		return nil, errors.New("redis client is required")
	}
	if keyspace == "" {
		keyspace = DefaultKeyspace
	}
	keyspace = strings.TrimRight(keyspace, ":")
	if keyspace == "" {
		return nil, errors.New("keyspace must not be empty")
	}
	if strings.ContainsAny(keyspace, "{}") {
		return nil, errors.New("keyspace must not contain Redis hash-tag braces")
	}
	return &Store{client: client, keyspace: keyspace}, nil
}

func NewClientFromEnv() (*redis.Client, error) {
	addr := strings.TrimSpace(os.Getenv("REDIS_URI"))
	if addr == "" {
		return nil, errors.New("REDIS_URI is not set")
	}

	password := os.Getenv("REDISCLI_AUTH")
	if strings.Contains(addr, "://") {
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

func (s *Store) Ping(ctx context.Context) error {
	if err := s.client.Ping(ctx).Err(); err != nil {
		return fmt.Errorf("ping redis: %w", err)
	}
	return nil
}

func (s *Store) Keys(bucket string) (windowKey, blockedKey string) {
	tag := "{" + bucket + "}"
	return s.keyspace + ":" + tag + ":window", s.keyspace + ":" + tag + ":blocked"
}

func (s *Store) LifecycleKeys(bucket string) (timerKey, payloadKey string) {
	tag := "{" + bucket + "}"
	return s.keyspace + ":" + tag + ":lifecycle:timers",
		s.keyspace + ":" + tag + ":lifecycle:payloads"
}

func (s *Store) LoadFunction(ctx context.Context, libraryName, source string) error {
	if err := s.client.Do(ctx, "FUNCTION", "LOAD", "REPLACE", source).Err(); err != nil {
		return fmt.Errorf("load %s: %w", libraryName, err)
	}
	return nil
}

func (s *Store) Call(ctx context.Context, functionName string, keys []string, args ...any) ([]any, error) {
	command := make([]any, 0, 3+len(keys)+len(args))
	command = append(command, "FCALL", functionName, len(keys))
	for _, key := range keys {
		command = append(command, key)
	}
	command = append(command, args...)

	values, err := s.client.Do(ctx, command...).Slice()
	if err != nil {
		return nil, fmt.Errorf("fcall %s: %w", functionName, err)
	}
	return values, nil
}
