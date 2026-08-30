package redisstore

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/redis/go-redis/v9"
)

const (
	DefaultKeyspace       = "ratelimit"
	lifecycleTimerMember = "shutdown:timer"
)

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

// ArmLifecycleTimerAbsolute reconstructs the Redis-owned timer from an
// externally durable absolute deadline. With reset=false, the first timer wins;
// a later reconstruction cannot extend an already-armed lifecycle. If a prior
// process died between ZADD and HSET, a later reconstruction repairs the missing
// payload without changing the deadline.
func (s *Store) ArmLifecycleTimerAbsolute(
	ctx context.Context,
	timerKey string,
	payloadKey string,
	rawContext string,
	deadlineUnixMS int64,
	reset bool,
) (bool, error) {
	if deadlineUnixMS <= 0 {
		return false, errors.New("lifecycle deadline must be positive")
	}
	if rawContext == "" {
		return false, errors.New("lifecycle context is required")
	}

	if reset {
		if err := s.client.Do(
			ctx,
			"ZADD",
			timerKey,
			deadlineUnixMS,
			lifecycleTimerMember,
		).Err(); err != nil {
			return false, fmt.Errorf("reset lifecycle timer: %w", err)
		}
		if err := s.client.HSet(
			ctx,
			payloadKey,
			lifecycleTimerMember,
			rawContext,
		).Err(); err != nil {
			return false, fmt.Errorf("reset lifecycle payload: %w", err)
		}
		return true, nil
	}

	added, err := s.client.Do(
		ctx,
		"ZADD",
		timerKey,
		"NX",
		deadlineUnixMS,
		lifecycleTimerMember,
	).Int()
	if err != nil {
		return false, fmt.Errorf("arm lifecycle timer: %w", err)
	}
	if added == 1 {
		if err := s.client.HSet(
			ctx,
			payloadKey,
			lifecycleTimerMember,
			rawContext,
		).Err(); err != nil {
			return false, fmt.Errorf("save lifecycle payload: %w", err)
		}
		return true, nil
	}

	exists, err := s.client.HExists(ctx, payloadKey, lifecycleTimerMember).Result()
	if err != nil {
		return false, fmt.Errorf("inspect lifecycle payload: %w", err)
	}
	if !exists {
		if err := s.client.HSet(
			ctx,
			payloadKey,
			lifecycleTimerMember,
			rawContext,
		).Err(); err != nil {
			return false, fmt.Errorf("repair lifecycle payload: %w", err)
		}
	}
	return false, nil
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
