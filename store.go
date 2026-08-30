package ratelimiter

import (
	"context"
	"fmt"

	"github.com/dash-xd/ratelimiter/internal/profiledef"
	"github.com/dash-xd/ratelimiter/internal/redisfunc"
	"github.com/dash-xd/ratelimiter/internal/redisstore"
	"github.com/redis/go-redis/v9"
)

// RedisConfig controls package-owned Redis key naming. Connection and transport
// policy remain the caller's responsibility.
type RedisConfig struct {
	Keyspace string
}

// RedisStore owns rate-limiter bootstrap and invocation state. It does not own
// or close the supplied Redis client.
type RedisStore struct {
	store *redisstore.Store
}

func NewRedisStore(client redis.UniversalClient, cfg RedisConfig) (*RedisStore, error) {
	store, err := redisstore.New(client, cfg.Keyspace)
	if err != nil {
		return nil, err
	}
	return &RedisStore{store: store}, nil
}

// NewClientFromEnv preserves the existing deployment convention while accepting
// either host:port or a redis:// / rediss:// URL. REDISCLI_AUTH overrides a URL
// password when supplied.
func NewClientFromEnv() (*redis.Client, error) {
	return redisstore.NewClientFromEnv()
}

func (s *RedisStore) Ping(ctx context.Context) error {
	if s == nil || s.store == nil {
		return fmt.Errorf("redis store is not initialized")
	}
	return s.store.Ping(ctx)
}

// Bootstrap loads or replaces only the selected profile libraries. Profiles use
// separate libraries, so bootstrapping one service cannot unregister another
// profile used by a different service sharing the same Redis instance.
func (s *RedisStore) Bootstrap(ctx context.Context, profiles ...Profile) error {
	if s == nil || s.store == nil {
		return fmt.Errorf("redis store is not initialized")
	}
	if len(profiles) == 0 {
		return fmt.Errorf("at least one profile is required")
	}

	seen := make(map[string]struct{}, len(profiles))
	for _, profile := range profiles {
		if err := profiledef.Validate(profile); err != nil {
			return err
		}
		libraryName := profiledef.LibraryName(profile)
		if _, ok := seen[libraryName]; ok {
			continue
		}
		seen[libraryName] = struct{}{}

		registrations := []redisfunc.Registration{{
			FunctionName: profiledef.FunctionName(profile),
			WrapperName:  profiledef.LuaWrapperName(profile),
		}}
		if profiledef.SupportsPreflight(profile) {
			registrations = append(
				registrations,
				redisfunc.Registration{
					FunctionName: profiledef.TimerTickFunctionName(profile),
					WrapperName:  "timer_tick",
				},
				redisfunc.Registration{
					FunctionName: profiledef.TimerCancelFunctionName(profile),
					WrapperName:  "timer_cancel",
				},
			)
		}

		source, err := redisfunc.Render(libraryName, registrations...)
		if err != nil {
			return fmt.Errorf("render %s: %w", libraryName, err)
		}
		if err := s.store.LoadFunction(ctx, libraryName, source); err != nil {
			return err
		}
	}
	return nil
}
