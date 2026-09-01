package ratelimiter

import (
	"context"
	"fmt"

	"github.com/dash-xd/ratelimiter/internal/profiledef"
	"github.com/dash-xd/ratelimiter/internal/redisfunc"
	"github.com/dash-xd/ratelimiter/internal/redisstore"
	"github.com/redis/go-redis/v9"
)

type RedisConfig struct {
	Keyspace string
}

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

func NewClientFromEnv() (*redis.Client, error) {
	return redisstore.NewClientFromEnv()
}

func (s *RedisStore) Ping(ctx context.Context) error {
	if s == nil || s.store == nil {
		return fmt.Errorf("redis store is not initialized")
	}
	return s.store.Ping(ctx)
}

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

		var source string
		var err error
		if profiledef.SupportsBurst(profile) {
			source, err = redisfunc.RenderBurst(libraryName, profiledef.FunctionName(profile))
		} else {
			registrations := []redisfunc.Registration{{
				FunctionName: profiledef.FunctionName(profile),
				WrapperName:  profiledef.LuaWrapperName(profile),
			}}
			if profiledef.SupportsPreflight(profile) {
				registrations = append(
					registrations,
					redisfunc.Registration{
						FunctionName: profiledef.TimerArmAbsoluteFunctionName(profile),
						WrapperName:  "timer_arm_absolute",
					},
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
			source, err = redisfunc.Render(libraryName, registrations...)
		}
		if err != nil {
			return fmt.Errorf("render %s: %w", libraryName, err)
		}
		if err := s.store.LoadFunction(ctx, libraryName, source); err != nil {
			return err
		}
	}
	return nil
}
