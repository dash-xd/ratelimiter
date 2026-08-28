package ratelimiter

import (
	"context"
	_ "embed"
	"fmt"
	"strings"
)

//go:embed internal/lua/rate_limiters.lua
var luaTemplate string

const (
	libraryNameMarker  = "__RATELIMITER_LIBRARY_NAME__"
	registrationMarker = "-- __RATELIMITER_REGISTRATION__"
)

// Bootstrap loads or replaces only the selected profile libraries. Profiles use
// separate libraries, so bootstrapping one service cannot unregister another
// profile used by a different service sharing the same Redis instance.
func (s *RedisStore) Bootstrap(ctx context.Context, profiles ...Profile) error {
	if len(profiles) == 0 {
		return fmt.Errorf("at least one profile is required")
	}

	seen := make(map[profileKind]struct{}, len(profiles))
	for _, profile := range profiles {
		if err := profile.validate(); err != nil {
			return err
		}
		if _, ok := seen[profile.kind]; ok {
			continue
		}
		seen[profile.kind] = struct{}{}

		source := renderLibrary(profile)
		if err := s.client.Do(ctx, "FUNCTION", "LOAD", "REPLACE", source).Err(); err != nil {
			return fmt.Errorf("load %s: %w", profile.libraryName(), err)
		}
	}
	return nil
}

func renderLibrary(profile Profile) string {
	source := strings.Replace(luaTemplate, libraryNameMarker, profile.libraryName(), 1)
	return strings.Replace(source, registrationMarker, profile.registration(), 1)
}
