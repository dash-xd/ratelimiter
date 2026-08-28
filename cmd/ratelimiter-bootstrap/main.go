package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/dash-xd/ratelimiter"
)

func main() {
	os.Exit(run())
}

func run() int {
	var profileList string
	var timeout time.Duration
	flag.StringVar(&profileList, "profiles", "minimal,preflight,decisions,lifecycle", "comma-separated Redis Function profiles to load")
	flag.DurationVar(&timeout, "timeout", 10*time.Second, "Redis bootstrap timeout")
	flag.Parse()

	profiles, err := parseProfiles(profileList)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}

	client, err := ratelimiter.NewClientFromEnv()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer client.Close()

	store, err := ratelimiter.NewRedisStore(client, ratelimiter.RedisConfig{})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	if err := store.Ping(ctx); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := store.Bootstrap(ctx, profiles...); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}

	fmt.Fprintf(os.Stdout, "loaded %d rate limiter profile(s)\n", len(profiles))
	return 0
}

func parseProfiles(raw string) ([]ratelimiter.Profile, error) {
	noop := ratelimiter.TargetResolverFunc(func(ratelimiter.Input, ratelimiter.Stage) []ratelimiter.Target {
		return nil
	})

	parts := strings.Split(raw, ",")
	profiles := make([]ratelimiter.Profile, 0, len(parts))
	seen := make(map[string]struct{}, len(parts))
	for _, part := range parts {
		name := strings.ToLower(strings.TrimSpace(part))
		if name == "" {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}

		switch name {
		case "minimal":
			profiles = append(profiles, ratelimiter.Minimal())
		case "preflight":
			profiles = append(profiles, ratelimiter.Preflight(noop))
		case "decisions":
			profiles = append(profiles, ratelimiter.Decisions(noop))
		case "lifecycle":
			profiles = append(profiles, ratelimiter.Lifecycle(noop))
		default:
			return nil, fmt.Errorf("unknown profile %q", name)
		}
	}
	if len(profiles) == 0 {
		return nil, fmt.Errorf("at least one profile is required")
	}
	return profiles, nil
}
