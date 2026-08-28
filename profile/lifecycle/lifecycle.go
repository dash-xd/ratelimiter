// Package lifecycle provides the fully observable rate limiter profile.
package lifecycle

import (
	"github.com/dash-xd/ratelimiter"
	"github.com/dash-xd/ratelimiter/internal/profiledef"
)

// New returns a profile that publishes preflight and the final allowed/blocked
// stage around the exact sliding-window decision.
func New(resolver ratelimiter.TargetResolver) ratelimiter.Profile {
	return profiledef.Lifecycle(resolver)
}
