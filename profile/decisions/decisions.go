// Package decisions provides the profile that publishes final admission decisions.
package decisions

import (
	"github.com/dash-xd/ratelimiter"
	"github.com/dash-xd/ratelimiter/internal/profiledef"
)

// New returns a profile that publishes either allowed or blocked after the
// exact sliding-window decision.
func New(resolver ratelimiter.TargetResolver) ratelimiter.Profile {
	return profiledef.Decisions(resolver)
}
