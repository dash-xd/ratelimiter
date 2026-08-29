// Package preflight provides the profile that publishes before admission.
package preflight

import (
	"github.com/dash-xd/ratelimiter"
	"github.com/dash-xd/ratelimiter/internal/profiledef"
)

// New returns a profile that publishes the preflight stage and then performs the
// exact sliding-window decision.
func New(resolver ratelimiter.TargetResolver) ratelimiter.Profile {
	return profiledef.Preflight(resolver)
}
