// Package minimal provides the rate limiter profile with no Pub/Sub callbacks.
package minimal

import (
	"github.com/dash-xd/ratelimiter"
	"github.com/dash-xd/ratelimiter/internal/profiledef"
)

// New returns the minimal exact sliding-window profile.
func New() ratelimiter.Profile {
	return profiledef.Minimal()
}
