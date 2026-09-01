// Package burst provides the atomic Redis token-bucket profile.
package burst

import (
	"github.com/dash-xd/ratelimiter"
	"github.com/dash-xd/ratelimiter/internal/profiledef"
)

// New returns the sustained-rate plus burst-capacity token-bucket profile.
func New() ratelimiter.Profile {
	return profiledef.Burst()
}
