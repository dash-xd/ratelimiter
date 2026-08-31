package ratelimiter

import (
	"errors"
	"strings"
)

// WorkerKeyspace builds the Redis prefix owned by one ACL-scoped worker.
// The returned shape is <scope>:<subsystem>[:<resource...>].
func WorkerKeyspace(scope, subsystem string, resource ...string) (string, error) {
	scope = strings.TrimSpace(scope)
	subsystem = strings.Trim(strings.TrimSpace(subsystem), ":")
	if scope == "" || subsystem == "" {
		return "", errors.New("scope and subsystem are required")
	}
	if strings.ContainsAny(scope, ":*?[]{} \t\r\n") {
		return "", errors.New("scope contains reserved Redis ACL pattern characters")
	}
	parts := []string{scope, subsystem}
	for _, part := range resource {
		part = strings.Trim(strings.TrimSpace(part), ":")
		if part == "" { continue }
		if strings.ContainsAny(part, "*?[]{}") { return "", errors.New("resource contains reserved Redis pattern characters") }
		parts = append(parts, part)
	}
	return strings.Join(parts, ":"), nil
}
