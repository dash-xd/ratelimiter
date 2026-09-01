package ratelimiter

import (
	"errors"
	"strings"
	"unicode"
)

var errInvalidKeyspaceSegment = errors.New("keyspace segment contains reserved Redis delimiter, glob, escape, hash-tag, or whitespace characters")

// WorkerKeyspace builds a Redis prefix owned by one independently ACL-scoped
// worker or subsystem. Every segment is validated as a literal namespace
// component so the returned prefix can safely be embedded in Redis ACL key
// patterns without broadening authority through glob characters, escapes,
// hash tags, delimiters, or whitespace.
//
// The returned shape is:
//
//	<scope>:<subsystem>[:<resource>...]
func WorkerKeyspace(scope, subsystem string, resource ...string) (string, error) {
	parts := make([]string, 0, 2+len(resource))
	for _, part := range append([]string{scope, subsystem}, resource...) {
		if part == "" {
			return "", errors.New("keyspace segments must be non-empty")
		}
		if strings.ContainsAny(part, ":*?[]{}\\") || strings.IndexFunc(part, unicode.IsSpace) >= 0 {
			return "", errInvalidKeyspaceSegment
		}
		parts = append(parts, part)
	}
	return strings.Join(parts, ":"), nil
}
