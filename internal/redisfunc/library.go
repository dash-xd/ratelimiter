package redisfunc

import (
	_ "embed"
	"fmt"
	"strings"
)

//go:embed rate_limiters.lua
var template string

const (
	libraryNameMarker  = "__RATELIMITER_LIBRARY_NAME__"
	registrationMarker = "-- __RATELIMITER_REGISTRATION__"
)

type Registration struct {
	FunctionName string
	WrapperName  string
}

func Render(libraryName string, registrations ...Registration) (string, error) {
	if !isIdentifier(libraryName) {
		return "", fmt.Errorf("invalid library name %q", libraryName)
	}
	if len(registrations) == 0 {
		return "", fmt.Errorf("at least one function registration is required")
	}

	lines := make([]string, 0, len(registrations))
	for _, registration := range registrations {
		for name, value := range map[string]string{
			"function name": registration.FunctionName,
			"wrapper name":  registration.WrapperName,
		} {
			if !isIdentifier(value) {
				return "", fmt.Errorf("invalid %s %q", name, value)
			}
		}
		lines = append(lines, fmt.Sprintf(
			"redis.register_function('%s', %s)",
			registration.FunctionName,
			registration.WrapperName,
		))
	}

	if !strings.Contains(template, libraryNameMarker) || !strings.Contains(template, registrationMarker) {
		return "", fmt.Errorf("rate limiter Lua template is missing render markers")
	}

	source := strings.Replace(template, libraryNameMarker, libraryName, 1)
	return strings.Replace(source, registrationMarker, strings.Join(lines, "
"), 1), nil
}

func isIdentifier(value string) bool {
	if value == "" {
		return false
	}
	for i := 0; i < len(value); i++ {
		ch := value[i]
		if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || ch == '_' || (i > 0 && ch >= '0' && ch <= '9') {
			continue
		}
		return false
	}
	return true
}
