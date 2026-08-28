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

func Render(libraryName, functionName, wrapperName string) (string, error) {
	for name, value := range map[string]string{
		"library name":  libraryName,
		"function name": functionName,
		"wrapper name":  wrapperName,
	} {
		if !isIdentifier(value) {
			return "", fmt.Errorf("invalid %s %q", name, value)
		}
	}

	if !strings.Contains(template, libraryNameMarker) || !strings.Contains(template, registrationMarker) {
		return "", fmt.Errorf("rate limiter Lua template is missing render markers")
	}

	source := strings.Replace(template, libraryNameMarker, libraryName, 1)
	registration := fmt.Sprintf("redis.register_function('%s', %s)", functionName, wrapperName)
	return strings.Replace(source, registrationMarker, registration, 1), nil
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
