package redisfunc

import (
	_ "embed"
	"fmt"
	"strings"
)

//go:embed burst.lua
var burstTemplate string

const (
	burstLibraryMarker  = "__RATELIMITER_BURST_LIBRARY__"
	burstFunctionMarker = "__RATELIMITER_BURST_FUNCTION__"
)

func RenderBurst(libraryName, functionName string) (string, error) {
	if !isIdentifier(libraryName) {
		return "", fmt.Errorf("invalid burst library name %q", libraryName)
	}
	if !isIdentifier(functionName) {
		return "", fmt.Errorf("invalid burst function name %q", functionName)
	}
	if !strings.Contains(burstTemplate, burstLibraryMarker) || !strings.Contains(burstTemplate, burstFunctionMarker) {
		return "", fmt.Errorf("burst Lua template is missing render markers")
	}
	source := strings.Replace(burstTemplate, burstLibraryMarker, libraryName, 1)
	return strings.Replace(source, burstFunctionMarker, functionName, 1), nil
}
