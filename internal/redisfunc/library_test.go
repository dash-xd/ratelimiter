package redisfunc

import (
	"strings"
	"testing"
)

func TestRenderRegistersRequestedFunction(t *testing.T) {
	source, err := Render("dashxd_test_v1", "dashxd_test_fn_v1", "rate_limit_minimal")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(source, "#!lua name=dashxd_test_v1") {
		t.Fatal("rendered source is missing library name")
	}
	if !strings.Contains(source, "redis.register_function('dashxd_test_fn_v1', rate_limit_minimal)") {
		t.Fatal("rendered source is missing function registration")
	}
	if strings.Contains(source, libraryNameMarker) || strings.Contains(source, registrationMarker) {
		t.Fatal("rendered source still contains template markers")
	}
}

func TestRenderRejectsInvalidIdentifiers(t *testing.T) {
	if _, err := Render("bad:name", "fn", "wrapper"); err == nil {
		t.Fatal("expected invalid library identifier to be rejected")
	}
}
