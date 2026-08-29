package redisfunc

import (
	"strings"
	"testing"
)

func TestRenderRegistersRequestedFunctions(t *testing.T) {
	source, err := Render(
		"dashxd_test_v1",
		Registration{FunctionName: "dashxd_test_fn_v1", WrapperName: "rate_limit_minimal"},
		Registration{FunctionName: "dashxd_test_tick_v1", WrapperName: "timer_tick"},
	)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(source, "#!lua name=dashxd_test_v1") {
		t.Fatal("rendered source is missing library name")
	}
	if !strings.Contains(source, "redis.register_function('dashxd_test_fn_v1', rate_limit_minimal)") {
		t.Fatal("rendered source is missing rate-limit registration")
	}
	if !strings.Contains(source, "redis.register_function('dashxd_test_tick_v1', timer_tick)") {
		t.Fatal("rendered source is missing timer tick registration")
	}
	if strings.Contains(source, libraryNameMarker) || strings.Contains(source, registrationMarker) {
		t.Fatal("rendered source still contains template markers")
	}
}

func TestRenderRejectsInvalidIdentifiers(t *testing.T) {
	if _, err := Render(
		"bad:name",
		Registration{FunctionName: "fn", WrapperName: "wrapper"},
	); err == nil {
		t.Fatal("expected invalid library identifier to be rejected")
	}
	if _, err := Render("valid_name"); err == nil {
		t.Fatal("expected empty registrations to be rejected")
	}
}
