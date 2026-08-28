package ratelimiter

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/dash-xd/ratelimiter/internal/profiledef"
)

func TestNamespaceStageTargets(t *testing.T) {
	resolver := NamespaceStageTargets("logs:rate_limiters", PurposeMetrics, Metadata{"source": "fixed"})
	in := Input{Request: Request{Namespace: Namespace{
		Environment: "prod",
		Parent:      "bootstrap",
		Child:       "global",
	}}}
	targets := resolver.ResolveTargets(in, StageAllowed)
	if len(targets) != 1 || targets[0].Channel != "prod:bootstrap:global:logs:rate_limiters:allowed" {
		t.Fatalf("unexpected targets: %#v", targets)
	}
}

func TestBuildEventContextMergesRequestData(t *testing.T) {
	profile := profiledef.Lifecycle(StaticTargets(map[Stage][]Target{
		StageAllowed: {{
			Channel: "events:allowed",
			Purpose: PurposeTracing,
			Data:    Metadata{"fixed": "yes", "override": "fixed"},
		}},
	}))
	in := Input{
		Bucket:  "tenant:client",
		Request: Request{ID: "req-1", Operation: "compute"},
		CallbackData: Metadata{
			"override": "request",
			"dynamic":  "yes",
		},
	}

	raw, err := buildEventContext(profile, in)
	if err != nil {
		t.Fatal(err)
	}
	var got eventContext
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	data := got.Targets[StageAllowed][0].Data
	if data["fixed"] != "yes" || data["override"] != "request" || data["dynamic"] != "yes" {
		t.Fatalf("unexpected merged data: %#v", data)
	}
}

func TestInputAndLimitValidation(t *testing.T) {
	if err := (Input{Bucket: "bad{tag}"}).validate(); err == nil {
		t.Fatal("expected hash-tag braces to be rejected")
	}
	if err := (Limit{MaxRequests: 1, Window: 500 * time.Microsecond}).validate(); err == nil {
		t.Fatal("expected sub-millisecond window to be rejected")
	}
}
