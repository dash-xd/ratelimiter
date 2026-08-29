package main

import "testing"

func TestParseProfiles(t *testing.T) {
	profiles, err := parseProfiles("minimal, lifecycle, minimal")
	if err != nil {
		t.Fatal(err)
	}
	if len(profiles) != 2 {
		t.Fatalf("got %d profiles, want 2", len(profiles))
	}
}

func TestParseProfilesRejectsUnknownProfile(t *testing.T) {
	if _, err := parseProfiles("minimal,unknown"); err == nil {
		t.Fatal("expected unknown profile to be rejected")
	}
}
