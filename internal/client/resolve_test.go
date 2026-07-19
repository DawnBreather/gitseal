package client

import (
	"reflect"
	"testing"
)

// --- Task 4.1: ResolveEnvs base + per-env override fan-out ---------------------
//
// ResolveEnvs is the pure authoring core behind `seal --svc --from base.env
// [--env-file env=override.env ...]`. For each requested env it starts from a
// COPY of the base map and overlays that env's override (per-key last-wins),
// producing env → (KEY → value) with no shared backing maps between envs.

// TestResolveEnvsOverlay is the table from the plan: base {A:1,B:2}, overrides
// {prod:{A:9}}, envs [prod,staging] → {prod:{A:9,B:2}, staging:{A:1,B:2}}.
func TestResolveEnvsOverlay(t *testing.T) {
	base := map[string]string{"A": "1", "B": "2"}
	overrides := map[string]map[string]string{"prod": {"A": "9"}}
	got := ResolveEnvs(base, overrides, []string{"prod", "staging"})

	want := map[string]map[string]string{
		"prod":    {"A": "9", "B": "2"},
		"staging": {"A": "1", "B": "2"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ResolveEnvs mismatch:\n got=%v\nwant=%v", got, want)
	}
}

// TestResolveEnvsNilOverrides proves nil (or empty) overrides replicate the base
// verbatim to every requested env.
func TestResolveEnvsNilOverrides(t *testing.T) {
	base := map[string]string{"A": "1", "B": "2"}
	got := ResolveEnvs(base, nil, []string{"prod", "preprod", "staging"})

	want := map[string]map[string]string{
		"prod":    {"A": "1", "B": "2"},
		"preprod": {"A": "1", "B": "2"},
		"staging": {"A": "1", "B": "2"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ResolveEnvs(nil overrides) mismatch:\n got=%v\nwant=%v", got, want)
	}
}

// TestResolveEnvsEmptyEnvs proves an empty env list yields an empty (non-nil)
// result — no env → nothing resolved.
func TestResolveEnvsEmptyEnvs(t *testing.T) {
	got := ResolveEnvs(map[string]string{"A": "1"}, nil, nil)
	if len(got) != 0 {
		t.Fatalf("ResolveEnvs(empty envs): got %v want empty", got)
	}
}

// TestResolveEnvsNoAliasing proves per-env maps are independent COPIES of base:
// mutating one env's resolved map must not bleed into another env or the base.
func TestResolveEnvsNoAliasing(t *testing.T) {
	base := map[string]string{"A": "1"}
	got := ResolveEnvs(base, nil, []string{"prod", "staging"})
	got["prod"]["A"] = "mutated"
	if got["staging"]["A"] != "1" {
		t.Fatalf("aliasing: mutating prod bled into staging (%q)", got["staging"]["A"])
	}
	if base["A"] != "1" {
		t.Fatalf("aliasing: mutating a resolved env bled into base (%q)", base["A"])
	}
}
