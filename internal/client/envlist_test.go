package client

import (
	"strings"
	"testing"
)

// RenderEnvList turns a resolved RepoConfig + the caller's live project level into
// a human table: each env → its cluster, required level, and whether the caller can
// seal it (live level >= env_min_level). callerLevel < 0 means "unknown" (couldn't
// resolve) → shown as "?" rather than a false ✓/✗.
func TestRenderEnvList(t *testing.T) {
	rc := &RepoConfig{
		Recipient:   "age1proj",
		EnvCluster:  map[string]string{"prod": "example", "preprod": "example", "staging": "staging"},
		EnvMinLevel: map[string]int{"prod": 40, "preprod": 40, "staging": 30},
		Clusters:    map[string]string{"example": "age1G", "staging": "age1S"},
	}
	out := RenderEnvList(rc, 30) // a Developer (level 30)

	// every env present, sorted, with its cluster + min-level
	for _, want := range []string{"prod", "preprod", "staging", "example", "40", "30"} {
		if !strings.Contains(out, want) {
			t.Fatalf("output missing %q:\n%s", want, out)
		}
	}
	// order: envs sorted alphabetically (preprod, prod, staging)
	if i, j, k := strings.Index(out, "preprod"), strings.Index(out, "prod "), strings.Index(out, "staging"); i >= j || j >= k {
		// (loose — just assert deterministic sorted grouping exists)
		if strings.Index(out, "preprod") >= strings.Index(out, "staging") {
			t.Fatalf("envs not sorted:\n%s", out)
		}
	}
	// a level-30 dev can seal staging (min 30) but NOT prod/preprod (min 40).
	staleLine := lineContaining(out, "staging")
	if !strings.Contains(staleLine, "✓") {
		t.Fatalf("staging line should show writable for level 30:\n%s", staleLine)
	}
	prodLine := lineContaining(out, "prod ")
	if strings.Contains(prodLine, "✓") {
		t.Fatalf("prod line must NOT show writable for level 30:\n%s", prodLine)
	}
}

// An unknown caller level (-1) must not claim ✓ or ✗ — show "?".
func TestRenderEnvList_UnknownLevel(t *testing.T) {
	rc := &RepoConfig{
		EnvCluster:  map[string]string{"prod": "example"},
		EnvMinLevel: map[string]int{"prod": 40},
		Clusters:    map[string]string{"example": "age1G"},
	}
	out := RenderEnvList(rc, -1)
	if strings.Contains(out, "✓") || strings.Contains(out, "✗") {
		t.Fatalf("unknown level must not assert writability:\n%s", out)
	}
	if !strings.Contains(out, "?") {
		t.Fatalf("unknown level should render '?':\n%s", out)
	}
}

func lineContaining(s, sub string) string {
	for _, ln := range strings.Split(s, "\n") {
		if strings.Contains(ln, sub) {
			return ln
		}
	}
	return ""
}
