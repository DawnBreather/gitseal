package client

import (
	"path/filepath"
	"testing"

	"github.com/dawnbreather/gitseal/internal/crypto"
)

// StripKeyFromBundle removes KEY from every env section of a v2 bundle file, so a
// subsequent reseal re-seals it fresh (the L10 remove-then-reseal rotation
// ritual, made a first-class op instead of a hand-edit). It is the mechanism
// behind `reseal --rotate KEY`.
func TestStripKeyFromBundle(t *testing.T) {
	human, _ := crypto.GenerateRepoKey()
	g, _ := crypto.GenerateRepoKey()
	s, _ := crypto.GenerateRepoKey()
	path := filepath.Join(t.TempDir(), "geo.app.json")
	clusters := map[string]string{"example": g.Recipient, "staging": s.Recipient}
	envCluster := map[string]string{"prod": "example", "staging": "staging"}
	resolved := map[string]map[string]string{
		"prod":    {"A": "1", "SECRET": "old"},
		"staging": {"A": "1", "SECRET": "old"},
	}
	if _, err := SealBundleV2(path, human.Recipient, clusters, envCluster, 338, 30, resolved); err != nil {
		t.Fatal(err)
	}

	n, err := StripKeyFromBundle(path, "SECRET")
	if err != nil {
		t.Fatalf("StripKeyFromBundle: %v", err)
	}
	if n != 2 {
		t.Fatalf("expected SECRET removed from 2 env sections, got %d", n)
	}

	after, _ := LoadBundle(path)
	for _, env := range []string{"prod", "staging"} {
		if _, ok := after.Envs[env].Entries["SECRET"]; ok {
			t.Errorf("SECRET still present in %s after strip", env)
		}
		if _, ok := after.Envs[env].Entries["A"]; !ok {
			t.Errorf("A must be retained in %s", env)
		}
	}
}

func TestStripKeyFromBundle_AbsentKeyIsZero(t *testing.T) {
	human, _ := crypto.GenerateRepoKey()
	g, _ := crypto.GenerateRepoKey()
	path := filepath.Join(t.TempDir(), "geo.app.json")
	clusters := map[string]string{"example": g.Recipient}
	envCluster := map[string]string{"prod": "example"}
	SealBundleV2(path, human.Recipient, clusters, envCluster, 338, 30,
		map[string]map[string]string{"prod": {"A": "1"}})

	n, err := StripKeyFromBundle(path, "NOPE")
	if err != nil {
		t.Fatalf("stripping an absent key should not error: %v", err)
	}
	if n != 0 {
		t.Fatalf("absent key strip count = %d, want 0", n)
	}
}
