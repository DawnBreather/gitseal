package client

import (
	"path/filepath"
	"testing"

	"github.com/dawnbreather/gitseal/internal/crypto"
)

// TestSealBundleV2ScopedPreservesOtherEnvs is the safety property behind
// env-scoped `seal --env staging`: sealing a SUBSET of envs (only those present
// in `resolved`) must leave the OTHER env sections BYTE-IDENTICAL, not drop them.
// Without this, a developer scoping a change to staging would silently delete the
// prod/preprod sections. Envs absent from `resolved` are carried verbatim from the
// prior bundle; envs present in `resolved` follow the existing per-key replace +
// no-nonce-churn rules.
func TestSealBundleV2ScopedPreservesOtherEnvs(t *testing.T) {
	human, _ := crypto.GenerateRepoKey()
	g, _ := crypto.GenerateRepoKey()
	s, _ := crypto.GenerateRepoKey()
	path := filepath.Join(t.TempDir(), "geo.app.json")

	clusters := map[string]string{"example": g.Recipient, "staging": s.Recipient}
	envCluster := map[string]string{"prod": "example", "preprod": "example", "staging": "staging"}

	// 1. full seal — all three envs present.
	full := map[string]map[string]string{
		"prod":    {"A": "1", "B": "2"},
		"preprod": {"A": "1", "B": "2"},
		"staging": {"A": "1", "B": "2"},
	}
	if _, err := SealBundleV2(path, human.Recipient, clusters, envCluster, 338, 30, full); err != nil {
		t.Fatalf("initial full seal: %v", err)
	}
	before, _ := LoadBundle(path)
	prodBefore := before.Envs["prod"].Entries["A"]
	preprodBefore := before.Envs["preprod"].Entries["B"]

	// 2. scoped seal — ONLY staging in `resolved`, adding a brand-new key TOKEN
	//    (A/B carried verbatim by the no-nonce-churn rule; changing an existing
	//    value is the separate remove-then-reseal L10 ritual, not exercised here).
	scoped := map[string]map[string]string{
		"staging": {"A": "1", "B": "2", "TOKEN": "sk-new"},
	}
	if _, err := SealBundleV2(path, human.Recipient, clusters, envCluster, 338, 30, scoped); err != nil {
		t.Fatalf("scoped seal: %v", err)
	}
	after, _ := LoadBundle(path)

	// prod + preprod sections must be preserved byte-identical (not dropped).
	if _, ok := after.Envs["prod"]; !ok {
		t.Fatal("prod section was DROPPED by a staging-scoped seal (data loss)")
	}
	if _, ok := after.Envs["preprod"]; !ok {
		t.Fatal("preprod section was DROPPED by a staging-scoped seal (data loss)")
	}
	if after.Envs["prod"].Entries["A"] != prodBefore {
		t.Error("prod/A ciphertext churned by a staging-scoped seal")
	}
	if after.Envs["preprod"].Entries["B"] != preprodBefore {
		t.Error("preprod/B ciphertext churned by a staging-scoped seal")
	}

	// the NEW staging key opens to its value with the staging key, and prod does
	// NOT gain it (scope respected).
	pt, _, err := crypto.UnsealVerified(after.EnvCiphertext("staging", "TOKEN"), []byte(s.Identity), 338)
	if err != nil {
		t.Fatalf("staging/TOKEN should open with S: %v", err)
	}
	if string(pt) != "sk-new" {
		t.Fatalf("staging/TOKEN = %q, want sk-new", pt)
	}
	if _, ok := after.Envs["prod"].Entries["TOKEN"]; ok {
		t.Fatal("scope violation: staging-scoped seal leaked TOKEN into prod")
	}
}
