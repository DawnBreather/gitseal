package client

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/dawnbreather/gitseal/internal/crypto"
)

// hasViol reports whether any violation string contains substr (case-sensitive).
func hasViol(viols []string, substr string) bool {
	for _, v := range viols {
		if strings.Contains(v, substr) {
			return true
		}
	}
	return false
}

// sealTo is a test helper: seal "x" to the given recipients and return the
// base64-encoded ciphertext (the on-disk entry form).
func sealTo(t *testing.T, projectID int64, recipients ...string) string {
	t.Helper()
	ct, err := crypto.SealMulti([]byte("x"), recipients, projectID, "K", crypto.DefaultMinAccessLevel)
	if err != nil {
		t.Fatalf("SealMulti: %v", err)
	}
	return base64.StdEncoding.EncodeToString(ct)
}

// v2rc builds a canonical v2 RepoConfig for tests: one human + G(example)/
// S(staging), prod+preprod→example, staging→staging.
func v2rc(t *testing.T, human, g, s string) *RepoConfig {
	t.Helper()
	return &RepoConfig{
		ProjectID: 338,
		Recipient: human,
		Clusters:  map[string]string{"example": g, "staging": s},
		EnvCluster: map[string]string{
			"prod":    "example",
			"preprod": "example",
			"staging": "staging",
		},
	}
}

// TestVerifyBundleHappy: a well-formed v2 bundle (built by SealBundleV2) →
// 0 violations.
func TestVerifyBundleHappy(t *testing.T) {
	human, _ := crypto.GenerateRepoKey()
	g, _ := crypto.GenerateRepoKey()
	s, _ := crypto.GenerateRepoKey()
	rc := v2rc(t, human.Recipient, g.Recipient, s.Recipient)

	path := t.TempDir() + "/geo.app.json"
	resolved := map[string]map[string]string{
		"prod":    {"A": "1", "B": "2"},
		"preprod": {"A": "1"},
		"staging": {"A": "9"},
	}
	if _, err := SealBundleV2(path, human.Recipient, rc.Clusters, rc.EnvCluster, 338, 30, resolved); err != nil {
		t.Fatalf("SealBundleV2: %v", err)
	}
	b, err := LoadBundle(path)
	if err != nil {
		t.Fatalf("LoadBundle: %v", err)
	}
	if res := VerifyBundle(b, rc, false); len(res.Violations) != 0 || len(res.Warnings) != 0 {
		t.Fatalf("expected 0 violations/warnings, got: %+v", res)
	}
	// strict mode on a clean v2 bundle is also 0.
	if res := VerifyBundle(b, rc, true); len(res.Violations) != 0 || len(res.Warnings) != 0 {
		t.Fatalf("strict: expected 0 violations/warnings, got: %+v", res)
	}
}

// TestVerifyBundleTamperedClusterLabel: [SECURITY] an env section whose declared
// Cluster does not match rc.EnvCluster is a violation. This is the realizable
// catch (stanza count is still 2, so the count check alone would pass).
func TestVerifyBundleTamperedClusterLabel(t *testing.T) {
	human, _ := crypto.GenerateRepoKey()
	g, _ := crypto.GenerateRepoKey()
	s, _ := crypto.GenerateRepoKey()
	rc := v2rc(t, human.Recipient, g.Recipient, s.Recipient)

	// Hand-build: prod section correctly sealed to [human, G] but the section's
	// Cluster label is faked to "staging" while rc.EnvCluster["prod"]=="example".
	b := &SealedBundle{
		Kind: "SealedBundle", Version: "v2", ProjectID: 338, MinAccessLevel: 30,
		Recipients: map[string]string{"human": human.Recipient, "example": g.Recipient, "staging": s.Recipient},
		Envs: map[string]EnvSection{
			"prod":    {Cluster: "staging", Entries: map[string]string{"A": sealTo(t, 338, human.Recipient, g.Recipient)}},
			"preprod": {Cluster: "example", Entries: map[string]string{"A": sealTo(t, 338, human.Recipient, g.Recipient)}},
			"staging": {Cluster: "staging", Entries: map[string]string{"A": sealTo(t, 338, human.Recipient, s.Recipient)}},
		},
	}
	viols := VerifyBundle(b, rc, false).Violations
	if !hasViol(viols, "prod") || !hasViol(viols, "cluster") {
		t.Fatalf("expected a prod cluster-mismatch violation, got: %v", viols)
	}
}

// TestVerifyBundleThreeStanzas: [SECURITY] an entry sealed to [human, G, S]
// (the FORBIDDEN cross-cluster over-seal) has 3 stanzas → count!=2 violation.
func TestVerifyBundleThreeStanzas(t *testing.T) {
	human, _ := crypto.GenerateRepoKey()
	g, _ := crypto.GenerateRepoKey()
	s, _ := crypto.GenerateRepoKey()
	rc := v2rc(t, human.Recipient, g.Recipient, s.Recipient)

	b := &SealedBundle{
		Kind: "SealedBundle", Version: "v2", ProjectID: 338, MinAccessLevel: 30,
		Recipients: map[string]string{"human": human.Recipient, "example": g.Recipient, "staging": s.Recipient},
		Envs: map[string]EnvSection{
			"prod":    {Cluster: "example", Entries: map[string]string{"LEAK": sealTo(t, 338, human.Recipient, g.Recipient, s.Recipient)}},
			"preprod": {Cluster: "example", Entries: map[string]string{"A": sealTo(t, 338, human.Recipient, g.Recipient)}},
			"staging": {Cluster: "staging", Entries: map[string]string{"A": sealTo(t, 338, human.Recipient, s.Recipient)}},
		},
	}
	viols := VerifyBundle(b, rc, false).Violations
	if !hasViol(viols, "LEAK") || !hasViol(viols, "prod") {
		t.Fatalf("expected a prod/LEAK stanza-count violation, got: %v", viols)
	}
}

// TestVerifyBundleMissingEnv: an env declared in rc.EnvCluster but absent from
// the bundle's Envs is a violation.
func TestVerifyBundleMissingEnv(t *testing.T) {
	human, _ := crypto.GenerateRepoKey()
	g, _ := crypto.GenerateRepoKey()
	s, _ := crypto.GenerateRepoKey()
	rc := v2rc(t, human.Recipient, g.Recipient, s.Recipient)

	b := &SealedBundle{
		Kind: "SealedBundle", Version: "v2", ProjectID: 338, MinAccessLevel: 30,
		Recipients: map[string]string{"human": human.Recipient, "example": g.Recipient, "staging": s.Recipient},
		Envs: map[string]EnvSection{
			// prod + staging present; preprod (in rc.EnvCluster) is MISSING.
			"prod":    {Cluster: "example", Entries: map[string]string{"A": sealTo(t, 338, human.Recipient, g.Recipient)}},
			"staging": {Cluster: "staging", Entries: map[string]string{"A": sealTo(t, 338, human.Recipient, s.Recipient)}},
		},
	}
	viols := VerifyBundle(b, rc, false).Violations
	if !hasViol(viols, "preprod") {
		t.Fatalf("expected a missing-env (preprod) violation, got: %v", viols)
	}
}

// TestVerifyBundleHumanRecipientMismatch: b.Recipients["human"] must equal
// rc.Recipient; a mismatch (or absent human) is a violation.
func TestVerifyBundleHumanRecipientMismatch(t *testing.T) {
	human, _ := crypto.GenerateRepoKey()
	other, _ := crypto.GenerateRepoKey()
	g, _ := crypto.GenerateRepoKey()
	s, _ := crypto.GenerateRepoKey()
	rc := v2rc(t, human.Recipient, g.Recipient, s.Recipient)

	b := &SealedBundle{
		Kind: "SealedBundle", Version: "v2", ProjectID: 338, MinAccessLevel: 30,
		Recipients: map[string]string{"human": other.Recipient, "example": g.Recipient, "staging": s.Recipient},
		Envs: map[string]EnvSection{
			"prod":    {Cluster: "example", Entries: map[string]string{"A": sealTo(t, 338, human.Recipient, g.Recipient)}},
			"preprod": {Cluster: "example", Entries: map[string]string{"A": sealTo(t, 338, human.Recipient, g.Recipient)}},
			"staging": {Cluster: "staging", Entries: map[string]string{"A": sealTo(t, 338, human.Recipient, s.Recipient)}},
		},
	}
	viols := VerifyBundle(b, rc, false).Violations
	if !hasViol(viols, "human") {
		t.Fatalf("expected a human-recipient mismatch violation, got: %v", viols)
	}
}

// TestVerifyBundleMissingClusterRecipient: an env's declared cluster must be
// present in b.Recipients; if a referenced cluster is absent from the registry
// it is a violation.
func TestVerifyBundleMissingClusterRecipient(t *testing.T) {
	human, _ := crypto.GenerateRepoKey()
	g, _ := crypto.GenerateRepoKey()
	s, _ := crypto.GenerateRepoKey()
	rc := v2rc(t, human.Recipient, g.Recipient, s.Recipient)

	b := &SealedBundle{
		Kind: "SealedBundle", Version: "v2", ProjectID: 338, MinAccessLevel: 30,
		// "example" recipient deliberately missing from the registry.
		Recipients: map[string]string{"human": human.Recipient, "staging": s.Recipient},
		Envs: map[string]EnvSection{
			"prod":    {Cluster: "example", Entries: map[string]string{"A": sealTo(t, 338, human.Recipient, g.Recipient)}},
			"preprod": {Cluster: "example", Entries: map[string]string{"A": sealTo(t, 338, human.Recipient, g.Recipient)}},
			"staging": {Cluster: "staging", Entries: map[string]string{"A": sealTo(t, 338, human.Recipient, s.Recipient)}},
		},
	}
	viols := VerifyBundle(b, rc, false).Violations
	if !hasViol(viols, "example") {
		t.Fatalf("expected a missing cluster-recipient violation, got: %v", viols)
	}
}

// v1Bundle builds a minimal v1 (flat) bundle for the migration-window tests.
func v1Bundle(t *testing.T, human string) *SealedBundle {
	t.Helper()
	return &SealedBundle{
		Kind: "SealedBundle", Version: "v1", ProjectID: 338, MinAccessLevel: 30,
		Recipient: human,
		Entries:   map[string]string{"A": sealTo(t, 338, human)}, // 1-recipient v1-style entry
	}
}

// TestVerifyBundleV1Advisory: a v1 bundle → single advisory WARNING (no hard
// violation) in non-strict mode; a HARD violation (no warning) in strict mode.
func TestVerifyBundleV1Advisory(t *testing.T) {
	human, _ := crypto.GenerateRepoKey()
	g, _ := crypto.GenerateRepoKey()
	s, _ := crypto.GenerateRepoKey()
	rc := v2rc(t, human.Recipient, g.Recipient, s.Recipient)
	b := v1Bundle(t, human.Recipient)

	nonStrict := VerifyBundle(b, rc, false)
	if len(nonStrict.Violations) != 0 {
		t.Fatalf("v1 non-strict: expected zero hard violations, got: %v", nonStrict.Violations)
	}
	if len(nonStrict.Warnings) != 1 || !hasViol(nonStrict.Warnings, "v1") {
		t.Fatalf("v1 non-strict: expected exactly one v1 warning, got: %v", nonStrict.Warnings)
	}

	strict := VerifyBundle(b, rc, true)
	if !hasViol(strict.Violations, "v1") {
		t.Fatalf("v1 strict: expected a hard v1 violation, got: %v", strict.Violations)
	}
	if len(strict.Warnings) != 0 {
		t.Fatalf("v1 strict: expected no warnings (v1 is a hard failure), got: %v", strict.Warnings)
	}
}

// TestVerifyBundleV1NonStrictVsStrict pins the CLI-adjacent exit semantics: the
// same v1 bundle must PASS (no hard violation) in the default migration-window
// mode — so wiring verify into CI does not red the pipeline on un-migrated
// bundles — while --strict turns it into a hard violation. This is the exact
// behavior cmdVerify keys its exit code off (res.Violations only).
func TestVerifyBundleV1NonStrictVsStrict(t *testing.T) {
	human, _ := crypto.GenerateRepoKey()
	g, _ := crypto.GenerateRepoKey()
	s, _ := crypto.GenerateRepoKey()
	rc := v2rc(t, human.Recipient, g.Recipient, s.Recipient)
	b := v1Bundle(t, human.Recipient)

	// Non-strict: no hard violation (verify would exit 0) but a visible warning.
	nonStrict := VerifyBundle(b, rc, false)
	if !nonStrict.OK() {
		t.Fatalf("v1 non-strict: expected OK() (no hard violation), got: %v", nonStrict.Violations)
	}
	if len(nonStrict.Warnings) == 0 {
		t.Fatalf("v1 non-strict: expected a visible warning about the un-migrated bundle")
	}

	// Strict: a hard violation (verify would exit non-zero).
	strict := VerifyBundle(b, rc, true)
	if strict.OK() {
		t.Fatalf("v1 --strict: expected a hard violation (not OK), got none")
	}
	if !hasViol(strict.Violations, "strict") {
		t.Fatalf("v1 --strict: expected the strict v1 violation, got: %v", strict.Violations)
	}
}
