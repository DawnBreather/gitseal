package client

import (
	"path/filepath"
	"testing"

	"github.com/dawnbreather/gitseal/internal/crypto"
)

// --- Task 1.3: bundle v2 per-env sections + version-detecting LoadBundle -------
//
// A v2 SealedBundle carries a `recipients` registry (human + one age recipient
// per cluster) and an `envs` map of per-env sections, each naming its cluster
// and holding its own name→ciphertext entries. LoadBundle branches on `version`:
// v2 requires recipients+envs, v1/"" keep the flat-`entries` behavior.

// TestBundleV2RoundTrip writes a v2 bundle via writeBundle, reads it with
// LoadBundle, and asserts the v2-specific structure survives verbatim.
func TestBundleV2RoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "geo.app.json")

	in := &SealedBundle{
		Kind:           "SealedBundle",
		Version:        "v2",
		ProjectID:      338,
		MinAccessLevel: 30,
		Recipients: map[string]string{
			"human":   "age1human",
			"example": "age1G",
			"staging": "age1S",
		},
		Envs: map[string]EnvSection{
			"prod":    {Cluster: "example", Entries: map[string]string{"DB_HOST": "Y3Rwcm9k"}},
			"staging": {Cluster: "staging", Entries: map[string]string{"DB_HOST": "Y3RzdGc="}},
		},
	}
	if err := writeBundle(path, in); err != nil {
		t.Fatalf("writeBundle: %v", err)
	}

	b, err := LoadBundle(path)
	if err != nil {
		t.Fatalf("LoadBundle: %v", err)
	}
	if b.Version != "v2" {
		t.Fatalf("version: got %q want v2", b.Version)
	}
	if b.ProjectID != 338 || b.MinAccessLevel != 30 {
		t.Fatalf("metadata wrong: %+v", b)
	}
	if got := b.Envs["prod"].Cluster; got != "example" {
		t.Fatalf("envs[prod].cluster: got %q want example", got)
	}
	if got := b.Envs["staging"].Cluster; got != "staging" {
		t.Fatalf("envs[staging].cluster: got %q want staging", got)
	}
	if got := b.Recipients["example"]; got != "age1G" {
		t.Fatalf("recipients[example]: got %q want age1G", got)
	}
	if got := b.Recipients["human"]; got != "age1human" {
		t.Fatalf("recipients[human]: got %q want age1human", got)
	}
	// EnvCiphertext base64-decodes the selected env/name entry.
	if ct := b.EnvCiphertext("prod", "DB_HOST"); string(ct) != "ctprod" {
		t.Fatalf("EnvCiphertext(prod,DB_HOST): got %q want ctprod", ct)
	}
	if ct := b.EnvCiphertext("staging", "DB_HOST"); string(ct) != "ctstg" {
		t.Fatalf("EnvCiphertext(staging,DB_HOST): got %q want ctstg", ct)
	}
	if ct := b.EnvCiphertext("prod", "MISSING"); ct != nil {
		t.Fatalf("EnvCiphertext(missing name): got %q want nil", ct)
	}
	if ct := b.EnvCiphertext("bogus", "DB_HOST"); ct != nil {
		t.Fatalf("EnvCiphertext(missing env): got %q want nil", ct)
	}
}

// TestBundleV1StillLoads proves the v2 loader did not break v1 back-compat: a
// bundle sealed by the existing v1 SealBundle path loads with version "v1" and
// Ciphertext() still resolves flat entries.
func TestBundleV1StillLoads(t *testing.T) {
	kp, _ := crypto.GenerateRepoKey()
	path := filepath.Join(t.TempDir(), "legacy.json")

	if _, err := SealBundle(path, kp.Recipient, 412, 40, map[string]string{"API_KEY": "sk-1"}, false, false); err != nil {
		t.Fatalf("SealBundle(v1): %v", err)
	}

	b, err := LoadBundle(path)
	if err != nil {
		t.Fatalf("LoadBundle: %v", err)
	}
	if b.Version != "v1" {
		t.Fatalf("version: got %q want v1", b.Version)
	}
	ct := b.Ciphertext("API_KEY")
	if ct == nil {
		t.Fatal("v1 Ciphertext returned nil")
	}
	pt, level, err := crypto.UnsealVerified(ct, []byte(kp.Identity), 412)
	if err != nil || string(pt) != "sk-1" || level != 40 {
		t.Fatalf("v1 entry did not round-trip: %q/%d err=%v", pt, level, err)
	}
}

// --- Task 2.2: SealBundleV2 per-cluster fan-out --------------------------------

// TestSealBundleV2SealsPerCluster proves per-cluster isolation at the BUNDLE
// layer: after sealing the same plaintext into prod (cluster example → G) and
// staging (cluster staging → S), the prod section's ciphertext opens with G but
// NOT with S, and the staging section's opens with S but NOT with G. Both open
// with the human identity.
func TestSealBundleV2SealsPerCluster(t *testing.T) {
	human, _ := crypto.GenerateRepoKey()
	g, _ := crypto.GenerateRepoKey() // example
	s, _ := crypto.GenerateRepoKey() // staging
	path := filepath.Join(t.TempDir(), "geo.app.json")

	clusters := map[string]string{"example": g.Recipient, "staging": s.Recipient}
	envCluster := map[string]string{"prod": "example", "staging": "staging"}
	resolved := map[string]map[string]string{
		"prod":    {"A": "1"},
		"staging": {"A": "1"},
	}

	if _, err := SealBundleV2(path, human.Recipient, clusters, envCluster, 338, 30, resolved); err != nil {
		t.Fatalf("SealBundleV2: %v", err)
	}

	b, err := LoadBundle(path)
	if err != nil {
		t.Fatalf("LoadBundle: %v", err)
	}
	// v3: normalized — no cluster label, no recipients registry on disk.
	// The per-cluster isolation is proven by the decrypt checks below (crypto truth),
	// not by any label.
	if b.Version != BundleVersionV3 {
		t.Fatalf("version: got %q want v3", b.Version)
	}
	if b.Envs["prod"].Cluster != "" || b.Envs["staging"].Cluster != "" {
		t.Fatalf("v3 sections must not carry a cluster label: %+v", b.Envs)
	}
	if b.Recipients != nil {
		t.Fatalf("v3 must not carry a recipients registry: %+v", b.Recipients)
	}

	prodCT := b.EnvCiphertext("prod", "A")
	stgCT := b.EnvCiphertext("staging", "A")

	// prod section opens with G, NOT with S.
	if _, _, err := crypto.UnsealVerified(prodCT, []byte(g.Identity), 338); err != nil {
		t.Fatalf("prod entry should open with G: %v", err)
	}
	if _, _, err := crypto.UnsealVerified(prodCT, []byte(s.Identity), 338); err == nil {
		t.Fatal("SECURITY FAILURE: staging key S decrypted a prod (example) entry")
	}
	// staging section opens with S, NOT with G.
	if _, _, err := crypto.UnsealVerified(stgCT, []byte(s.Identity), 338); err != nil {
		t.Fatalf("staging entry should open with S: %v", err)
	}
	if _, _, err := crypto.UnsealVerified(stgCT, []byte(g.Identity), 338); err == nil {
		t.Fatal("SECURITY FAILURE: example key G decrypted a staging entry")
	}
	// human opens both.
	if _, _, err := crypto.UnsealVerified(prodCT, []byte(human.Identity), 338); err != nil {
		t.Fatalf("human should open prod entry: %v", err)
	}
	if _, _, err := crypto.UnsealVerified(stgCT, []byte(human.Identity), 338); err != nil {
		t.Fatalf("human should open staging entry: %v", err)
	}
}

// TestSealBundleV2NoNonceChurn is the load-bearing minimal-diff MUST: resealing
// with an unchanged key present in the prior section leaves that entry's stored
// ciphertext BYTE-IDENTICAL (no fresh nonce), while a new key is added. This is
// what keeps rotation/cutover diffs honest — untouched keys don't churn.
func TestSealBundleV2NoNonceChurn(t *testing.T) {
	human, _ := crypto.GenerateRepoKey()
	g, _ := crypto.GenerateRepoKey()
	path := filepath.Join(t.TempDir(), "geo.app.json")

	clusters := map[string]string{"example": g.Recipient}
	envCluster := map[string]string{"prod": "example"}

	if _, err := SealBundleV2(path, human.Recipient, clusters, envCluster, 338, 30,
		map[string]map[string]string{"prod": {"A": "1"}}); err != nil {
		t.Fatalf("first SealBundleV2: %v", err)
	}
	first, err := LoadBundle(path)
	if err != nil {
		t.Fatalf("LoadBundle(first): %v", err)
	}
	capturedA := first.Envs["prod"].Entries["A"]
	if capturedA == "" {
		t.Fatal("expected an A entry after first seal")
	}

	// reseal: A unchanged, B new.
	if _, err := SealBundleV2(path, human.Recipient, clusters, envCluster, 338, 30,
		map[string]map[string]string{"prod": {"A": "1", "B": "2"}}); err != nil {
		t.Fatalf("second SealBundleV2: %v", err)
	}
	second, err := LoadBundle(path)
	if err != nil {
		t.Fatalf("LoadBundle(second): %v", err)
	}

	if got := second.Envs["prod"].Entries["A"]; got != capturedA {
		t.Fatalf("no-nonce-churn violated: A changed on reseal\n  before=%q\n   after=%q", capturedA, got)
	}
	if second.Envs["prod"].Entries["B"] == "" {
		t.Fatal("new key B was not added on reseal")
	}
	// B must still be a real, openable ciphertext (not a carried-over stub).
	if _, _, err := crypto.UnsealVerified(second.EnvCiphertext("prod", "B"), []byte(g.Identity), 338); err != nil {
		t.Fatalf("new key B should open with G: %v", err)
	}
}

// TestSealBundleV2ClusterRemapForcesReseal is the security regression for the
// cluster-aware carry-over guard: the no-nonce-churn carry-over must NOT reuse a
// prior ciphertext when env_cluster has remapped the env to a DIFFERENT cluster.
// Reusing it would keep OLD-cluster ciphertext (openable by the wrong cluster)
// while the section's Cluster field flips to the new cluster — crypto and
// metadata disagree, defeating per-cluster isolation. The guard forces a fresh
// SealMulti so the ciphertext follows the remap.
func TestSealBundleV2ClusterRemapForcesReseal(t *testing.T) {
	human, _ := crypto.GenerateRepoKey()
	g, _ := crypto.GenerateRepoKey() // example
	s, _ := crypto.GenerateRepoKey() // staging
	path := filepath.Join(t.TempDir(), "geo.app.json")

	clusters := map[string]string{"example": g.Recipient, "staging": s.Recipient}

	// 1) Seal prod→example. prod.A is sealed to [human, G].
	if _, err := SealBundleV2(path, human.Recipient, clusters,
		map[string]string{"prod": "example"}, 338, 30,
		map[string]map[string]string{"prod": {"A": "secret"}}); err != nil {
		t.Fatalf("first SealBundleV2: %v", err)
	}
	first, err := LoadBundle(path)
	if err != nil {
		t.Fatalf("LoadBundle(first): %v", err)
	}
	beforeA := first.Envs["prod"].Entries["A"]
	if beforeA == "" {
		t.Fatal("expected prod.A after first seal")
	}
	// v3: no cluster label on the section. Isolation is crypto: G opens
	// prod.A, S does NOT.
	beforeCT := first.EnvCiphertext("prod", "A")
	if _, _, err := crypto.UnsealVerified(beforeCT, []byte(g.Identity), 338); err != nil {
		t.Fatalf("prod.A should open with G before remap: %v", err)
	}
	if _, _, err := crypto.UnsealVerified(beforeCT, []byte(s.Identity), 338); err == nil {
		t.Fatal("prod.A must NOT open with S before remap")
	}

	// 2) v3 REMAP SEMANTICS: dropping the cluster label removes the
	// info that let v2 AUTO-detect a cluster remap offline. A naive reseal after
	// remapping prod→staging with the SAME key set therefore CARRIES the old
	// (example-sealed) bytes verbatim (no-nonce-churn). This is NOT a leak: the
	// new cluster's key can't decrypt old-cluster bytes, so gate #2 (crypto) makes
	// the pod secret FAIL to materialize (loud) — availability failure, never a
	// confidentiality leak. A remap is a DELIBERATE act, done via the L10
	// remove-then-reseal ritual (same as value rotation, which the tool also can't
	// auto-detect offline). This test pins that honest semantic.
	if _, err := SealBundleV2(path, human.Recipient, clusters,
		map[string]string{"prod": "staging"}, 338, 30,
		map[string]map[string]string{"prod": {"A": "secret"}}); err != nil {
		t.Fatalf("remap SealBundleV2: %v", err)
	}
	naive, _ := LoadBundle(path)
	if naive.Envs["prod"].Entries["A"] != beforeA {
		t.Fatal("expected naive remap to carry old bytes verbatim (v3 can't auto-detect a remap offline)")
	}

	// 3) The L10 ritual: STRIP the key (→ absent) then reseal → fresh seal to the
	// new cluster. Now crypto follows the remap.
	if _, err := StripKeyFromBundle(path, "A"); err != nil {
		t.Fatalf("strip: %v", err)
	}
	if _, err := SealBundleV2(path, human.Recipient, clusters,
		map[string]string{"prod": "staging"}, 338, 30,
		map[string]map[string]string{"prod": {"A": "secret"}}); err != nil {
		t.Fatalf("reseal after strip: %v", err)
	}
	second, _ := LoadBundle(path)
	afterCT := second.EnvCiphertext("prod", "A")
	if afterCT == nil || second.Envs["prod"].Entries["A"] == beforeA {
		t.Fatal("after remove-then-reseal, prod.A must be freshly sealed (bytes changed)")
	}
	// Crypto followed the remap: S opens prod.A, G does NOT.
	if _, _, err := crypto.UnsealVerified(afterCT, []byte(s.Identity), 338); err != nil {
		t.Fatalf("after ritual prod.A must open with S: %v", err)
	}
	if _, _, err := crypto.UnsealVerified(afterCT, []byte(g.Identity), 338); err == nil {
		t.Fatal("SECURITY: old cluster G still opens prod.A after the remove-then-reseal remap")
	}
	if _, _, err := crypto.UnsealVerified(afterCT, []byte(human.Identity), 338); err != nil {
		t.Fatalf("human should open prod.A after remap: %v", err)
	}
}

// TestSealBundleV2WrongProjectStillBoundByAEAD documents the v3 change:
// v3 dropped the top-level project_id, so SealBundleV2 can no longer AUTO-refuse a
// cross-project reseal offline (there's no stored project_id to compare). This is
// NOT a hole: project_id is embedded in EVERY AEAD envelope, so a carried-over
// entry from another project FAILS LOUD at unseal (UnsealVerified re-asserts the
// project_id) — a decrypt failure, never a wrong-secret leak. This test pins that
// the embedded binding still catches a cross-project ciphertext.
func TestSealBundleV2WrongProjectStillBoundByAEAD(t *testing.T) {
	human, _ := crypto.GenerateRepoKey()
	g, _ := crypto.GenerateRepoKey()
	path := filepath.Join(t.TempDir(), "geo.app.json")

	clusters := map[string]string{"example": g.Recipient}
	envCluster := map[string]string{"prod": "example"}

	// Seal for project 338, then reseal the SAME path claiming project 999. v3 has
	// no stored project_id, so this does NOT error offline (carry-over keeps 338's
	// bytes) — the guarantee is downstream:
	if _, err := SealBundleV2(path, human.Recipient, clusters, envCluster, 338, 30,
		map[string]map[string]string{"prod": {"A": "1"}}); err != nil {
		t.Fatalf("first SealBundleV2: %v", err)
	}
	if _, err := SealBundleV2(path, human.Recipient, clusters, envCluster, 999, 30,
		map[string]map[string]string{"prod": {"A": "1"}}); err != nil {
		t.Fatalf("v3 reseal (no offline project guard): %v", err)
	}
	// The carried 338-bound ciphertext must FAIL to unseal under project 999 — the
	// AEAD project_id binding is the real cross-project guard.
	b, _ := LoadBundle(path)
	ct := b.EnvCiphertext("prod", "A")
	if _, _, err := crypto.UnsealVerified(ct, []byte(g.Identity), 999); err == nil {
		t.Fatal("SECURITY: a 338-bound entry unsealed under project 999 — AEAD project binding broken")
	}
	if _, _, err := crypto.UnsealVerified(ct, []byte(g.Identity), 338); err != nil {
		t.Fatalf("the entry must still unseal under its real project 338: %v", err)
	}
}

// TestSealBundleV2UnmappedEnvErrors proves an env present in `resolved` but
// absent from `envCluster` is a hard error (no cluster → no isolation target),
// not a silent skip.
func TestSealBundleV2UnmappedEnvErrors(t *testing.T) {
	human, _ := crypto.GenerateRepoKey()
	g, _ := crypto.GenerateRepoKey()
	path := filepath.Join(t.TempDir(), "geo.app.json")

	clusters := map[string]string{"example": g.Recipient}
	// envCluster maps only "prod"; "staging" below is unmapped.
	envCluster := map[string]string{"prod": "example"}

	if _, err := SealBundleV2(path, human.Recipient, clusters, envCluster, 338, 30,
		map[string]map[string]string{"prod": {"A": "1"}, "staging": {"A": "1"}}); err == nil {
		t.Fatal("expected error: env 'staging' has no cluster mapping in envCluster")
	}
}
