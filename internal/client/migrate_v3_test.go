package client

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/ssh"
)

// MigrateBundleToV3 is the v2→v3 transition: it NORMALIZES a v2 bundle
// (drop project_id/min_access_level/recipients + each section's cluster label)
// and SIGNS each env section — over the EXISTING ciphertext (CanonicalSectionBytes
// hashes project_id‖env‖entries), so it NEVER decrypts and the entries are
// preserved byte-for-byte. The signed result must pass VerifySectionAuthz.
func TestMigrateBundleToV3_NormalizesAndSigns(t *testing.T) {
	ctA := encB64("ciphertext-A")
	ctB := encB64("ciphertext-B")
	v2 := `{"kind":"SealedBundle","version":"v2","project_id":338,"min_access_level":40,` +
		`"recipients":{"human":"age1h","example":"age1G","staging":"age1S"},` +
		`"envs":{` +
		`"prod":{"cluster":"example","entries":{"DB":"` + ctA + `","API":"` + ctB + `"}},` +
		`"staging":{"cluster":"staging","entries":{"DB":"` + ctA + `"}}` +
		`}}`
	path := filepath.Join(t.TempDir(), "svc.app.json")
	if err := os.WriteFile(path, []byte(v2), 0o644); err != nil {
		t.Fatal(err)
	}

	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	sshPub, _ := ssh.NewPublicKey(pub)
	signer := NewSSHSignerFrom(mustSigner(t, priv))
	fp := KeyFingerprint(sshPub)

	res, err := MigrateBundleToV3(path, 338, signer)
	if err != nil {
		t.Fatalf("MigrateBundleToV3: %v", err)
	}
	if res.Fingerprint != fp {
		t.Fatalf("fingerprint = %q, want %q", res.Fingerprint, fp)
	}
	if len(res.EnvsSigned) != 2 {
		t.Fatalf("expected 2 envs signed, got %v", res.EnvsSigned)
	}

	b, err := LoadBundle(path)
	if err != nil {
		t.Fatal(err)
	}
	// (1) normalized to v3, denormalized fields gone
	if b.Version != BundleVersionV3 {
		t.Fatalf("version = %q, want v3", b.Version)
	}
	if b.ProjectID != 0 || b.MinAccessLevel != 0 || b.Recipients != nil || b.Recipient != "" || b.Entries != nil {
		t.Fatalf("denormalized fields not dropped: %+v", b)
	}
	for env, sec := range b.Envs {
		if sec.Cluster != "" {
			t.Fatalf("env %q still carries a cluster label", env)
		}
	}
	// (2) ciphertext preserved byte-for-byte (NO decrypt/re-encrypt)
	if b.Envs["prod"].Entries["DB"] != ctA || b.Envs["prod"].Entries["API"] != ctB ||
		b.Envs["staging"].Entries["DB"] != ctA {
		t.Fatal("ciphertext was altered — migration must preserve entries verbatim")
	}
	// (3) every section signed + verifies under the gate (level 40 >= min 40)
	reg := stubResolver{
		users:  map[string]ssh.PublicKey{fp: sshPub},
		levels: map[string]int{fp: 50},
	}
	for _, env := range []string{"prod", "staging"} {
		sec := b.Envs[env]
		if sec.Sig == nil || sec.Sig.By != fp {
			t.Fatalf("env %q not signed", env)
		}
		if err := VerifySectionAuthz(338, env, sec, 40, reg); err != nil {
			t.Fatalf("migrated env %q must pass authz: %v", env, err)
		}
	}
}

// A project_id mismatch (bundle says 338, caller passes 999) is a hard error —
// signing under the wrong project would bind canonical bytes to the wrong id and
// the sig would be meaningless/unverifiable downstream. Fail closed.
func TestMigrateBundleToV3_RejectsProjectMismatch(t *testing.T) {
	v2 := `{"kind":"SealedBundle","version":"v2","project_id":338,"min_access_level":40,` +
		`"recipients":{"human":"age1h"},"envs":{"prod":{"cluster":"example","entries":{"A":"` + encB64("x") + `"}}}}`
	path := filepath.Join(t.TempDir(), "svc.app.json")
	os.WriteFile(path, []byte(v2), 0o644)
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer := NewSSHSignerFrom(mustSigner(t, priv))
	if _, err := MigrateBundleToV3(path, 999, signer); err == nil {
		t.Fatal("project_id mismatch must be rejected")
	}
}

// Running migrate on an already-v3 bundle just re-signs it (idempotent shape) —
// it must not corrupt entries or fail on the missing denormalized fields.
func TestMigrateBundleToV3_IdempotentOnV3(t *testing.T) {
	v3 := `{"kind":"SealedBundle","version":"v3","envs":{"prod":{"entries":{"A":"` + encB64("x") + `"}}}}`
	path := filepath.Join(t.TempDir(), "svc.app.json")
	os.WriteFile(path, []byte(v3), 0o644)
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer := NewSSHSignerFrom(mustSigner(t, priv))
	if _, err := MigrateBundleToV3(path, 338, signer); err != nil {
		t.Fatalf("migrate on v3 must succeed (re-sign): %v", err)
	}
	b, _ := LoadBundle(path)
	if b.Version != BundleVersionV3 || b.Envs["prod"].Entries["A"] != encB64("x") {
		t.Fatalf("idempotent migrate altered the bundle: %+v", b)
	}
}

// A v1 flat bundle has no env sections — refuse it (v1 must be resealed, not
// mechanically migrated, since it predates the per-env model entirely).
func TestMigrateBundleToV3_RejectsV1(t *testing.T) {
	v1 := `{"kind":"SealedBundle","version":"v1","recipient":"age1h","entries":{"A":"` + encB64("x") + `"}}`
	path := filepath.Join(t.TempDir(), "svc.app.json")
	os.WriteFile(path, []byte(v1), 0o644)
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer := NewSSHSignerFrom(mustSigner(t, priv))
	if _, err := MigrateBundleToV3(path, 338, signer); err == nil {
		t.Fatal("v1 flat bundle must be rejected (no per-env sections to migrate)")
	}
}

func mustSigner(t *testing.T, priv ed25519.PrivateKey) ssh.Signer {
	t.Helper()
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return s
}
