package client

import (
	"crypto/ed25519"
	"crypto/rand"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/dawnbreather/gitseal/internal/crypto"
)

// SealBundleV4 is the seal-first authoring path: a fresh seal holds the
// plaintext, so it emits v4 DIRECTLY (embedding the project PUBKEY as the AEAD
// anti-splice discriminator) — no numeric project_id, no private-key `migrate-v4`
// round-trip. This mirrors the whole fleet's committed shape (recipient-only
// repo.yaml + v4 bundles) so a seald-first tenant is materializable in one step.

func TestSealBundleV4WritesV4AndOmitsNumericFields(t *testing.T) {
	human, _ := crypto.GenerateRepoKey()
	prodK, _ := crypto.GenerateRepoKey()
	stagingK, _ := crypto.GenerateRepoKey()
	path := filepath.Join(t.TempDir(), "backend.app.json")
	envRecipient := map[string]string{"prod": prodK.Recipient, "staging": stagingK.Recipient}
	resolved := map[string]map[string]string{
		"prod":    {"A": "1", "B": "2"},
		"staging": {"A": "1"},
	}
	if _, err := SealBundleV4(path, human.Recipient, envRecipient, 40, resolved); err != nil {
		t.Fatalf("SealBundleV4: %v", err)
	}

	b, err := LoadBundle(path)
	if err != nil {
		t.Fatal(err)
	}
	if b.Version != BundleVersionV4 {
		t.Fatalf("expected v4, got %q", b.Version)
	}
	// v4 is normalized: no numeric project_id / recipients / cluster labels on disk.
	raw := readFile(t, path)
	for _, forbidden := range []string{`"project_id"`, `"min_access_level"`, `"recipients"`, `"cluster"`} {
		if strings.Contains(raw, forbidden) {
			t.Fatalf("v4 bundle must not carry %s:\n%s", forbidden, raw)
		}
	}
	if len(b.Envs) != 2 {
		t.Fatalf("want 2 env sections, got %d", len(b.Envs))
	}
}

// The materializer path (UnsealVerifiedByKey with the per-env identity + the
// project pubkey) must open every v4 entry and recover the exact plaintext — the
// end-to-end proof a seald-first bundle is decryptable in-cluster.
func TestSealBundleV4MaterializerRoundTrip(t *testing.T) {
	human, _ := crypto.GenerateRepoKey()
	prodK, _ := crypto.GenerateRepoKey()
	path := filepath.Join(t.TempDir(), "backend.app.json")
	envRecipient := map[string]string{"prod": prodK.Recipient}
	resolved := map[string]map[string]string{"prod": {"SECRET_KEY": "s3cr3t", "DEBUG": "false"}}
	if _, err := SealBundleV4(path, human.Recipient, envRecipient, 40, resolved); err != nil {
		t.Fatalf("SealBundleV4: %v", err)
	}

	b, _ := LoadBundle(path)
	for name, want := range map[string]string{"SECRET_KEY": "s3cr3t", "DEBUG": "false"} {
		ct := b.EnvCiphertext("prod", name)
		if ct == nil {
			t.Fatalf("no ciphertext for %q", name)
		}
		// per-env identity opens it; the human key also opens it (both recipients).
		pt, lvl, err := crypto.UnsealVerifiedByKey(ct, []byte(prodK.Identity), human.Recipient)
		if err != nil {
			t.Fatalf("materializer unseal %q: %v", name, err)
		}
		if string(pt) != want {
			t.Fatalf("%q: got %q want %q", name, pt, want)
		}
		if lvl != 40 {
			t.Fatalf("%q: embedded level %d want 40", name, lvl)
		}
	}
}

// A v4 prior bundle reseal is a MINIMAL-DIFF op: re-supplying an unchanged key set
// carries every ciphertext byte-verbatim (no nonce churn), a new key seals fresh,
// and untouched env sections are preserved. This is the invariant that makes a
// seald-first reseal safe — and is exactly what the v3 path (SealBundleV2) FAILED
// to do for a v4 prior (it saw no v2/v3 prior → re-churned everything as v3).
func TestSealBundleV4ResealNoNonceChurn(t *testing.T) {
	human, _ := crypto.GenerateRepoKey()
	prodK, _ := crypto.GenerateRepoKey()
	path := filepath.Join(t.TempDir(), "backend.app.json")
	envRecipient := map[string]string{"prod": prodK.Recipient}

	if _, err := SealBundleV4(path, human.Recipient, envRecipient, 40,
		map[string]map[string]string{"prod": {"A": "1", "B": "2"}}); err != nil {
		t.Fatal(err)
	}
	before, _ := LoadBundle(path)
	ctABefore := before.Envs["prod"].Entries["A"]
	ctBBefore := before.Envs["prod"].Entries["B"]

	// reseal, adding C, re-supplying A+B unchanged.
	if _, err := SealBundleV4(path, human.Recipient, envRecipient, 40,
		map[string]map[string]string{"prod": {"A": "1", "B": "2", "C": "3"}}); err != nil {
		t.Fatal(err)
	}
	after, _ := LoadBundle(path)
	if after.Version != BundleVersionV4 {
		t.Fatalf("reseal must stay v4, got %q", after.Version)
	}
	if after.Envs["prod"].Entries["A"] != ctABefore || after.Envs["prod"].Entries["B"] != ctBBefore {
		t.Fatal("carry-over failed: unchanged keys were re-sealed (nonce churn)")
	}
	if after.Envs["prod"].Entries["C"] == "" {
		t.Fatal("new key C not sealed")
	}
}

// A scoped v4 seal (resolved covers a subset of envs) must PRESERVE the untouched
// env sections byte-identical rather than dropping them.
func TestSealBundleV4ScopedPreservesOtherEnvs(t *testing.T) {
	human, _ := crypto.GenerateRepoKey()
	prodK, _ := crypto.GenerateRepoKey()
	stagingK, _ := crypto.GenerateRepoKey()
	path := filepath.Join(t.TempDir(), "backend.app.json")
	envRecipient := map[string]string{"prod": prodK.Recipient, "staging": stagingK.Recipient}
	if _, err := SealBundleV4(path, human.Recipient, envRecipient, 40,
		map[string]map[string]string{"prod": {"A": "1"}, "staging": {"A": "1"}}); err != nil {
		t.Fatal(err)
	}
	before, _ := LoadBundle(path)
	stagingBefore := before.Envs["staging"].Entries["A"]

	// reseal ONLY prod
	if _, err := SealBundleV4(path, human.Recipient, envRecipient, 40,
		map[string]map[string]string{"prod": {"A": "2"}}); err != nil {
		t.Fatal(err)
	}
	after, _ := LoadBundle(path)
	if _, ok := after.Envs["staging"]; !ok {
		t.Fatal("scoped seal dropped the untouched staging section")
	}
	if after.Envs["staging"].Entries["A"] != stagingBefore {
		t.Fatal("scoped seal churned the untouched staging section")
	}
}

// SignBundleFileV4 signs each v4 section over CanonicalSectionBytesV4 (bound to the
// pubkey) and the result passes VerifySectionAuthz; a post-sign tamper fails.
func TestSignBundleFileV4RoundTrip(t *testing.T) {
	human, _ := crypto.GenerateRepoKey()
	prodK, _ := crypto.GenerateRepoKey()
	path := filepath.Join(t.TempDir(), "backend.app.json")
	envRecipient := map[string]string{"prod": prodK.Recipient}
	if _, err := SealBundleV4(path, human.Recipient, envRecipient, 40,
		map[string]map[string]string{"prod": {"DB": "v", "API": "w"}}); err != nil {
		t.Fatal(err)
	}

	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	sshPub, _ := ssh.NewPublicKey(pub)
	inSigner, _ := ssh.NewSignerFromKey(priv)
	signer := NewSSHSignerFrom(inSigner)

	fp, err := SignBundleFileV4(path, human.Recipient, signer)
	if err != nil {
		t.Fatalf("SignBundleFileV4: %v", err)
	}
	if fp != KeyFingerprint(sshPub) {
		t.Fatal("returned fingerprint mismatch")
	}

	b, _ := LoadBundle(path)
	sec := b.Envs["prod"]
	if sec.Sig == nil || sec.Sig.By != fp {
		t.Fatalf("prod section not signed: %+v", sec.Sig)
	}

	reg := stubResolver{
		users:  map[string]ssh.PublicKey{fp: sshPub},
		levels: map[string]int{fp: 40},
	}
	if err := VerifySectionAuthzV4(human.Recipient, "prod", sec, 40, reg); err != nil {
		t.Fatalf("freshly signed v4 section must pass authz: %v", err)
	}
	sec.Entries["DB"] = sec.Entries["DB"] + "X"
	if err := VerifySectionAuthzV4(human.Recipient, "prod", sec, 40, reg); err == nil {
		t.Fatal("a post-sign tamper must fail v4 authz")
	}
}
