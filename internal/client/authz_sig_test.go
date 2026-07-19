package client

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// --- signature-enforced write-authz verdict (Stage B) ----------------
//
// VerifySectionAuthz decides, for ONE changed env section, whether the change may
// land: the section MUST carry a signature that (a) verifies against the signer's
// registered SSH pubkey, (b) the signer is a REGISTERED user, (c) that user has
// >= env_min_level LIVE on the project. Missing/invalid/unregistered/under-level →
// fail closed. Folds the write-authz into attribution: the signer's live
// level IS the authorization.

func mkSignedSection(t *testing.T, projectID int64, env string, entries map[string]string) (EnvSection, ssh.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := ssh.NewSignerFromKey(priv)
	sshPub, _ := ssh.NewPublicKey(pub)
	msg := CanonicalSectionBytes(projectID, env, entries)
	sigB64, err := SignSSHSig(signer, msg)
	if err != nil {
		t.Fatal(err)
	}
	sec := EnvSection{Entries: entries, Sig: &EnvSectionSig{By: KeyFingerprint(sshPub), Sig: sigB64}}
	return sec, sshPub, priv
}

// registry + level resolver stubs
type stubResolver struct {
	users  map[string]ssh.PublicKey // fingerprint -> pubkey (registered users)
	levels map[string]int           // fingerprint -> live project level
}

func (s stubResolver) PubKeyFor(fp string) (ssh.PublicKey, bool) { p, ok := s.users[fp]; return p, ok }
func (s stubResolver) LiveLevelFor(fp string) (int, error)       { return s.levels[fp], nil }

func TestVerifySectionAuthz(t *testing.T) {
	const pid = 338
	entries := map[string]string{"DB": "ct1", "API": "ct2"}
	sec, pub, _ := mkSignedSection(t, pid, "prod", entries)
	fp := KeyFingerprint(pub)

	reg := stubResolver{
		users:  map[string]ssh.PublicKey{fp: pub},
		levels: map[string]int{fp: 40},
	}

	// happy: registered signer, valid sig, level 40 >= prod min 40
	if err := VerifySectionAuthz(pid, "prod", sec, 40, reg); err != nil {
		t.Fatalf("valid signed section by an authorized user must pass: %v", err)
	}

	// under-level: signer has 30, prod needs 40 → deny
	regLow := stubResolver{users: map[string]ssh.PublicKey{fp: pub}, levels: map[string]int{fp: 30}}
	if err := VerifySectionAuthz(pid, "prod", sec, 40, regLow); err == nil {
		t.Fatal("signer below env_min_level must be denied")
	}

	// unregistered signer → deny
	regEmpty := stubResolver{users: map[string]ssh.PublicKey{}, levels: map[string]int{}}
	if err := VerifySectionAuthz(pid, "prod", sec, 40, regEmpty); err == nil {
		t.Fatal("unregistered signer must be denied")
	}

	// MISSING signature → deny (fail closed)
	unsigned := EnvSection{Entries: entries}
	if err := VerifySectionAuthz(pid, "prod", unsigned, 40, reg); err == nil {
		t.Fatal("missing signature must be denied")
	} else if !strings.Contains(err.Error(), "signature") {
		t.Errorf("error should mention the missing signature: %v", err)
	}

	// TAMPERED entries (sig no longer matches canonical bytes) → deny
	tampered := EnvSection{Entries: map[string]string{"DB": "ct1-EVIL", "API": "ct2"}, Sig: sec.Sig}
	if err := VerifySectionAuthz(pid, "prod", tampered, 40, reg); err == nil {
		t.Fatal("a tampered section (sig over old bytes) must be denied")
	}

	// signature `By` fingerprint that doesn't match the actual signing key in the
	// registry (attacker claims someone else's fp) → the registered pubkey won't
	// verify the sig → deny.
	otherPubRaw, _, _ := ed25519.GenerateKey(rand.Reader)
	otherPub, _ := ssh.NewPublicKey(otherPubRaw)
	regSpoof := stubResolver{users: map[string]ssh.PublicKey{fp: otherPub}, levels: map[string]int{fp: 40}}
	if err := VerifySectionAuthz(pid, "prod", sec, 40, regSpoof); err == nil {
		t.Fatal("sig must not verify when the registry pubkey for that fp differs")
	}
}
