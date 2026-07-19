package client

import (
	"crypto/ed25519"
	"crypto/rand"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/dawnbreather/gitseal/internal/crypto"
)

// TestSealSignVerifyRoundTrip: seal (v3) → SignBundleFile → the signed sections
// pass VerifySectionAuthz for the signer (registered, authorized), and a tampered
// entry afterward fails. This is the full Stage-B attribution loop end to end.
func TestSealSignVerifyRoundTrip(t *testing.T) {
	human, _ := crypto.GenerateRepoKey()
	g, _ := crypto.GenerateRepoKey()
	path := filepath.Join(t.TempDir(), "auth.app.json")
	clusters := map[string]string{"example": g.Recipient}
	envCluster := map[string]string{"prod": "example"}
	if _, err := SealBundleV2(path, human.Recipient, clusters, envCluster, 338, 40,
		map[string]map[string]string{"prod": {"DB": "v", "API": "w"}}); err != nil {
		t.Fatal(err)
	}

	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	sshPub, _ := ssh.NewPublicKey(pub)
	inSigner, _ := ssh.NewSignerFromKey(priv)
	signer := NewSSHSignerFrom(inSigner)

	fp, err := SignBundleFile(path, 338, signer)
	if err != nil {
		t.Fatalf("SignBundleFile: %v", err)
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
	if err := VerifySectionAuthz(338, "prod", sec, 40, reg); err != nil {
		t.Fatalf("freshly signed section must pass authz: %v", err)
	}

	// tamper an entry after signing → authz fails (canonical bytes changed)
	sec.Entries["DB"] = sec.Entries["DB"] + "X"
	if err := VerifySectionAuthz(338, "prod", sec, 40, reg); err == nil {
		t.Fatal("a post-sign tamper must fail authz")
	}
}

// (TestGitLabUserHasKey removed with GitLabUserHasKey in — user identity
// is now the broker's GitLab-backed index, not a manual onboarding verify.)
