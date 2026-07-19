package broker

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// authViaSSH resolves the signer from the IdentityIndex (built from
// GitLab), not a hand-maintained registry. A fingerprint present in the index
// authenticates with no `admin onboard-user` / users.json entry.
func TestAuthViaSSH_FromIndex(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	sshPub, _ := ssh.NewPublicKey(pub)
	fp := ssh.FingerprintSHA256(sshPub)
	line := string(ssh.MarshalAuthorizedKey(sshPub))
	line = line[:len(line)-1]

	idx := NewIdentityIndex()
	idx.Swap(map[string]IndexEntry{fp: {UserID: 87, PubKey: line}})

	b := &Broker{
		Challenges: NewChallengeStore(time.Minute),
		Identity:   idx,
		// NOTE: no Registry.Users / UserKeys — the index is the sole source.
	}

	nonce := b.Challenges.Issue()
	gotFp, sig := signNonce(t, priv, nonce)
	if gotFp != fp {
		t.Fatal("setup fp mismatch")
	}
	uid, err := b.authViaSSH(fp, nonce, sig)
	if err != nil || uid != 87 {
		t.Fatalf("index-backed authViaSSH: uid=%d err=%v", uid, err)
	}

	// a fingerprint NOT in the index is denied (fail-closed), even with a valid
	// signature over a live nonce.
	pub2, priv2, _ := ed25519.GenerateKey(rand.Reader)
	sshPub2, _ := ssh.NewPublicKey(pub2)
	fp2 := ssh.FingerprintSHA256(sshPub2)
	n2 := b.Challenges.Issue()
	_, sig2 := signNonce(t, priv2, n2)
	if _, err := b.authViaSSH(fp2, n2, sig2); err == nil {
		t.Fatal("fingerprint absent from the index must be denied")
	}
}

// signerPubKey resolves a fingerprint's authorized-key line preferring the index,
// falling back to the legacy registry (migration window). Used by both authViaSSH
// and /v1/signer/resolve so they share one resolution rule.
func TestResolveSignerPrefersIndex(t *testing.T) {
	// index has the fp; registry does not → resolves from the index.
	line, ifp := keyLine(t)
	idx := NewIdentityIndex()
	idx.Swap(map[string]IndexEntry{ifp: {UserID: 55, PubKey: line}})
	b := &Broker{Identity: idx, Registry: &Registry{Users: map[string]int64{}, UserKeys: map[string]string{}}}
	if uid, pk, ok := b.resolveSigner(ifp); !ok || uid != 55 || pk != line {
		t.Fatalf("index resolution wrong: %d %q %v", uid, pk, ok)
	}

	// only the legacy registry has it (migration fallback) → still resolves.
	rline, rfp := keyLine(t)
	b2 := &Broker{
		Identity: NewIdentityIndex(),
		Registry: &Registry{Users: map[string]int64{rfp: 99}, UserKeys: map[string]string{rfp: rline}},
	}
	if uid, pk, ok := b2.resolveSigner(rfp); !ok || uid != 99 || pk != rline {
		t.Fatalf("registry fallback wrong: %d %q %v", uid, pk, ok)
	}

	// neither has it → not resolved (fail closed).
	if _, _, ok := b2.resolveSigner("SHA256:nobody"); ok {
		t.Fatal("unknown fp must not resolve")
	}
}
