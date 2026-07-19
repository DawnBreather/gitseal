package broker

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/dawnbreather/gitseal/internal/client"
)

// --- SSH challenge-auth resolution (Stage D) -------------------------
//
// authViaSSH verifies a challenge-response and resolves it to a gitlab user_id via
// the registry: (1) the nonce must be live+single-use, (2) the signature must
// verify against the PRESENTED fingerprint's key, (3) that fingerprint must be a
// REGISTERED user (→ user_id). It does NOT do the live member check — that stays
// in the shared unseal path (leg D). Fail closed on every step.

func signNonce(t *testing.T, priv ed25519.PrivateKey, nonce string) (fp, sig string) {
	t.Helper()
	signer, _ := ssh.NewSignerFromKey(priv)
	pub, _ := ssh.NewPublicKey(priv.Public().(ed25519.PublicKey))
	s, err := client.SignSSHSig(signer, []byte(nonce))
	if err != nil {
		t.Fatal(err)
	}
	return ssh.FingerprintSHA256(pub), s
}

func TestAuthViaSSH(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	sshPub, _ := ssh.NewPublicKey(pub)
	fp := ssh.FingerprintSHA256(sshPub)

	b := &Broker{
		Challenges: NewChallengeStore(time.Minute),
		Registry: &Registry{
			Projects: map[string]ProjectEntry{},
			Users:    map[string]int64{fp: 87},
		},
	}
	// The registry must also hold the PUBKEY to verify against. Users maps fp→uid;
	// the pubkey is resolved from a parallel map — store it via UserKeys.
	b.Registry.UserKeys = map[string]string{fp: string(ssh.MarshalAuthorizedKey(sshPub))}

	nonce := b.Challenges.Issue()
	gotFp, sig := signNonce(t, priv, nonce)
	if gotFp != fp {
		t.Fatal("fingerprint mismatch in test setup")
	}

	// happy path → resolves user_id 87
	uid, err := b.authViaSSH(fp, nonce, sig)
	if err != nil || uid != 87 {
		t.Fatalf("authViaSSH happy path: uid=%d err=%v", uid, err)
	}

	// replay: same nonce again → consumed → deny
	if _, err := b.authViaSSH(fp, nonce, sig); err == nil {
		t.Fatal("replayed nonce must be denied")
	}

	// unregistered fingerprint → deny
	n2 := b.Challenges.Issue()
	_, sig2 := signNonce(t, priv, n2)
	b2 := &Broker{Challenges: b.Challenges, Registry: &Registry{Users: map[string]int64{}, UserKeys: map[string]string{}}}
	if _, err := b2.authViaSSH(fp, n2, sig2); err == nil {
		t.Fatal("unregistered fingerprint must be denied")
	}

	// tampered signature (sign a DIFFERENT nonce) → deny
	n3 := b.Challenges.Issue()
	_, sigOther := signNonce(t, priv, "some-other-nonce")
	if _, err := b.authViaSSH(fp, n3, sigOther); err == nil {
		t.Fatal("signature over a different nonce must be denied")
	}
}
