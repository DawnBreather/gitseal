package crypto

import (
	"bytes"
	"strings"
	"testing"
)

// v4 envelope: the anti-splice discriminator embedded in the AEAD is
// the project PUBLIC KEY (recipient), not the numeric project_id. This lets
// .seald/repo.yaml collapse to just `recipient:` — the pubkey is the sole project
// identity. v1-v3 (numeric) stay byte-unchanged and still verify.

func TestV4SealUnsealByKeyRoundTrip(t *testing.T) {
	kp, _ := GenerateRepoKey()
	pt := []byte("postgres://user:pw@db:5432/app")

	ct, err := SealMultiV4(pt, []string{kp.Recipient}, kp.Recipient, "DATABASE_URL", DefaultMinAccessLevel)
	if err != nil {
		t.Fatalf("SealMultiV4: %v", err)
	}
	if bytes.Contains(ct, pt) {
		t.Fatal("ciphertext contains plaintext")
	}

	got, lvl, err := UnsealVerifiedByKey(ct, []byte(kp.Identity), kp.Recipient)
	if err != nil {
		t.Fatalf("UnsealVerifiedByKey: %v", err)
	}
	if !bytes.Equal(got, pt) {
		t.Fatalf("round-trip mismatch: %q", got)
	}
	if lvl != DefaultMinAccessLevel {
		t.Fatalf("level = %d", lvl)
	}
}

// The embedded pubkey must be re-asserted: opening a v4 blob "as" a different
// pubkey fails even if the decrypting identity is correct (anti-splice) —
// mirrors the numeric project_id mismatch guard.
func TestV4EmbeddedPubkeyMismatchRejected(t *testing.T) {
	owner, _ := GenerateRepoKey() // the true owner (embedded)
	other, _ := GenerateRepoKey() // a different project's pubkey

	// Seal to a shared "cluster" recipient so the identity CAN decrypt, but embed
	// the owner's pubkey. Then ask to open it as `other` → must be rejected.
	cluster, _ := GenerateRepoKey()
	ct, err := SealMultiV4([]byte("secret"), []string{cluster.Recipient}, owner.Recipient, "X", DefaultMinAccessLevel)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	_, _, err = UnsealVerifiedByKey(ct, []byte(cluster.Identity), other.Recipient)
	if err == nil {
		t.Fatal("expected embedded-pubkey mismatch rejection, got success")
	}
	if !strings.Contains(err.Error(), "recipient") && !strings.Contains(err.Error(), "pubkey") {
		t.Fatalf("expected pubkey-mismatch error, got: %v", err)
	}
	// the true owner-key holder opening it as the owner pubkey succeeds
	if _, _, err := UnsealVerifiedByKey(ct, []byte(cluster.Identity), owner.Recipient); err != nil {
		t.Fatalf("owner-pubkey open must succeed: %v", err)
	}
}

// A v4 blob carries NO numeric project-id header, so the legacy numeric
// UnsealVerified must reject it (missing id) rather than silently accept — a v4
// blob is only openable via the by-key path. Fail closed.
func TestV4RejectedByNumericUnseal(t *testing.T) {
	kp, _ := GenerateRepoKey()
	ct, _ := SealMultiV4([]byte("s"), []string{kp.Recipient}, kp.Recipient, "X", DefaultMinAccessLevel)
	if _, _, err := UnsealVerified(ct, []byte(kp.Identity), 338); err == nil {
		t.Fatal("numeric UnsealVerified must reject a v4 (pubkey) envelope")
	}
}

// A v1-v3 numeric blob must be rejected by the by-key path (no recipient header).
func TestNumericRejectedByV4Unseal(t *testing.T) {
	kp, _ := GenerateRepoKey()
	ct, _ := Seal([]byte("s"), kp.Recipient, 338, "X")
	if _, _, err := UnsealVerifiedByKey(ct, []byte(kp.Identity), kp.Recipient); err == nil {
		t.Fatal("by-key UnsealVerifiedByKey must reject a numeric (v1-v3) envelope")
	}
}

// EnvelopeIsV4 detects which discriminator an already-decrypted-or-raw blob uses,
// so readers can dispatch. (Broker/materializer decrypt first then re-assert, but
// a cheap kind probe keeps error messages clear.)
func TestV4TamperOnEmbeddedPubkeyFails(t *testing.T) {
	kp, _ := GenerateRepoKey()
	ct, _ := SealMultiV4([]byte("secret"), []string{kp.Recipient}, kp.Recipient, "X", DefaultMinAccessLevel)
	ct[len(ct)/2] ^= 0xFF
	if _, _, err := UnsealVerifiedByKey(ct, []byte(kp.Identity), kp.Recipient); err == nil {
		t.Fatal("tampered v4 ciphertext must fail")
	}
}
