package crypto

import (
	"bytes"
	"strings"
	"testing"
)

// --- SEAL / UNSEAL round trip -------------------------------------------------

func TestSealUnsealRoundTrip(t *testing.T) {
	kp, err := GenerateRepoKey()
	if err != nil {
		t.Fatalf("GenerateRepoKey: %v", err)
	}
	plaintext := []byte("postgres://user:pw@db:5432/app")

	ct, err := Seal(plaintext, kp.Recipient, 412, "DATABASE_URL")
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if bytes.Contains(ct, plaintext) {
		t.Fatal("ciphertext contains plaintext")
	}

	got, err := Unseal(ct, []byte(kp.Identity), 412)
	if err != nil {
		t.Fatalf("Unseal: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("round-trip mismatch: got %q want %q", got, plaintext)
	}
}

// --- R4: wrong repo key cannot decrypt (cross-repo isolation, crypto layer) ---

func TestUnsealWithWrongRepoKeyFails(t *testing.T) {
	a, _ := GenerateRepoKey()
	b, _ := GenerateRepoKey()

	ct, err := Seal([]byte("secret-A"), a.Recipient, 100, "X")
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	// Try to open repo A's blob with repo B's identity — must fail (AEAD).
	if _, err := Unseal(ct, []byte(b.Identity), 100); err == nil {
		t.Fatal("expected failure decrypting A's ciphertext with B's key, got success")
	}
}

// --- R4: embedded project_id mismatch is rejected even with the right key -----

func TestUnsealEmbeddedProjectIDMismatchRejected(t *testing.T) {
	kp, _ := GenerateRepoKey()
	// Sealed for project 100, but the broker is asked to open it for project 200.
	ct, err := Seal([]byte("secret"), kp.Recipient, 100, "X")
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	_, err = Unseal(ct, []byte(kp.Identity), 200)
	if err == nil {
		t.Fatal("expected project_id mismatch rejection, got success")
	}
	if !strings.Contains(err.Error(), "project") {
		t.Fatalf("expected project-id mismatch error, got: %v", err)
	}
}

// --- tamper rejection ---------------------------------------------------------

func TestUnsealTamperedCiphertextFails(t *testing.T) {
	kp, _ := GenerateRepoKey()
	ct, _ := Seal([]byte("secret"), kp.Recipient, 1, "X")
	ct[len(ct)/2] ^= 0xFF // flip a byte
	if _, err := Unseal(ct, []byte(kp.Identity), 1); err == nil {
		t.Fatal("expected tamper to fail decryption, got success")
	}
}

// --- KEK envelope: wrap / unwrap the repo private key -------------------------

func TestKEKWrapUnwrapRoundTrip(t *testing.T) {
	kek, err := GenerateKEK()
	if err != nil {
		t.Fatalf("GenerateKEK: %v", err)
	}
	kp, _ := GenerateRepoKey()
	secret := []byte(kp.Identity)

	wrapped, err := WrapKey(secret, kek)
	if err != nil {
		t.Fatalf("WrapKey: %v", err)
	}
	if bytes.Contains(wrapped, secret) {
		t.Fatal("wrapped key contains the plaintext key")
	}

	got, err := UnwrapKey(wrapped, kek)
	if err != nil {
		t.Fatalf("UnwrapKey: %v", err)
	}
	if !bytes.Equal(got, secret) {
		t.Fatalf("KEK round-trip mismatch")
	}
}

func TestUnwrapWithWrongKEKFails(t *testing.T) {
	k1, _ := GenerateKEK()
	k2, _ := GenerateKEK()
	wrapped, _ := WrapKey([]byte("AGE-SECRET-KEY-1abc"), k1)
	if _, err := UnwrapKey(wrapped, k2); err == nil {
		t.Fatal("expected unwrap with wrong KEK to fail, got success")
	}
}
