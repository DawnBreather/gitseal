package client

import (
	"testing"

	"github.com/dawnbreather/gitseal/internal/crypto"
)

// AddRepoKey generates a repo keypair + KEK, wraps the private key, and returns
// the public recipient + a bundle entry the broker can load. The private key is
// never returned in the clear beyond the wrapped form.
func TestAddRepoKeyProducesLoadableBundleEntry(t *testing.T) {
	recipient, entry, err := AddRepoKey()
	if err != nil {
		t.Fatalf("AddRepoKey: %v", err)
	}
	if recipient == "" {
		t.Fatal("empty recipient")
	}
	// The wrapped key in the entry must unwrap and be able to unseal a blob
	// sealed to the returned recipient.
	wrapped := mustB64(t, entry.WrappedKeyB64)
	kek := mustB64(t, entry.KEKB64)
	identity, err := crypto.UnwrapKey(wrapped, kek)
	if err != nil {
		t.Fatalf("unwrap: %v", err)
	}
	ct, err := crypto.Seal([]byte("hello"), recipient, 412, "X")
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	got, err := crypto.Unseal(ct, identity, 412)
	if err != nil || string(got) != "hello" {
		t.Fatalf("round-trip via AddRepoKey output failed: %v / %q", err, got)
	}
}

func mustB64(t *testing.T, s string) []byte {
	t.Helper()
	b, err := b64decode(s)
	if err != nil {
		t.Fatalf("b64: %v", err)
	}
	return b
}
