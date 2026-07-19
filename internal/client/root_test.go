package client

import (
	"strings"
	"testing"

	"filippo.io/age"
)

// GenRoot makes a seald-root age keypair and Shamir-splits the private key into
// N shares (threshold T). Any T shares reconstruct it; T-1 do not.
func TestGenRootShamirRoundTrip(t *testing.T) {
	recipient, shares, err := GenRoot(3, 2)
	if err != nil {
		t.Fatalf("GenRoot: %v", err)
	}
	if recipient == "" || !strings.HasPrefix(recipient, "age1") {
		t.Fatalf("bad recipient: %q", recipient)
	}
	if len(shares) != 3 {
		t.Fatalf("want 3 shares, got %d", len(shares))
	}
	// 2 shares reconstruct the identity.
	id, err := CombineShares(shares[:2])
	if err != nil {
		t.Fatalf("CombineShares(2): %v", err)
	}
	if !strings.HasPrefix(id, "AGE-SECRET-KEY-") {
		t.Fatalf("reconstructed identity malformed: %q", id[:20])
	}
	// A different 2-of-3 subset also reconstructs the same identity.
	id2, err := CombineShares([]string{shares[0], shares[2]})
	if err != nil || id2 != id {
		t.Fatalf("different 2-subset must reconstruct same identity: %v", err)
	}
	// 1 share must NOT reconstruct it.
	if got, err := CombineShares(shares[:1]); err == nil && got == id {
		t.Fatal("1 share reconstructed the secret — threshold broken")
	}

	// SEED-PATH PROOF: the reconstructed identity must parse as an age X25519 key
	// and its public recipient must EXACTLY match GenRoot's recipient. This is what
	// `sealdctl admin combine --verify` relies on to let an operator confirm the
	// seeded materializer identity matches the committed repo.yaml clusters entry.
	parsed, err := age.ParseX25519Identity(id)
	if err != nil {
		t.Fatalf("reconstructed identity did not parse as an age X25519 key: %v", err)
	}
	if got := parsed.Recipient().String(); got != recipient {
		t.Fatalf("recipient mismatch: reconstructed %q != GenRoot %q", got, recipient)
	}
}
