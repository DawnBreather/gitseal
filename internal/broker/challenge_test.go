package broker

import (
	"testing"
	"time"
)

// --- SSH challenge nonce store (Stage D) -----------------------------
//
// The broker issues a single-use, short-TTL nonce; the caller SSH-signs it and
// presents (fingerprint, nonce, signature) to unseal. The nonce store makes the
// signed proof non-replayable: a nonce is consumed on first use and expires.

func TestChallengeStore_IssueConsumeOnce(t *testing.T) {
	cs := NewChallengeStore(1 * time.Minute)
	n := cs.Issue()
	if n == "" {
		t.Fatal("Issue must return a non-empty nonce")
	}
	// first consume succeeds
	if !cs.Consume(n) {
		t.Fatal("first Consume must succeed")
	}
	// second consume of the SAME nonce fails (single-use → no replay)
	if cs.Consume(n) {
		t.Fatal("second Consume of the same nonce must fail (replay)")
	}
	// an unknown nonce fails
	if cs.Consume("never-issued") {
		t.Fatal("unknown nonce must not consume")
	}
}

func TestChallengeStore_Expiry(t *testing.T) {
	cs := NewChallengeStore(10 * time.Millisecond)
	n := cs.Issue()
	time.Sleep(25 * time.Millisecond)
	if cs.Consume(n) {
		t.Fatal("an expired nonce must not consume")
	}
}

// Nonces are unique across issues (no collisions in a small batch).
func TestChallengeStore_Unique(t *testing.T) {
	cs := NewChallengeStore(time.Minute)
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		n := cs.Issue()
		if seen[n] {
			t.Fatalf("duplicate nonce issued: %q", n)
		}
		seen[n] = true
	}
}
