package crypto

import (
	"strings"
	"testing"
)

// testRecip generates a fresh age recipient for stanza-count tests.
func testRecip(t *testing.T) string {
	t.Helper()
	k, err := GenerateRepoKey()
	if err != nil {
		t.Fatalf("GenerateRepoKey: %v", err)
	}
	return k.Recipient
}

// TestRecipientStanzaCountSingle: SealWithLevel seals to one recipient → 1 stanza.
func TestRecipientStanzaCountSingle(t *testing.T) {
	ct, err := SealWithLevel([]byte("hello"), testRecip(t), 338, "K", DefaultMinAccessLevel)
	if err != nil {
		t.Fatalf("SealWithLevel: %v", err)
	}
	n, err := RecipientStanzaCount(ct)
	if err != nil {
		t.Fatalf("RecipientStanzaCount: %v", err)
	}
	if n != 1 {
		t.Fatalf("stanza count = %d, want 1", n)
	}
}

// TestRecipientStanzaCountTwo: SealMulti to [human, cluster] → 2 stanzas
// (the materializer's per-cluster isolation shape).
func TestRecipientStanzaCountTwo(t *testing.T) {
	ct, err := SealMulti([]byte("hello"), []string{testRecip(t), testRecip(t)}, 338, "K", DefaultMinAccessLevel)
	if err != nil {
		t.Fatalf("SealMulti: %v", err)
	}
	n, err := RecipientStanzaCount(ct)
	if err != nil {
		t.Fatalf("RecipientStanzaCount: %v", err)
	}
	if n != 2 {
		t.Fatalf("stanza count = %d, want 2", n)
	}
}

// TestRecipientStanzaCountThree: the FORBIDDEN cross-cluster over-seal
// [human, G, S] → 3 stanzas (verify uses count!=2 to catch this).
func TestRecipientStanzaCountThree(t *testing.T) {
	ct, err := SealMulti([]byte("hello"), []string{testRecip(t), testRecip(t), testRecip(t)}, 338, "K", DefaultMinAccessLevel)
	if err != nil {
		t.Fatalf("SealMulti: %v", err)
	}
	n, err := RecipientStanzaCount(ct)
	if err != nil {
		t.Fatalf("RecipientStanzaCount: %v", err)
	}
	if n != 3 {
		t.Fatalf("stanza count = %d, want 3", n)
	}
}

// TestRecipientStanzaCountGarbage: non-age bytes → error.
func TestRecipientStanzaCountGarbage(t *testing.T) {
	if _, err := RecipientStanzaCount([]byte("not an age file at all")); err == nil {
		t.Fatalf("expected error on garbage input, got nil")
	}
	if _, err := RecipientStanzaCount(nil); err == nil {
		t.Fatalf("expected error on nil input, got nil")
	}
	// A truncated header (intro but no footer) must also error.
	if _, err := RecipientStanzaCount([]byte("age-encryption.org/v1\n-> X25519 abc\n")); err == nil {
		t.Fatalf("expected error on truncated header, got nil")
	}
}

// TestRecipientStanzaCountManyRecipients: a larger fan-out still counts exactly.
func TestRecipientStanzaCountManyRecipients(t *testing.T) {
	recips := []string{testRecip(t), testRecip(t), testRecip(t), testRecip(t), testRecip(t)}
	ct, err := SealMulti([]byte(strings.Repeat("x", 4096)), recips, 338, "K", DefaultMinAccessLevel)
	if err != nil {
		t.Fatalf("SealMulti: %v", err)
	}
	n, err := RecipientStanzaCount(ct)
	if err != nil {
		t.Fatalf("RecipientStanzaCount: %v", err)
	}
	if n != len(recips) {
		t.Fatalf("stanza count = %d, want %d", n, len(recips))
	}
}
