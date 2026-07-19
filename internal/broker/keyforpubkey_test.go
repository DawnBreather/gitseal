package broker

import (
	"testing"

	"github.com/dawnbreather/gitseal/internal/crypto"
)

// v4: a v4 unseal request carries the project PUBKEY (recipient), not
// the numeric project_id. keyForPubkey resolves that pubkey → (identity, numeric
// project_id) from the loaded keystore, so the broker can still (a) pick the right
// private key and (b) do the live members/all/:project_id check. This keeps the
// broker registry-INDEPENDENT for unseal: the numeric id comes from the keystore
// file the key was loaded from, not from a registry lookup.
func TestKeyForPubkey_ResolvesIdentityAndProjectID(t *testing.T) {
	a, _ := crypto.GenerateRepoKey()
	b, _ := crypto.GenerateRepoKey()
	br := &Broker{Keys: &KeyStore{Identities: map[int64]string{
		338: a.Identity,
		412: b.Identity,
	}}}

	id, pid, ok := br.keyForPubkey(a.Recipient)
	if !ok {
		t.Fatal("pubkey A must resolve")
	}
	if id != a.Identity || pid != 338 {
		t.Fatalf("resolved wrong key/pid: pid=%d", pid)
	}
	id2, pid2, ok := br.keyForPubkey(b.Recipient)
	if !ok || id2 != b.Identity || pid2 != 412 {
		t.Fatalf("pubkey B resolve wrong: pid=%d ok=%v", pid2, ok)
	}

	// an unknown pubkey does not resolve (fail closed)
	other, _ := crypto.GenerateRepoKey()
	if _, _, ok := br.keyForPubkey(other.Recipient); ok {
		t.Fatal("unknown pubkey must not resolve")
	}
	// a malformed pubkey does not resolve (no panic)
	if _, _, ok := br.keyForPubkey("not-an-age-key"); ok {
		t.Fatal("malformed pubkey must not resolve")
	}
}
