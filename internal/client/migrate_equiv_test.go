package client

import (
	"encoding/base64"
	"testing"

	"github.com/dawnbreather/gitseal/internal/crypto"
)

// TestMigrateEquivalence proves the relocation is LOSSLESS at the unit
// level: a v1 (KEK-wrapped) key file and the v2 (raw) key file derived by
// unwrapping it resolve to the SAME identity AND the SAME public recipient. This
// is the guarantee migrate-keystore relies on for repo 338 (375 sealed entries
// that cannot be re-sealed — its keypair MUST survive the relocation unchanged).
func TestMigrateEquivalence(t *testing.T) {
	kp, _ := crypto.GenerateRepoKey()
	kek, _ := crypto.GenerateKEK()
	wrapped, _ := crypto.WrapKey([]byte(kp.Identity), kek)

	// v1 as it exists in the legacy monolith
	v1 := NewKeyFile(338, wrapped, kek)

	// migration: unwrap v1 → raw identity → v2 (what admin migrate-keystore does)
	id1, err := v1.Identity()
	if err != nil {
		t.Fatalf("v1 Identity: %v", err)
	}
	v2 := NewKeyFileV2(338, id1)

	id2, err := v2.Identity()
	if err != nil {
		t.Fatalf("v2 Identity: %v", err)
	}
	// identity string survives byte-for-byte
	if id1 != id2 || id2 != kp.Identity {
		t.Fatalf("identity not preserved across migration: v1=%q v2=%q orig=%q", id1, id2, kp.Identity)
	}
	// and the derived RECIPIENT matches the original (decrypt ability preserved)
	if err := v2.Verify(kp.Recipient); err != nil {
		t.Fatalf("migrated v2 key must verify against the ORIGINAL recipient: %v", err)
	}
	// sanity: the v2 private_key_b64 decodes to exactly the original identity string
	raw, _ := base64.StdEncoding.DecodeString(v2.PrivateKeyB64)
	if string(raw) != kp.Identity {
		t.Fatal("v2 private_key_b64 does not decode to the original AGE-SECRET-KEY string")
	}
}
