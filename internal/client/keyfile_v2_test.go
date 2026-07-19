package client

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/dawnbreather/gitseal/internal/crypto"
)

// --- KeyFile v2 (raw identity, no KEK) + mixed v1/v2 load ------------
//
// v2 stores the age identity DIRECTLY (private_key_b64), no KEK indirection — the
// broker-owned out-of-band keystore. v1 (wrapped_key_b64+kek_b64) still parses for
// the migration window. Both resolve to the SAME identity via KeyFile.Identity(),
// and LoadKeyDir returns identities keyed by pid (broker no longer holds KEKs).

func TestKeyFileV2_RoundTripAndIdentity(t *testing.T) {
	kp, _ := crypto.GenerateRepoKey()
	kf := NewKeyFileV2(338, kp.Identity)
	if kf.Version != "v2" || kf.ProjectID != 338 {
		t.Fatalf("bad v2 header: %+v", kf)
	}
	data, _ := json.Marshal(kf)
	got, err := ParseKeyFile(data)
	if err != nil {
		t.Fatalf("ParseKeyFile(v2): %v", err)
	}
	id, err := got.Identity()
	if err != nil {
		t.Fatalf("Identity(): %v", err)
	}
	if id != kp.Identity {
		t.Fatal("v2 identity round-trip mismatch")
	}
	if err := got.Verify(kp.Recipient); err != nil {
		t.Fatalf("v2 Verify against its recipient: %v", err)
	}
	if got.Verify("age1wrong") == nil {
		t.Fatal("v2 Verify must fail on recipient mismatch")
	}
}

// A v1 (wrapped+kek) and a v2 (raw) keyfile for the SAME keypair must resolve to
// the IDENTICAL identity — this is the migration equivalence guarantee (relocating
// 338 from v1 to v2 is lossless).
func TestKeyFile_V1V2Equivalence(t *testing.T) {
	kp, _ := crypto.GenerateRepoKey()
	kek, _ := crypto.GenerateKEK()
	wrapped, _ := crypto.WrapKey([]byte(kp.Identity), kek)

	v1 := NewKeyFile(338, wrapped, kek) // v1: wrapped + kek
	v2 := NewKeyFileV2(338, kp.Identity)

	id1, err := v1.Identity()
	if err != nil {
		t.Fatalf("v1 Identity: %v", err)
	}
	id2, err := v2.Identity()
	if err != nil {
		t.Fatalf("v2 Identity: %v", err)
	}
	if id1 != id2 || id1 != kp.Identity {
		t.Fatalf("v1/v2 must resolve to the same identity: v1=%q v2=%q want=%q", id1, id2, kp.Identity)
	}
}

func TestParseKeyFileV2_RejectsBad(t *testing.T) {
	// v2 missing private_key_b64
	bad := `{"version":"v2","project_id":1}`
	if _, err := ParseKeyFile([]byte(bad)); err == nil {
		t.Fatal("v2 without private_key_b64 must fail")
	}
	// v2 with a non-age private key
	badkey := `{"version":"v2","project_id":1,"private_key_b64":"` + base64.StdEncoding.EncodeToString([]byte("not-an-age-key")) + `"}`
	if _, err := ParseKeyFile([]byte(badkey)); err == nil {
		t.Fatal("v2 with a non-age private key must fail")
	}
}

// LoadKeyDir over a MIXED dir (one v1, one v2) resolves both to the right identity.
func TestLoadKeyDir_MixedV1V2(t *testing.T) {
	dir := t.TempDir()
	// v2 for 338
	kp338, _ := crypto.GenerateRepoKey()
	writeRaw(t, dir, 338, NewKeyFileV2(338, kp338.Identity))
	// v1 for 412
	kp412, _ := crypto.GenerateRepoKey()
	kek, _ := crypto.GenerateKEK()
	wrapped, _ := crypto.WrapKey([]byte(kp412.Identity), kek)
	writeRaw(t, dir, 412, NewKeyFile(412, wrapped, kek))

	ks, skipped, err := LoadKeyDir(dir)
	if err != nil {
		t.Fatalf("LoadKeyDir mixed: %v", err)
	}
	if len(skipped) != 0 {
		t.Fatalf("no skips expected: %v", skipped)
	}
	if ks.Identities[338] != kp338.Identity {
		t.Errorf("338 (v2) identity wrong")
	}
	if ks.Identities[412] != kp412.Identity {
		t.Errorf("412 (v1) identity wrong")
	}
}

func writeRaw(t *testing.T, dir string, pid int64, kf *KeyFile) {
	t.Helper()
	data, _ := json.Marshal(kf)
	if err := os.WriteFile(filepath.Join(dir, KeyFileName(pid)), data, 0600); err != nil {
		t.Fatal(err)
	}
}
