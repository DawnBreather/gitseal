package broker

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/dawnbreather/gitseal/internal/client"
	"github.com/dawnbreather/gitseal/internal/crypto"
)

// TestV2Keystore_DecryptRoundTrip is the load-bearing security proof for
// a secret sealed to a repo's recipient decrypts correctly when the broker loads
// the key from a v2 (raw-identity) keyfile and passes it STRAIGHT to
// crypto.UnsealVerified — i.e. removing the KEK unwrap step did not break the
// unseal crypto. It also confirms the project_id binding still holds.
func TestV2Keystore_DecryptRoundTrip(t *testing.T) {
	kp, _ := crypto.GenerateRepoKey()
	const pid int64 = 338

	// seal a secret to the repo's recipient (offline, as sealdctl does)
	plaintext := []byte("s3cr3t-value")
	ct, err := crypto.SealWithLevel(plaintext, kp.Recipient, pid, "API_KEY", 40)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}

	// write a v2 keyfile, load it through the broker's directory loader
	dir := t.TempDir()
	data, _ := json.Marshal(client.NewKeyFileV2(pid, kp.Identity))
	os.WriteFile(filepath.Join(dir, client.KeyFileName(pid)), data, 0600)
	ks, skipped, err := LoadKeyStoreDir(dir)
	if err != nil || len(skipped) != 0 {
		t.Fatalf("LoadKeyStoreDir: %v skipped=%v", err, skipped)
	}
	b := &Broker{Keys: ks}

	// the broker resolves the identity (no unwrap) and UnsealVerified decrypts it
	identity, ok := b.keyFor(pid)
	if !ok {
		t.Fatal("keyFor(338) missing")
	}
	got, level, err := crypto.UnsealVerified(ct, []byte(identity), pid)
	if err != nil {
		t.Fatalf("UnsealVerified with v2-loaded identity: %v", err)
	}
	if string(got) != string(plaintext) {
		t.Fatalf("decrypt mismatch: got %q want %q", got, plaintext)
	}
	if level != 40 {
		t.Fatalf("embedded level = %d, want 40", level)
	}

	// wrong project_id must still be rejected (binding intact)
	if _, _, err := crypto.UnsealVerified(ct, []byte(identity), 999); err == nil {
		t.Fatal("UnsealVerified must reject a wrong project_id even with the right key")
	}
}
