package broker

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/dawnbreather/gitseal/internal/crypto"
)

// The broker loads its KeyStore from a bundle file: a JSON map of
// {project_id: {wrapped_key_b64, kek_b64}}. In production the bundle file is
// produced by decrypting the seald-root-encrypted, bitnami-sealed Secret; here we
// test the parser directly.
func TestLoadKeyStoreFromBundle(t *testing.T) {
	kek, _ := crypto.GenerateKEK()
	kp, _ := crypto.GenerateRepoKey()
	wrapped, _ := crypto.WrapKey([]byte(kp.Identity), kek)

	bundle := map[string]bundleEntry{
		"412": {
			WrappedKeyB64: base64.StdEncoding.EncodeToString(wrapped),
			KEKB64:        base64.StdEncoding.EncodeToString(kek),
		},
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "bundle.json")
	data, _ := json.Marshal(bundle)
	os.WriteFile(path, data, 0600)

	ks, err := LoadKeyStore(path)
	if err != nil {
		t.Fatalf("LoadKeyStore: %v", err)
	}
	// LoadKeyStore now unwraps the legacy monolith to raw identities:
	// the loaded identity must equal the original.
	if got, ok := ks.Identities[412]; !ok || got != kp.Identity {
		t.Fatalf("project 412 identity missing or wrong: ok=%v", ok)
	}
}

func TestLoadKeyStoreMissingFileErrors(t *testing.T) {
	if _, err := LoadKeyStore("/nonexistent/bundle.json"); err == nil {
		t.Fatal("expected error loading missing bundle")
	}
}
