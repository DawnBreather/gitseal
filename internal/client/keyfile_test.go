package client

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dawnbreather/gitseal/internal/crypto"
)

// --- per-repo key file model (Stage 1/2: dissolve the monolith) ----------------
//
// A KeyFile is one repo's KEK-wrapped age identity, self-describing (carries its
// own version + project_id), stored as <project_id>.key.json. The broker reads a
// DIRECTORY of these instead of one monolithic bundle.json, so one bad file can
// no longer abort the whole fleet. This test pins the file's round-trip + the
// offline verify (unwrap-back) that the CI gate and onboard self-check rely on.

func TestKeyFile_RoundTripAndVerify(t *testing.T) {
	kp, _ := crypto.GenerateRepoKey()
	kek, _ := crypto.GenerateKEK()
	wrapped, _ := crypto.WrapKey([]byte(kp.Identity), kek)

	kf := NewKeyFile(338, wrapped, kek) // v1 (KEK-wrapped) — still supported for the migration window
	if kf.Version != KeyFileVersionV1 || kf.ProjectID != 338 {
		t.Fatalf("bad header: %+v", kf)
	}

	// marshal → parse round-trips
	data, err := json.Marshal(kf)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseKeyFile(data)
	if err != nil {
		t.Fatalf("ParseKeyFile: %v", err)
	}
	if got.ProjectID != 338 {
		t.Fatalf("project_id lost: %+v", got)
	}

	// VerifyKeyFile unwraps the identity offline and confirms it parses as an age
	// key AND that its derived recipient matches the expected one.
	if err := got.Verify(kp.Recipient); err != nil {
		t.Fatalf("Verify should pass for the matching recipient: %v", err)
	}
	if err := got.Verify("age1someotherrecipient"); err == nil {
		t.Fatal("Verify must fail on a recipient mismatch")
	}
}

func TestParseKeyFile_RejectsGarbage(t *testing.T) {
	if _, err := ParseKeyFile([]byte("not json")); err == nil {
		t.Fatal("garbage must fail")
	}
	// wrong version → rejected (fail closed)
	bad := `{"version":"v99","project_id":1,"wrapped_key_b64":"x","kek_b64":"y"}`
	if _, err := ParseKeyFile([]byte(bad)); err == nil {
		t.Fatal("unknown version must fail")
	}
	// missing project_id → rejected
	nopid := `{"version":"` + KeyFileVersion + `","wrapped_key_b64":"x","kek_b64":"y"}`
	if _, err := ParseKeyFile([]byte(nopid)); err == nil {
		t.Fatal("missing project_id must fail")
	}
}

// LoadKeyDir reads every <pid>.key.json in a dir and is TOLERANT: a bad file is
// skipped-and-reported, never fatal (the Stage-2 SPOF kill). Fatal only if the
// dir is unreadable. Returns (good KeyStore, skipped pids/reasons).
func TestLoadKeyDir_SkipsBadFileLoadsRest(t *testing.T) {
	dir := t.TempDir()
	// two good keys
	for _, pid := range []int64{338, 412} {
		kp, _ := crypto.GenerateRepoKey()
		kek, _ := crypto.GenerateKEK()
		wrapped, _ := crypto.WrapKey([]byte(kp.Identity), kek)
		writeKeyFileT(t, dir, pid, NewKeyFile(pid, wrapped, kek))
	}
	// one corrupt file
	if err := os.WriteFile(filepath.Join(dir, "999.key.json"), []byte("{bad"), 0600); err != nil {
		t.Fatal(err)
	}

	ks, skipped, err := LoadKeyDir(dir)
	if err != nil {
		t.Fatalf("LoadKeyDir should not be fatal on a bad file: %v", err)
	}
	if len(ks.Identities) != 2 || ks.Identities[338] == "" || ks.Identities[412] == "" {
		t.Fatalf("both good keys must load: %+v", ks.Identities)
	}
	if len(skipped) != 1 || !strings.Contains(skipped[0], "999") {
		t.Fatalf("the corrupt file must be reported skipped: %v", skipped)
	}
}

func TestLoadKeyDir_FatalOnMissingDir(t *testing.T) {
	if _, _, err := LoadKeyDir(filepath.Join(t.TempDir(), "does-not-exist")); err == nil {
		t.Fatal("a missing keystore dir must be fatal (fail closed)")
	}
}

// Zero valid keys in an existing dir is fatal — an empty keystore means the
// broker can serve nothing, and (silent-health lesson) that must be loud.
func TestLoadKeyDir_FatalOnZeroValid(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "1.key.json"), []byte("{bad"), 0600)
	if _, _, err := LoadKeyDir(dir); err == nil {
		t.Fatal("zero valid keys must be fatal")
	}
}

func writeKeyFileT(t *testing.T, dir string, pid int64, kf *KeyFile) {
	t.Helper()
	data, _ := json.Marshal(kf)
	if err := os.WriteFile(filepath.Join(dir, KeyFileName(pid)), data, 0600); err != nil {
		t.Fatal(err)
	}
}
