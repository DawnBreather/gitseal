package broker

import (
	"os"
	"path/filepath"
	"testing"
)

// LoadRegistry must load ALL THREE files the out-of-band Secret carries:
//
//	projects.json  (fatal if missing)
//	users.json     (fp → user_id; optional)
//	userkeys.json  (fp → authorized-key line; optional)
//
// The userkeys map is what authViaSSH verifies the challenge signature against —
// omitting it makes SSH auth fail-closed forever ("no registered public key")
// even after correct out-of-band seeding. This test pins that the loader wires
// UserKeys, not just Users (a bug the unit/E2E tests missed because they set
// Registry.UserKeys directly, bypassing the loader).
func TestLoadRegistry_LoadsUserKeys(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("projects.json", `{"age1p":{"project_id":338,"env_cluster":{"prod":"example"},"env_min_level":{"prod":40},"cluster_recipients":{"example":"age1G"}}}`)
	write("users.json", `{"SHA256:fp1":87}`)
	write("userkeys.json", `{"SHA256:fp1":"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAExample won@host"}`)

	reg, err := LoadRegistry(dir)
	if err != nil {
		t.Fatalf("LoadRegistry: %v", err)
	}
	if uid, ok := reg.User("SHA256:fp1"); !ok || uid != 87 {
		t.Fatalf("user not loaded: %v %v", uid, ok)
	}
	kl, ok := reg.UserKey("SHA256:fp1")
	if !ok {
		t.Fatal("userkeys.json not loaded — authViaSSH would fail-closed on every SSH unseal")
	}
	if kl != "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAExample won@host" {
		t.Fatalf("wrong key line loaded: %q", kl)
	}
}

// A missing userkeys.json is tolerated (projects-first / users-first seeding),
// mirroring the users.json contract — the map is just empty, not an error.
func TestLoadRegistry_MissingUserKeysTolerated(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "projects.json"),
		[]byte(`{"age1p":{"project_id":338}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	reg, err := LoadRegistry(dir)
	if err != nil {
		t.Fatalf("LoadRegistry with no users/userkeys must succeed: %v", err)
	}
	if _, ok := reg.UserKey("SHA256:none"); ok {
		t.Fatal("no userkeys.json → UserKey must resolve to not-found, not panic")
	}
}
